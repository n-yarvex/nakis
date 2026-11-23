package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

type ECHKey struct {
	Config string `json:"config"`
	Key    string `json:"key"`
	Retry  bool   `json:"retry"`
}

func pinOf(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

func normalizePin(p string) (string, error) {
	p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), ":", ""))
	if raw, err := hex.DecodeString(p); err != nil || len(raw) != sha256.Size {
		return "", fmt.Errorf("pin %q is not a sha256 hex digest", p)
	}
	return p, nil
}

func clientTLS(sni string, pins []string, ech string, alpn []string) (*tls.Config, error) {
	cfg := &tls.Config{
		ServerName: sni,
		MinVersion: tls.VersionTLS13,
		NextProtos: alpn,
	}
	if ech != "" {
		list, err := base64.StdEncoding.DecodeString(ech)
		if err != nil {
			return nil, fmt.Errorf("ech_config is not base64: %w", err)
		}
		cfg.EncryptedClientHelloConfigList = list
	}
	if len(pins) == 0 {
		return cfg, nil
	}
	set := make(map[string]struct{}, len(pins))
	for _, p := range pins {
		n, err := normalizePin(p)
		if err != nil {
			return nil, err
		}
		set[n] = struct{}{}
	}
	cfg.InsecureSkipVerify = true
	cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("the server sent no certificate")
		}
		leaf, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return err
		}
		if _, ok := set[pinOf(leaf)]; !ok {
			return errors.New("the server certificate is not one of tls_pins")
		}
		return nil
	}
	return cfg, nil
}

func serverTLS(certFile, keyFile string, keys []ECHKey, alpn []string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("can't load tls_cert / tls_key: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   alpn,
	}
	for i, k := range keys {
		conf, err := base64.StdEncoding.DecodeString(k.Config)
		if err != nil {
			return nil, fmt.Errorf("ech_keys[%d].config is not base64: %w", i, err)
		}
		priv, err := base64.StdEncoding.DecodeString(k.Key)
		if err != nil {
			return nil, fmt.Errorf("ech_keys[%d].key is not base64: %w", i, err)
		}
		cfg.EncryptedClientHelloKeys = append(cfg.EncryptedClientHelloKeys, tls.EncryptedClientHelloKey{
			Config:      conf,
			PrivateKey:  priv,
			SendAsRetry: k.Retry,
		})
	}
	return cfg, nil
}

type echKit struct {
	list   string
	config string
	key    string
}

func newECH(publicName string, id byte) (*echKit, error) {
	if publicName == "" || len(publicName) > 255 {
		return nil, errors.New("the public name must be 1-255 bytes")
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := priv.PublicKey().Bytes()
	var body []byte
	body = append(body, id)
	body = binary.BigEndian.AppendUint16(body, 0x0020)
	body = binary.BigEndian.AppendUint16(body, uint16(len(pub)))
	body = append(body, pub...)
	body = binary.BigEndian.AppendUint16(body, 8)
	for _, aead := range []uint16{0x0001, 0x0003} {
		body = binary.BigEndian.AppendUint16(body, 0x0001)
		body = binary.BigEndian.AppendUint16(body, aead)
	}
	body = append(body, 64, byte(len(publicName)))
	body = append(body, publicName...)
	body = binary.BigEndian.AppendUint16(body, 0)

	conf := binary.BigEndian.AppendUint16(nil, 0xfe0d)
	conf = binary.BigEndian.AppendUint16(conf, uint16(len(body)))
	conf = append(conf, body...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(conf)))
	list = append(list, conf...)
	enc := base64.StdEncoding.EncodeToString
	return &echKit{list: enc(list), config: enc(conf), key: enc(priv.Bytes())}, nil
}

func newCert(names ...string) (certPEM, keyPEM []byte, pin string, err error) {
	if len(names) == 0 {
		return nil, nil, "", errors.New("at least one name is needed")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, nil, "", err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, "", err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, "", err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, pinOf(leaf), nil
}
