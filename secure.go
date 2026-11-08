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

type ClientOptions struct {
	ServerName string
	Pins       []string
	ECHConfig  string
}

type ECHKey struct {
	Config string `json:"config"`
	Key    string `json:"key"`
	Retry  bool   `json:"retry"`
}

type ServerOptions struct {
	CertFile string
	KeyFile  string
	ECHKeys  []ECHKey
}

func PinOf(cert *x509.Certificate) string {
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

func TLSClientConfig(o ClientOptions) (*tls.Config, error) {
	cfg := &tls.Config{
		ServerName:                  o.ServerName,
		MinVersion:                  tls.VersionTLS12,
		NextProtos:                  []string{"h2", "http/1.1"},
		DynamicRecordSizingDisabled: true,
		ClientSessionCache:          tls.NewLRUClientSessionCache(64),
	}
	if o.ECHConfig != "" {
		list, err := base64.StdEncoding.DecodeString(o.ECHConfig)
		if err != nil {
			return nil, fmt.Errorf("ech_config: %w", err)
		}
		if o.ServerName == "" {
			return nil, errors.New("ech needs sni: the real server name that travels inside the encrypted hello")
		}
		cfg.EncryptedClientHelloConfigList = list
		cfg.MinVersion = tls.VersionTLS13
	}

	if len(o.Pins) == 0 {
		if o.ServerName == "" {
			return nil, errors.New("tls needs sni or tls_pins")
		}
		return cfg, nil
	}
	pins := make(map[string]struct{}, len(o.Pins))
	for _, p := range o.Pins {
		n, err := normalizePin(p)
		if err != nil {
			return nil, err
		}
		pins[n] = struct{}{}
	}
	cfg.InsecureSkipVerify = true
	cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("server sent no certificate")
		}
		leaf, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return err
		}
		if _, ok := pins[PinOf(leaf)]; !ok {
			return errors.New("server certificate does not match any tls_pins entry")
		}
		return nil
	}
	return cfg, nil
}

func TLSServerConfig(o ServerOptions) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load tls_cert/tls_key: %w", err)
	}
	cfg := &tls.Config{
		Certificates:                []tls.Certificate{cert},
		MinVersion:                  tls.VersionTLS13,
		NextProtos:                  []string{"http/1.1"},
		DynamicRecordSizingDisabled: true,
	}
	for i, k := range o.ECHKeys {
		conf, err := base64.StdEncoding.DecodeString(k.Config)
		if err != nil {
			return nil, fmt.Errorf("ech_keys[%d].config: %w", i, err)
		}
		priv, err := base64.StdEncoding.DecodeString(k.Key)
		if err != nil {
			return nil, fmt.Errorf("ech_keys[%d].key: %w", i, err)
		}
		cfg.EncryptedClientHelloKeys = append(cfg.EncryptedClientHelloKeys, tls.EncryptedClientHelloKey{
			Config:      conf,
			PrivateKey:  priv,
			SendAsRetry: k.Retry,
		})
	}
	return cfg, nil
}

const (
	echVersion = 0xfe0d
	kemX25519  = 0x0020
	kdfSHA256  = 0x0001
	aeadAES128 = 0x0001
	aeadChaCha = 0x0003
)

type ECHKit struct {
	ConfigList string
	Config     string
	PrivateKey string
}

func NewECH(publicName string, id byte) (*ECHKit, error) {
	if publicName == "" || len(publicName) > 255 {
		return nil, errors.New("public name must be 1-255 bytes")
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := priv.PublicKey().Bytes()

	var body []byte
	body = append(body, id)
	body = binary.BigEndian.AppendUint16(body, kemX25519)
	body = binary.BigEndian.AppendUint16(body, uint16(len(pub)))
	body = append(body, pub...)
	body = binary.BigEndian.AppendUint16(body, 8)
	for _, aead := range []uint16{aeadAES128, aeadChaCha} {
		body = binary.BigEndian.AppendUint16(body, kdfSHA256)
		body = binary.BigEndian.AppendUint16(body, aead)
	}
	body = append(body, 64, byte(len(publicName)))
	body = append(body, publicName...)
	body = binary.BigEndian.AppendUint16(body, 0)

	conf := binary.BigEndian.AppendUint16(nil, echVersion)
	conf = binary.BigEndian.AppendUint16(conf, uint16(len(body)))
	conf = append(conf, body...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(conf)))
	list = append(list, conf...)

	enc := base64.StdEncoding.EncodeToString
	return &ECHKit{ConfigList: enc(list), Config: enc(conf), PrivateKey: enc(priv.Bytes())}, nil
}

func NewCert(names ...string) (certPEM, keyPEM []byte, pin string, err error) {
	if len(names) == 0 {
		return nil, nil, "", errors.New("at least one name is required")
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
	return certPEM, keyPEM, PinOf(leaf), nil
}
