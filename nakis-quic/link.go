package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	linkScheme  = "nakisq://"
	linkVersion = 1
)

var linkKeys = []string{"sni", "pin", "ech", "alt", "alpn", "race", "pool", "uses", "age", "streams", "ka", "idle"}

func formatUUID(id []byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16])
}

func FormatLink(c ClientConfig, name string) (string, error) {
	list, err := normServers(c.Server)
	if err != nil {
		return "", err
	}
	servers := strings.Split(list, ",")
	id, err := ParseUUID(c.UUID)
	if err != nil {
		return "", fmt.Errorf("uuid: %w", err)
	}
	def := DefaultClient()
	q := map[string]string{}
	if c.SNI != "" {
		sni, err := normHost(c.SNI)
		if err != nil {
			return "", err
		}
		q["sni"] = sni
	}
	if len(c.TLSPins) > 0 {
		pins := make([]string, len(c.TLSPins))
		for i, p := range c.TLSPins {
			if pins[i], err = normalizePin(p); err != nil {
				return "", err
			}
		}
		q["pin"] = strings.Join(pins, ",")
	}
	if c.ECHConfig != "" {
		raw, err := base64.StdEncoding.DecodeString(c.ECHConfig)
		if err != nil {
			return "", fmt.Errorf("ech_config: %w", err)
		}
		q["ech"] = base64.RawURLEncoding.EncodeToString(raw)
	}
	if len(servers) > 1 {
		q["alt"] = strings.Join(servers[1:], ",")
	}
	if len(c.ALPN) > 0 && strings.Join(c.ALPN, ",") != strings.Join(def.ALPN, ",") {
		q["alpn"] = strings.Join(c.ALPN, ",")
	}
	num := func(key string, v, d int) {
		if v != 0 && v != d {
			q[key] = strconv.Itoa(v)
		}
	}
	num("race", c.RaceCount, def.RaceCount)
	num("uses", c.PoolMaxUses, def.PoolMaxUses)
	num("streams", c.Streams, def.Streams)
	if c.PoolLo != 0 && (c.PoolLo != def.PoolLo || c.PoolHi != def.PoolHi) {
		q["pool"] = fmt.Sprintf("%d-%d", c.PoolLo, c.PoolHi)
	}
	dur := func(key string, v, d Span) {
		if v != 0 && v != d {
			q[key] = v.D().String()
		}
	}
	dur("age", c.PoolMaxAge, def.PoolMaxAge)
	dur("ka", c.Keepalive, def.Keepalive)
	dur("idle", c.IdleTimeout, def.IdleTimeout)

	var b strings.Builder
	b.WriteString(linkScheme)
	b.WriteString(formatUUID(id))
	b.WriteByte('@')
	b.WriteString(servers[0])
	b.WriteString("?v=" + strconv.Itoa(linkVersion))
	for _, k := range linkKeys {
		if v, ok := q[k]; ok {
			b.WriteString("&" + k + "=" + url.QueryEscape(v))
		}
	}
	if name != "" {
		b.WriteString("#" + url.PathEscape(name))
	}
	return b.String(), nil
}

type Node struct {
	Name   string
	Config ClientConfig
}

func ParseLink(link string) (Node, error) {
	var n Node
	link = strings.TrimSpace(link)
	if !strings.HasPrefix(link, linkScheme) {
		return n, problem("L01", "a link starts with "+linkScheme, "")
	}
	u, err := url.Parse(link)
	if err != nil {
		return n, problem("L01", "that link doesn't parse: "+err.Error(), "")
	}
	if u.User == nil || u.Host == "" {
		return n, problem("L01", "a link looks like nakisq://UUID@host:port?...", "")
	}
	cfg := DefaultClient()
	cfg.UUID = u.User.Username()
	q := u.Query()
	if v := q.Get("v"); v != strconv.Itoa(linkVersion) {
		return n, problem("L02", "this link has version \""+v+"\", this build reads version 1", "update nakis-quic")
	}
	servers := []string{u.Host}
	if alt := q.Get("alt"); alt != "" {
		servers = append(servers, strings.Split(alt, ",")...)
	}
	cfg.Server = strings.Join(servers, ",")
	cfg.SNI = q.Get("sni")
	if p := q.Get("pin"); p != "" {
		cfg.TLSPins = strings.Split(p, ",")
	}
	if e := q.Get("ech"); e != "" {
		raw, err := base64.RawURLEncoding.DecodeString(e)
		if err != nil {
			return n, problem("L01", "ech in the link is not base64", "")
		}
		cfg.ECHConfig = base64.StdEncoding.EncodeToString(raw)
	}
	if a := q.Get("alpn"); a != "" {
		cfg.ALPN = strings.Split(a, ",")
	}
	for key, dst := range map[string]*int{"race": &cfg.RaceCount, "uses": &cfg.PoolMaxUses, "streams": &cfg.Streams} {
		if s := q.Get(key); s != "" {
			v, err := strconv.Atoi(s)
			if err != nil {
				return n, problem("L01", key+" in the link is not a number", "")
			}
			*dst = v
		}
	}
	if s := q.Get("pool"); s != "" {
		lo, hi, ok := strings.Cut(s, "-")
		a, e1 := strconv.Atoi(lo)
		b, e2 := strconv.Atoi(hi)
		if !ok || e1 != nil || e2 != nil {
			return n, problem("L01", "pool in the link wants lo-hi", "")
		}
		cfg.PoolLo, cfg.PoolHi = a, b
	}
	for key, dst := range map[string]*Span{"age": &cfg.PoolMaxAge, "ka": &cfg.Keepalive, "idle": &cfg.IdleTimeout} {
		if s := q.Get(key); s != "" {
			d, err := time.ParseDuration(s)
			if err != nil {
				return n, problem("L01", key+" in the link is not a duration", "")
			}
			*dst = Span(d)
		}
	}
	if err := cfg.Tidy(); err != nil {
		return n, err
	}
	n.Config = cfg
	if u.Fragment != "" {
		n.Name, _ = url.PathUnescape(u.Fragment)
	}
	return n, nil
}

func LinkFromServer(s ServerConfig, host string, sni string, port int, withPin bool) (string, error) {
	id, err := ParseUUID(s.UUID)
	if err != nil {
		return "", err
	}
	if port == 0 {
		_, p, err := net.SplitHostPort(s.Listen)
		if err != nil {
			return "", err
		}
		if port, err = strconv.Atoi(p); err != nil {
			return "", err
		}
	}
	c := DefaultClient()
	c.UUID = formatUUID(id)
	c.Server = net.JoinHostPort(host, strconv.Itoa(port))
	c.ALPN = s.ALPN
	c.SNI = sni
	if withPin {
		raw, err := os.ReadFile(s.TLSCert)
		if err != nil {
			return "", err
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			return "", errors.New("tls_cert is not PEM")
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return "", err
		}
		c.TLSPins = []string{pinOf(leaf)}
	}
	return FormatLink(c, "")
}
