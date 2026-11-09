package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
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
	linkScheme  = "nakis://"
	linkVersion = 1
)

type Node struct {
	Name   string
	Config ClientConfig
}

var linkKeys = []string{"v", "tls", "sni", "pin", "ech", "alt", "shape", "race", "pool", "uses", "age", "ka", "cc", "pack", "tail", "quiet", "wait"}

func escapeValue(s string) string {
	s = url.QueryEscape(s)
	for _, p := range [][2]string{{"%2C", ","}, {"%3A", ":"}, {"%5B", "["}, {"%5D", "]"}} {
		s = strings.ReplaceAll(s, p[0], p[1])
	}
	return s
}

func rangesText(r [][2]int) string {
	parts := make([]string, len(r))
	for i, v := range r {
		parts[i] = fmt.Sprintf("%d-%d", v[0], v[1])
	}
	return strings.Join(parts, ",")
}

func parseRanges(s string) ([][2]int, error) {
	var out [][2]int
	for _, item := range strings.Split(s, ",") {
		lo, hi, ok := strings.Cut(strings.TrimSpace(item), "-")
		if !ok {
			return nil, fmt.Errorf("range %q: want lo-hi", item)
		}
		a, err1 := strconv.Atoi(lo)
		b, err2 := strconv.Atoi(hi)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("range %q: want lo-hi numbers", item)
		}
		out = append(out, [2]int{a, b})
	}
	return out, nil
}

func decodeB64(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	s = strings.ReplaceAll(s, " ", "+")
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	return base64.RawStdEncoding.DecodeString(s)
}

func FormatLink(c ClientConfig, name string) (string, error) {
	servers := strings.Split(c.Server, ",")
	for i := range servers {
		servers[i] = strings.TrimSpace(servers[i])
		if _, _, err := net.SplitHostPort(servers[i]); err != nil {
			return "", fmt.Errorf("server %q: %w", servers[i], err)
		}
	}
	id, err := ParseUUID(c.UUID)
	if err != nil {
		return "", fmt.Errorf("uuid: %w", err)
	}
	def := DefaultClient()
	q := map[string]string{}
	if !c.TLS {
		q["tls"] = "0"
	} else {
		if c.SNI != "" {
			q["sni"] = c.SNI
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
	}
	if len(servers) > 1 {
		q["alt"] = strings.Join(servers[1:], ",")
	}
	if len(c.ShapeUp) > 0 {
		q["shape"] = rangesText(c.ShapeUp)
	}
	num := func(key string, v, d int) {
		if v != d {
			q[key] = strconv.Itoa(v)
		}
	}
	num("race", c.RaceCount, def.RaceCount)
	num("uses", c.PoolMaxUses, def.PoolMaxUses)
	num("pack", c.SendPack, def.SendPack)
	num("tail", c.SendTail, def.SendTail)
	num("quiet", c.SendQuiet, def.SendQuiet)
	if c.PoolLo != def.PoolLo || c.PoolHi != def.PoolHi {
		q["pool"] = fmt.Sprintf("%d-%d", c.PoolLo, c.PoolHi)
	}
	dur := func(key string, v, d Span) {
		if v != 0 && v != d {
			q[key] = v.D().String()
		}
	}
	dur("age", c.PoolMaxAge, def.PoolMaxAge)
	dur("ka", c.Keepalive, def.Keepalive)
	dur("wait", c.ShapeWait, def.ShapeWait)
	if c.Congestion != "" {
		q["cc"] = c.Congestion
	}

	var b strings.Builder
	b.WriteString(linkScheme)
	b.WriteString(fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:16]))
	b.WriteByte('@')
	b.WriteString(servers[0])
	b.WriteString("?v=")
	b.WriteString(strconv.Itoa(linkVersion))
	for _, k := range linkKeys[1:] {
		if v, ok := q[k]; ok {
			b.WriteByte('&')
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(escapeValue(v))
		}
	}
	if name != "" {
		b.WriteByte('#')
		b.WriteString(url.PathEscape(name))
	}
	return b.String(), nil
}

func ParseLink(link string) (Node, error) {
	var n Node
	link = strings.TrimSpace(link)
	if !strings.HasPrefix(strings.ToLower(link), linkScheme) {
		return n, errors.New("not a nakis:// link")
	}
	u, err := url.Parse(link)
	if err != nil {
		return n, fmt.Errorf("bad link: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return n, errors.New("link has no uuid before the @")
	}
	if _, err := ParseUUID(u.User.Username()); err != nil {
		return n, fmt.Errorf("uuid: %w", err)
	}
	if u.Hostname() == "" || u.Port() == "" {
		return n, errors.New("link needs host:port")
	}
	if p, err := strconv.Atoi(u.Port()); err != nil || p < 1 || p > 65535 {
		return n, fmt.Errorf("bad port %q", u.Port())
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return n, fmt.Errorf("bad query: %w", err)
	}
	if v := q.Get("v"); v != "" {
		ver, err := strconv.Atoi(v)
		if err != nil || ver < 1 {
			return n, fmt.Errorf("bad version %q", v)
		}
		if ver > linkVersion {
			return n, fmt.Errorf("link version %d is newer than this client understands (%d)", ver, linkVersion)
		}
	}

	c := DefaultClient()
	c.UUID = u.User.Username()
	c.Server = net.JoinHostPort(u.Hostname(), u.Port())
	if alt := q.Get("alt"); alt != "" {
		for _, a := range strings.Split(alt, ",") {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			if _, _, err := net.SplitHostPort(a); err != nil {
				return n, fmt.Errorf("alt %q: %w", a, err)
			}
			c.Server += "," + a
		}
	}
	if q.Get("tls") == "0" {
		c.TLS = false
	}
	c.SNI = q.Get("sni")
	if p := q.Get("pin"); p != "" {
		for _, item := range strings.Split(p, ",") {
			norm, err := normalizePin(item)
			if err != nil {
				return n, err
			}
			c.TLSPins = append(c.TLSPins, norm)
		}
	}
	if e := q.Get("ech"); e != "" {
		raw, err := decodeB64(e)
		if err != nil || len(raw) < 4 {
			return n, errors.New("ech is not valid base64")
		}
		c.ECHConfig = base64.StdEncoding.EncodeToString(raw)
	}
	if s := q.Get("shape"); s != "" {
		if c.ShapeUp, err = parseRanges(s); err != nil {
			return n, err
		}
	}
	intOf := func(key string, dst *int) error {
		if v := q.Get(key); v != "" {
			x, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("%s=%q is not a number", key, v)
			}
			*dst = x
		}
		return nil
	}
	durOf := func(key string, dst *Span) error {
		if v := q.Get(key); v != "" {
			d, err := time.ParseDuration(v)
			if err != nil {
				return fmt.Errorf("%s=%q is not a duration", key, v)
			}
			*dst = Span(d)
		}
		return nil
	}
	for _, step := range []error{
		intOf("race", &c.RaceCount), intOf("uses", &c.PoolMaxUses), intOf("pack", &c.SendPack),
		intOf("tail", &c.SendTail), intOf("quiet", &c.SendQuiet),
		durOf("age", &c.PoolMaxAge), durOf("ka", &c.Keepalive), durOf("wait", &c.ShapeWait),
	} {
		if step != nil {
			return n, step
		}
	}
	if p := q.Get("pool"); p != "" {
		r, err := parseRanges(p)
		if err != nil || len(r) != 1 {
			return n, errors.New("pool wants a single lo-hi range")
		}
		c.PoolLo, c.PoolHi = r[0][0], r[0][1]
	}
	c.Congestion = q.Get("cc")
	if err := c.Tidy(); err != nil {
		return n, err
	}
	n.Config = c
	n.Name = u.Fragment
	return n, nil
}

func ParseSubscription(body []byte) ([]Node, []error) {
	text := strings.TrimSpace(strings.TrimPrefix(string(body), "\xef\xbb\xbf"))
	if !strings.Contains(strings.ToLower(text), linkScheme) {
		compact := strings.Join(strings.Fields(text), "")
		if raw, err := decodeB64(compact); err == nil {
			text = string(raw)
		}
	}
	var nodes []Node
	var errs []error
	for i, line := range strings.Split(strings.ReplaceAll(text, "\r", ""), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(line), linkScheme) {
			continue
		}
		node, err := ParseLink(line)
		if err != nil {
			errs = append(errs, fmt.Errorf("line %d: %w", i+1, err))
			continue
		}
		nodes = append(nodes, node)
	}
	return nodes, errs
}

func EncodeSubscription(links []string) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n") + "\n"))
}

func LinkFromServer(s ServerConfig, host, sni string, port int) (ClientConfig, error) {
	c := DefaultClient()
	c.UUID = s.UUID
	if port == 0 {
		_, p, err := net.SplitHostPort(s.Listen)
		if err != nil {
			return c, err
		}
		if port, err = strconv.Atoi(p); err != nil {
			return c, err
		}
	}
	c.Server = net.JoinHostPort(host, strconv.Itoa(port))
	c.TLS = s.TLS
	if !s.TLS {
		return c, c.Tidy()
	}
	c.SNI = sni
	if s.TLSCert != "" {
		data, err := os.ReadFile(s.TLSCert)
		if err != nil {
			return c, err
		}
		block, _ := pem.Decode(data)
		if block == nil {
			return c, errors.New("tls_cert has no PEM block")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return c, err
		}
		c.TLSPins = []string{PinOf(cert)}
	}
	if len(s.ECHKeys) > 0 {
		conf, err := base64.StdEncoding.DecodeString(s.ECHKeys[0].Config)
		if err != nil {
			return c, fmt.Errorf("ech_keys[0].config: %w", err)
		}
		list := binary.BigEndian.AppendUint16(nil, uint16(len(conf)))
		c.ECHConfig = base64.StdEncoding.EncodeToString(append(list, conf...))
	}
	return c, c.Tidy()
}
