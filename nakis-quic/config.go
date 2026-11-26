package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type Span time.Duration

func (s Span) D() time.Duration { return time.Duration(s) }

func (s *Span) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return errors.New("a duration is written as a string such as \"5s\"")
	}
	v, err := time.ParseDuration(raw)
	if err != nil {
		return err
	}
	*s = Span(v)
	return nil
}

func (s Span) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(s).String())
}

type Problem struct {
	Code string
	Msg  string
	Hint string
}

func (p *Problem) Error() string {
	s := "[" + p.Code + "] " + p.Msg
	if p.Hint != "" {
		s += " (" + p.Hint + ")"
	}
	return s
}

func problem(code, msg, hint string) *Problem {
	return &Problem{Code: "NQ-" + code, Msg: msg, Hint: hint}
}

type ClientConfig struct {
	Listen                  string   `json:"listen"`
	Server                  string   `json:"server"`
	UUID                    string   `json:"uuid"`
	SNI                     string   `json:"sni"`
	TLSPins                 []string `json:"tls_pins"`
	ECHConfig               string   `json:"ech_config"`
	ALPN                    []string `json:"alpn"`
	RaceCount               int      `json:"race_count"`
	RaceStagger             Span     `json:"race_stagger"`
	PoolLo                  int      `json:"pool_lo"`
	PoolHi                  int      `json:"pool_hi"`
	PoolMaxAge              Span     `json:"pool_max_age"`
	PoolMaxUses             int      `json:"pool_max_uses"`
	Streams                 int      `json:"streams"`
	DialTimeout             Span     `json:"dial_timeout"`
	HandshakeTimeout        Span     `json:"handshake_timeout"`
	IdleTimeout             Span     `json:"idle_timeout"`
	Keepalive               Span     `json:"keepalive"`
	ProbeInterval           Span     `json:"probe_interval"`
	HalfCloseTimeout        Span     `json:"half_close_timeout"`
	UDP                     bool     `json:"udp"`
	UDPIdleTimeout          Span     `json:"udp_idle_timeout"`
	DNS                     []string `json:"dns"`
	LogLevel                string   `json:"log_level"`
	InitialStreamWindow     uint64   `json:"initial_stream_window"`
	MaxStreamWindow         uint64   `json:"max_stream_window"`
	InitialConnectionWindow uint64   `json:"initial_connection_window"`
	MaxConnectionWindow     uint64   `json:"max_connection_window"`

	noWarm bool
}

type ServerConfig struct {
	Listen                  string   `json:"listen"`
	UUID                    string   `json:"uuid"`
	TLSCert                 string   `json:"tls_cert"`
	TLSKey                  string   `json:"tls_key"`
	ECHKeys                 []ECHKey `json:"ech_keys"`
	ALPN                    []string `json:"alpn"`
	DNS                     []string `json:"dns"`
	DialTimeout             Span     `json:"dial_timeout"`
	HandshakeTimeout        Span     `json:"handshake_timeout"`
	IdleTimeout             Span     `json:"idle_timeout"`
	Keepalive               Span     `json:"keepalive"`
	ShutdownTimeout         Span     `json:"shutdown_timeout"`
	HalfCloseTimeout        Span     `json:"half_close_timeout"`
	UDP                     bool     `json:"udp"`
	UDPIdleTimeout          Span     `json:"udp_idle_timeout"`
	MaxConns                int      `json:"max_conns"`
	MaxStreams              int      `json:"max_streams"`
	AllowPrivate            bool     `json:"allow_private"`
	LogLevel                string   `json:"log_level"`
	InitialStreamWindow     uint64   `json:"initial_stream_window"`
	MaxStreamWindow         uint64   `json:"max_stream_window"`
	InitialConnectionWindow uint64   `json:"initial_connection_window"`
	MaxConnectionWindow     uint64   `json:"max_connection_window"`
}

func DefaultClient() ClientConfig {
	return ClientConfig{
		Listen:                  "127.0.0.1:1080",
		ALPN:                    []string{"h3"},
		RaceCount:               6,
		PoolLo:                  4,
		PoolHi:                  32,
		PoolMaxAge:              Span(30 * time.Minute),
		PoolMaxUses:             32768,
		Streams:                 256,
		DialTimeout:             Span(18 * time.Second),
		HandshakeTimeout:        Span(18 * time.Second),
		IdleTimeout:             Span(90 * time.Second),
		Keepalive:               Span(20 * time.Second),
		ProbeInterval:           Span(5 * time.Second),
		HalfCloseTimeout:        Span(300 * time.Second),
		UDP:                     true,
		UDPIdleTimeout:          Span(300 * time.Second),
		LogLevel:                "info",
		InitialStreamWindow:     16 << 20,
		MaxStreamWindow:         256 << 20,
		InitialConnectionWindow: 32 << 20,
		MaxConnectionWindow:     1024 << 20,
	}
}

func DefaultServer() ServerConfig {
	return ServerConfig{
		Listen:                  "0.0.0.0:443",
		ALPN:                    []string{"h3"},
		DialTimeout:             Span(12 * time.Second),
		HandshakeTimeout:        Span(18 * time.Second),
		IdleTimeout:             Span(90 * time.Second),
		Keepalive:               Span(20 * time.Second),
		ShutdownTimeout:         Span(40 * time.Second),
		HalfCloseTimeout:        Span(300 * time.Second),
		UDP:                     true,
		UDPIdleTimeout:          Span(480 * time.Second),
		MaxConns:                8192,
		MaxStreams:              1024,
		LogLevel:                "info",
		InitialStreamWindow:     16 << 20,
		MaxStreamWindow:         256 << 20,
		InitialConnectionWindow: 32 << 20,
		MaxConnectionWindow:     1024 << 20,
	}
}

func jsonKeys(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		if tag := strings.Split(t.Field(i).Tag.Get("json"), ",")[0]; tag != "" && tag != "-" {
			out = append(out, tag)
		}
	}
	return out
}

func distance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

func decode(path string, dst any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return problem("F01", "no config file at "+path, "make one with: nakis-quic init")
		}
		return problem("F02", "can't read "+path+": "+err.Error(), "")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		const mark = "json: unknown field "
		if msg := err.Error(); strings.HasPrefix(msg, mark) {
			name, _ := strconv.Unquote(strings.TrimPrefix(msg, mark))
			hint := "see the docs for the list of keys"
			best, bd := "", 4
			for _, k := range jsonKeys(reflect.TypeOf(dst).Elem()) {
				if d := distance(name, k); d < bd {
					best, bd = k, d
				}
			}
			if best != "" {
				hint = "did you mean \"" + best + "\"?"
			}
			return problem("F03", "unknown key \""+name+"\" in "+path, hint)
		}
		return problem("F04", path+" is not valid: "+err.Error(), "json needs double quotes and no trailing commas")
	}
	return nil
}

func LoadClient(path string) (ClientConfig, error) {
	c := DefaultClient()
	if err := decode(path, &c); err != nil {
		return c, err
	}
	return c, c.Tidy()
}

func LoadServer(path string) (ServerConfig, error) {
	s := DefaultServer()
	if err := decode(path, &s); err != nil {
		return s, err
	}
	return s, s.Tidy()
}

func clamp(v, lo, hi int) int { return min(max(v, lo), hi) }

func positive(v *Span, fallback time.Duration) {
	if *v <= 0 {
		*v = Span(fallback)
	}
}

func fixListen(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	i := strings.LastIndex(addr, ":")
	if i <= 0 {
		return addr
	}
	host, port := addr[:i], addr[i+1:]
	if port == "" || net.ParseIP(host) == nil {
		return addr
	}
	return net.JoinHostPort(host, port)
}

func normHost(h string) (string, error) {
	h = strings.TrimSpace(h)
	if h == "" {
		return "", errors.New("host is empty")
	}
	if strings.ContainsRune(h, '%') {
		return "", fmt.Errorf("host %q must not carry a zone", h)
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.String(), nil
	}
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 || h[0] == '.' || strings.Contains(h, "..") {
		return "", fmt.Errorf("host %q is not a valid name", h)
	}
	for _, r := range h {
		if r <= 0x20 || r == 0x7f || strings.ContainsRune(`/\?#@,[]:"'<>`, r) {
			return "", fmt.Errorf("host %q is not a valid name", h)
		}
	}
	return strings.ToLower(h), nil
}

func normServer(s string) (string, error) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(s))
	if err != nil {
		return "", fmt.Errorf("%q wants the form host:port", s)
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n < 1 {
		return "", fmt.Errorf("%q: the port must be 1-65535", s)
	}
	if host, err = normHost(host); err != nil {
		return "", fmt.Errorf("%q: %w", s, err)
	}
	return net.JoinHostPort(host, strconv.Itoa(int(n))), nil
}

func normServers(list string) (string, error) {
	var out []string
	seen := map[string]bool{}
	for _, item := range strings.Split(list, ",") {
		if strings.TrimSpace(item) == "" {
			continue
		}
		s, err := normServer(item)
		if err != nil {
			return "", err
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return "", errors.New("empty")
	}
	return strings.Join(out, ","), nil
}

func checkALPN(list []string) ([]string, error) {
	if len(list) == 0 {
		return []string{"h3"}, nil
	}
	for _, p := range list {
		if p == "" || len(p) > 255 {
			return nil, errors.New("alpn entries must be 1-255 bytes")
		}
	}
	return list, nil
}

func (c *ClientConfig) Tidy() error {
	if strings.TrimSpace(c.Server) == "" {
		return problem("C01", "server is missing", "write it as host:port, for example \"example.com:443\"")
	}
	servers, err := normServers(c.Server)
	if err != nil {
		return problem("C01", "server: "+err.Error(), "several servers are separated by commas")
	}
	c.Server = servers
	if _, err := ParseUUID(c.UUID); err != nil {
		return problem("C02", "uuid: "+err.Error(), "make one with: nakis-quic init")
	}
	if c.SNI != "" {
		if c.SNI, err = normHost(c.SNI); err != nil {
			return problem("C03", "sni: "+err.Error(), "")
		}
	}
	if c.SNI == "" && len(c.TLSPins) == 0 {
		return problem("C03", "nothing tells the client how to trust the server", "set \"sni\" for a real certificate, or \"tls_pins\" for a self-signed one")
	}
	for _, p := range c.TLSPins {
		if _, err := normalizePin(p); err != nil {
			return problem("C03", err.Error(), "nakis-quic cert prints a valid pin")
		}
	}
	if c.ECHConfig != "" && c.SNI == "" {
		return problem("C04", "ech needs \"sni\"", "sni is the real server name that travels inside the encrypted hello")
	}
	if c.ALPN, err = checkALPN(c.ALPN); err != nil {
		return problem("C03", err.Error(), "")
	}
	c.Listen = fixListen(c.Listen)
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return problem("C05", "listen: "+err.Error(), "for example \"127.0.0.1:1080\"")
	}
	if _, err := ParseLevel(c.LogLevel); err != nil {
		return problem("C09", err.Error(), "")
	}
	if c.PoolLo < 0 || c.PoolHi < 0 || (c.PoolHi > 0 && c.PoolHi < c.PoolLo) {
		return problem("C06", "pool_lo must not be larger than pool_hi", "")
	}
	c.RaceCount = clamp(c.RaceCount, 2, 16)
	c.PoolLo = clamp(c.PoolLo, 1, 128)
	c.PoolHi = clamp(c.PoolHi, c.PoolLo, 512)
	c.PoolMaxUses = clamp(c.PoolMaxUses, 0, 1<<30)
	c.Streams = clamp(c.Streams, 1, 32768)
	positive(&c.PoolMaxAge, 30*time.Minute)
	positive(&c.DialTimeout, 18*time.Second)
	positive(&c.HandshakeTimeout, 18*time.Second)
	positive(&c.IdleTimeout, 90*time.Second)
	positive(&c.Keepalive, 20*time.Second)
	positive(&c.HalfCloseTimeout, 300*time.Second)
	positive(&c.UDPIdleTimeout, 300*time.Second)
	if c.ProbeInterval < 0 {
		return problem("C06", "probe_interval must not be negative", "0 turns the health probe off")
	}
	if c.RaceStagger < 0 {
		return problem("C06", "race_stagger must not be negative", "")
	}
	if c.Keepalive >= c.IdleTimeout {
		return problem("C06", "keepalive must be shorter than idle_timeout", "")
	}
	if len(c.DNS) > 0 && NewDNSPool(c.DNS) == nil {
		return problem("C10", "dns has no usable entry", "write them as 1.1.1.1 or 1.1.1.1:53")
	}
	if c.InitialStreamWindow == 0 {
		c.InitialStreamWindow = 16 << 20
	}
	if c.MaxStreamWindow == 0 {
		c.MaxStreamWindow = 256 << 20
	}
	if c.InitialConnectionWindow == 0 {
		c.InitialConnectionWindow = 32 << 20
	}
	if c.MaxConnectionWindow == 0 {
		c.MaxConnectionWindow = 1024 << 20
	}
	if c.InitialStreamWindow > c.MaxStreamWindow {
		c.InitialStreamWindow = c.MaxStreamWindow
	}
	if c.InitialConnectionWindow > c.MaxConnectionWindow {
		c.InitialConnectionWindow = c.MaxConnectionWindow
	}
	return nil
}

func (s *ServerConfig) Tidy() error {
	if _, err := ParseUUID(s.UUID); err != nil {
		return problem("S01", "uuid: "+err.Error(), "make one with: nakis-quic init")
	}
	s.Listen = fixListen(s.Listen)
	if _, _, err := net.SplitHostPort(s.Listen); err != nil {
		return problem("S02", "listen: "+err.Error(), "for example \"0.0.0.0:443\"")
	}
	if s.TLSCert == "" || s.TLSKey == "" {
		return problem("S03", "tls_cert and tls_key are needed", "QUIC cannot run without a certificate; nakis-quic cert makes a self-signed one")
	}
	var err error
	if s.ALPN, err = checkALPN(s.ALPN); err != nil {
		return problem("S03", err.Error(), "")
	}
	if _, err := ParseLevel(s.LogLevel); err != nil {
		return problem("C09", err.Error(), "")
	}
	s.MaxConns = clamp(s.MaxConns, 1, 1<<20)
	s.MaxStreams = clamp(s.MaxStreams, 32, 100000)
	positive(&s.DialTimeout, 12*time.Second)
	positive(&s.HandshakeTimeout, 18*time.Second)
	positive(&s.IdleTimeout, 90*time.Second)
	positive(&s.Keepalive, 20*time.Second)
	positive(&s.ShutdownTimeout, 40*time.Second)
	positive(&s.HalfCloseTimeout, 300*time.Second)
	positive(&s.UDPIdleTimeout, 480*time.Second)
	if s.Keepalive >= s.IdleTimeout {
		return problem("S04", "keepalive must be shorter than idle_timeout", "")
	}
	if len(s.DNS) > 0 && NewDNSPool(s.DNS) == nil {
		return problem("S06", "dns has no usable entry", "write them as 1.1.1.1 or 1.1.1.1:53")
	}
	if s.InitialStreamWindow == 0 {
		s.InitialStreamWindow = 16 << 20
	}
	if s.MaxStreamWindow == 0 {
		s.MaxStreamWindow = 256 << 20
	}
	if s.InitialConnectionWindow == 0 {
		s.InitialConnectionWindow = 32 << 20
	}
	if s.MaxConnectionWindow == 0 {
		s.MaxConnectionWindow = 1024 << 20
	}
	if s.InitialStreamWindow > s.MaxStreamWindow {
		s.InitialStreamWindow = s.MaxStreamWindow
	}
	if s.InitialConnectionWindow > s.MaxConnectionWindow {
		s.InitialConnectionWindow = s.MaxConnectionWindow
	}
	return nil
}

func ParseLevel(name string) (slog.Level, error) {
	var l slog.Level
	if name == "" {
		return slog.LevelInfo, nil
	}
	err := l.UnmarshalText([]byte(name))
	return l, err
}