package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"
)

const (
	FrameCap   = BufMax - 2
	PackCap    = FrameCap - 1
	ShapeCap   = 16382
	ShapeSlots = 8
)

type Span time.Duration

func (s Span) D() time.Duration { return time.Duration(s) }

func (s *Span) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return errors.New("duration must be a string such as \"5s\"")
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

type ClientConfig struct {
	Listen           string   `json:"listen"`
	Server           string   `json:"server"`
	UUID             string   `json:"uuid"`
	RaceCount        int      `json:"race_count"`
	DialTimeout      Span     `json:"dial_timeout"`
	HandshakeTimeout Span     `json:"handshake_timeout"`
	PoolLo           int      `json:"pool_lo"`
	PoolHi           int      `json:"pool_hi"`
	PoolMaxAge       Span     `json:"pool_max_age"`
	PoolMaxUses      int      `json:"pool_max_uses"`
	Keepalive        Span     `json:"keepalive"`
	LogLevel         string   `json:"log_level"`
	Congestion       string   `json:"congestion"`
	SendPack         int      `json:"send_pack"`
	SendTail         int      `json:"send_tail"`
	SendQuiet        int      `json:"send_quiet"`
	ShapeUp          [][2]int `json:"shape_up"`
	ShapeWait        Span     `json:"shape_wait"`
	TLS              bool     `json:"tls"`
	SNI              string   `json:"sni"`
	TLSPins          []string `json:"tls_pins"`
	ECHConfig        string   `json:"ech_config"`

	noWarm      bool
	adaptWindow time.Duration
}

type ServerConfig struct {
	Listen           string   `json:"listen"`
	UUID             string   `json:"uuid"`
	DNS              []string `json:"dns"`
	DialTimeout      Span     `json:"dial_timeout"`
	HandshakeTimeout Span     `json:"handshake_timeout"`
	IdleTimeout      Span     `json:"idle_timeout"`
	ShutdownTimeout  Span     `json:"shutdown_timeout"`
	Congestion       string   `json:"congestion"`
	SendPack         int      `json:"send_pack"`
	SendTail         int      `json:"send_tail"`
	SendQuiet        int      `json:"send_quiet"`
	MergePack        int      `json:"merge_pack"`
	MaxQueue         int      `json:"max_queue"`
	MaxConns         int      `json:"max_conns"`
	AllowPrivate     bool     `json:"allow_private"`
	Keepalive        Span     `json:"keepalive"`
	LogLevel         string   `json:"log_level"`
	TLS              bool     `json:"tls"`
	TLSCert          string   `json:"tls_cert"`
	TLSKey           string   `json:"tls_key"`
	ECHKeys          []ECHKey `json:"ech_keys"`
}

func DefaultClient() ClientConfig {
	return ClientConfig{
		Listen:           "127.0.0.1:1080",
		RaceCount:        3,
		DialTimeout:      Span(8 * time.Second),
		HandshakeTimeout: Span(10 * time.Second),
		PoolLo:           2,
		PoolHi:           32,
		PoolMaxAge:       Span(45 * time.Second),
		PoolMaxUses:      8,
		Keepalive:        Span(15 * time.Second),
		LogLevel:         "info",
		SendPack:         20 * 1024,
		SendTail:         512,
		SendQuiet:        4,
		ShapeWait:        Span(20 * time.Millisecond),
		TLS:              true,
	}
}

func DefaultServer() ServerConfig {
	return ServerConfig{
		Listen:           "0.0.0.0:8443",
		DialTimeout:      Span(5 * time.Second),
		HandshakeTimeout: Span(10 * time.Second),
		IdleTimeout:      Span(120 * time.Second),
		ShutdownTimeout:  Span(20 * time.Second),
		Keepalive:        Span(15 * time.Second),
		LogLevel:         "info",
		MaxConns:         4096,
		SendPack:         32 * 1024,
		SendTail:         512,
		SendQuiet:        4,
		MergePack:        20 * 1024,
		MaxQueue:         4 * 1024 * 1024,
		TLS:              true,
	}
}

func decode(path string, dst any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("parse json: %w", err)
	}
	return nil
}

func LoadClient(path string) (ClientConfig, error) {
	cfg := DefaultClient()
	if err := decode(path, &cfg); err != nil {
		return cfg, err
	}
	return cfg, cfg.Tidy()
}

func LoadServer(path string) (ServerConfig, error) {
	cfg := DefaultServer()
	if err := decode(path, &cfg); err != nil {
		return cfg, err
	}
	return cfg, cfg.Tidy()
}

func clamp(v, lo, hi int) int { return min(max(v, lo), hi) }

func positive(v *Span, fallback time.Duration) {
	if *v <= 0 {
		*v = Span(fallback)
	}
}

func FixListen(addr string) string {
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

func (c *ClientConfig) Tidy() error {
	if c.Server == "" {
		return errors.New("server is required")
	}
	if _, err := ParseUUID(c.UUID); err != nil {
		return fmt.Errorf("uuid: %w", err)
	}
	for _, s := range strings.Split(c.Server, ",") {
		if _, _, err := net.SplitHostPort(strings.TrimSpace(s)); err != nil {
			return fmt.Errorf("server %q: %w", s, err)
		}
	}
	c.Listen = FixListen(c.Listen)
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if !c.TLS && (c.ECHConfig != "" || len(c.TLSPins) > 0) {
		return errors.New("ech_config / tls_pins need \"tls\": true")
	}
	if c.TLS && c.SNI == "" && len(c.TLSPins) == 0 {
		return errors.New("tls needs \"sni\" or \"tls_pins\"")
	}
	if c.ECHConfig != "" && c.SNI == "" {
		return errors.New("ech needs \"sni\", the real server name hidden inside the encrypted hello")
	}
	if _, err := ParseLevel(c.LogLevel); err != nil {
		return err
	}
	if err := checkShape(c.ShapeUp); err != nil {
		return err
	}
	c.RaceCount = clamp(c.RaceCount, 2, 12)
	c.PoolLo = clamp(c.PoolLo, 1, 1024)
	c.PoolHi = clamp(c.PoolHi, c.PoolLo+1, 4096)
	c.PoolMaxUses = clamp(c.PoolMaxUses, 0, 100)
	c.SendPack = clamp(c.SendPack, 1024, PackCap)
	c.SendTail = clamp(c.SendTail, 0, c.SendPack-1)
	c.SendQuiet = clamp(c.SendQuiet, 0, 64)
	positive(&c.DialTimeout, 8*time.Second)
	positive(&c.HandshakeTimeout, 10*time.Second)
	positive(&c.PoolMaxAge, 15*time.Second)
	positive(&c.Keepalive, 15*time.Second)
	positive(&c.ShapeWait, 20*time.Millisecond)
	return nil
}

func checkShape(plan [][2]int) error {
	if len(plan) > ShapeSlots {
		return fmt.Errorf("shape_up takes at most %d ranges", ShapeSlots)
	}
	for i, r := range plan {
		if r[0] < 1 || r[1] < r[0] || r[1] > ShapeCap {
			return fmt.Errorf("shape_up[%d]: need 1 <= min <= max <= %d", i, ShapeCap)
		}
	}
	return nil
}

func (s *ServerConfig) Tidy() error {
	if _, err := ParseUUID(s.UUID); err != nil {
		return fmt.Errorf("uuid: %w", err)
	}
	s.Listen = FixListen(s.Listen)
	if _, _, err := net.SplitHostPort(s.Listen); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if _, err := ParseLevel(s.LogLevel); err != nil {
		return err
	}
	if s.TLS && (s.TLSCert == "" || s.TLSKey == "") {
		return errors.New("tls needs tls_cert and tls_key (make them with: nakis cert)")
	}
	if !s.TLS && len(s.ECHKeys) > 0 {
		return errors.New("ech_keys need \"tls\": true")
	}
	s.SendPack = clamp(s.SendPack, 1024, PackCap)
	s.SendTail = clamp(s.SendTail, 0, s.SendPack-1)
	s.SendQuiet = clamp(s.SendQuiet, 0, 64)
	s.MergePack = clamp(s.MergePack, 1024, FrameCap)
	s.MaxQueue = clamp(s.MaxQueue, 64*1024, 256*1024*1024)
	positive(&s.DialTimeout, 5*time.Second)
	positive(&s.HandshakeTimeout, 10*time.Second)
	positive(&s.IdleTimeout, 120*time.Second)
	positive(&s.ShutdownTimeout, 20*time.Second)
	positive(&s.Keepalive, 15*time.Second)
	s.MaxConns = clamp(s.MaxConns, 1, 1<<20)
	return nil
}

func ParseLevel(name string) (slog.Level, error) {
	var l slog.Level
	if name == "" {
		return slog.LevelInfo, nil
	}
	if err := l.UnmarshalText([]byte(name)); err != nil {
		return l, fmt.Errorf("log_level %q: want debug, info, warn or error", name)
	}
	return l, nil
}
