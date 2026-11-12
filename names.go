package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	capacity = 8192
	retryAt  = 5 * time.Second
)

const dnsAttempt = 3 * time.Second

type DNSPool struct {
	servers []string
	res     []*net.Resolver
	pref    atomic.Int32
}

func NewDNSPool(entries []string) *DNSPool {
	p := &DNSPool{}
	for _, e := range entries {
		host := strings.TrimSpace(e)
		if host == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(strings.Trim(host, "[]"), "53")
		}
		p.servers = append(p.servers, host)
		addr := host
		p.res = append(p.res, &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		})
	}
	if len(p.res) == 0 {
		return nil
	}
	return p
}

func (p *DNSPool) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	n := len(p.res)
	start := int(p.pref.Load()) % n
	var last error
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		actx, cancel := ctx, context.CancelFunc(func() {})
		if n > 1 {
			actx, cancel = context.WithTimeout(ctx, dnsAttempt)
		}
		ips, err := p.res[idx].LookupIPAddr(actx, host)
		cancel()
		if err == nil {
			p.pref.Store(int32(idx))
			return ips, nil
		}
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, err
		}
		last = err
	}
	return nil, last
}

type LookupFunc func(ctx context.Context, host string) ([]net.IPAddr, error)

type dnsEntry struct {
	ips []string
	err error
	exp time.Time
}

type dnsCall struct {
	done chan struct{}
	ips  []string
	err  error
}

type NameCache struct {
	ttl    time.Duration
	lookup LookupFunc

	mu     sync.Mutex
	held   map[string]dnsEntry
	flying map[string]*dnsCall
}

func NewNames(ttl time.Duration, lookup LookupFunc) *NameCache {
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	return &NameCache{ttl: ttl, lookup: lookup, held: map[string]dnsEntry{}, flying: map[string]*dnsCall{}}
}

func (c *NameCache) Resolve(ctx context.Context, host string) ([]string, error) {
	if net.ParseIP(host) != nil {
		return []string{host}, nil
	}
	var f *dnsCall
	var stale dnsEntry
	for f == nil {
		c.mu.Lock()
		if e, ok := c.held[host]; ok && time.Now().Before(e.exp) {
			c.mu.Unlock()
			return e.ips, e.err
		}
		if other, ok := c.flying[host]; ok {
			c.mu.Unlock()
			select {
			case <-other.done:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			if other.err != nil && (errors.Is(other.err, context.Canceled) || errors.Is(other.err, context.DeadlineExceeded)) && ctx.Err() == nil {
				continue
			}
			return other.ips, other.err
		}
		f = &dnsCall{done: make(chan struct{})}
		c.flying[host] = f
		stale = c.held[host]
		c.mu.Unlock()
	}

	addrs, err := c.lookup(ctx, host)
	if err == nil && len(addrs) == 0 {
		err = errors.New("no address")
	}
	e := dnsEntry{exp: time.Now().Add(c.ttl)}
	switch {
	case err == nil:
		for _, a := range addrs {
			e.ips = append(e.ips, a.String())
		}
	case len(stale.ips) > 0:
		e.ips, e.exp = stale.ips, time.Now().Add(retryAt)
	default:
		e.err, e.exp = err, time.Now().Add(retryAt)
	}
	if ctx.Err() != nil && err != nil {
		e.exp = time.Time{}
	}

	c.mu.Lock()
	if len(c.held) >= capacity {
		for k := range c.held {
			delete(c.held, k)
			break
		}
	}
	c.held[host] = e
	delete(c.flying, host)
	c.mu.Unlock()

	f.ips, f.err = e.ips, e.err
	close(f.done)
	return f.ips, f.err
}

func Interleave(ips []string) []string {
	var v4, v6 []string
	for _, ip := range ips {
		if strings.IndexByte(ip, ':') >= 0 {
			v6 = append(v6, ip)
		} else {
			v4 = append(v4, ip)
		}
	}
	out := make([]string, 0, len(ips))
	for i := 0; i < len(v4) || i < len(v6); i++ {
		if i < len(v4) {
			out = append(out, v4[i])
		}
		if i < len(v6) {
			out = append(out, v6[i])
		}
	}
	return out
}
