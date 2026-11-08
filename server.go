package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Lair struct {
	cfg      ServerConfig
	guard    *Guard
	skewNote atomic.Bool
	turnNote atomic.Bool
	turned   atomic.Int64
	slots    chan struct{}
	names    *NameCache
	logger   *slog.Logger
	resolver *net.Resolver
	tlsCfg   *tls.Config

	mu    sync.Mutex
	conns map[net.Conn]struct{}
	wg    sync.WaitGroup
}

func NewLair(cfg ServerConfig, logger *slog.Logger) (*Lair, error) {
	id, err := ParseUUID(cfg.UUID)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	l := &Lair{cfg: cfg, guard: NewGuard(id), slots: make(chan struct{}, cfg.MaxConns), logger: logger, conns: map[net.Conn]struct{}{}}
	if cfg.TLS {
		l.tlsCfg, err = TLSServerConfig(ServerOptions{
			CertFile: cfg.TLSCert,
			KeyFile:  cfg.TLSKey,
			ECHKeys:  cfg.ECHKeys,
		})
		if err != nil {
			return nil, err
		}
	}
	l.resolver = buildResolver(cfg.DNS)
	lookup := net.DefaultResolver.LookupIPAddr
	if l.resolver != nil {
		lookup = l.resolver.LookupIPAddr
	}
	l.names = NewNames(60*time.Second, lookup)
	for _, addr := range cfg.DNS {
		logger.Info("looking up target names through " + addr)
	}
	logger.Info("server ready",
		"listen", cfg.Listen,
		"tls", cfg.TLS,
		"ech_keys", len(cfg.ECHKeys),
		"send_pack", cfg.SendPack,
		"send_tail", cfg.SendTail,
		"send_quiet", cfg.SendQuiet,
		"merge_pack", cfg.MergePack,
		"max_queue", cfg.MaxQueue,
	)
	return l, nil
}

func buildResolver(entries []string) *net.Resolver {
	var servers []string
	for _, e := range entries {
		host := strings.TrimSpace(e)
		if host == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(host, "53")
		}
		servers = append(servers, host)
	}
	if len(servers) == 0 {
		return nil
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			lastErr := errors.New("no DNS server reachable")
			for _, sv := range servers {
				conn, err := d.DialContext(ctx, network, sv)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

func (l *Lair) warnCongestion(err error) {
	l.logger.Warn("couldn't switch the congestion control, carrying on with the system default", "wanted", l.cfg.Congestion, "err", err)
}

func (l *Lair) ListenAndServe(ctx context.Context) error {
	lc := net.ListenConfig{Control: Congestion(l.cfg.Congestion, l.warnCongestion)}
	ln, err := lc.Listen(ctx, "tcp", l.cfg.Listen)
	if err != nil {
		return err
	}
	return l.Serve(ctx, ln)
}

func (l *Lair) track(c net.Conn, on bool) {
	l.mu.Lock()
	if on {
		l.conns[c] = struct{}{}
	} else {
		delete(l.conns, c)
	}
	l.mu.Unlock()
}

func (l *Lair) Serve(ctx context.Context, ln net.Listener) error {
	l.logger.Info("listening for tunnels", "addr", ln.Addr().String())
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	defer l.drainAll()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(l.cfg.Keepalive.D())
		}
		select {
		case l.slots <- struct{}{}:
		default:
			l.logger.Warn(fmt.Sprintf("already at the limit of %d connections, dropping new ones until some finish", l.cfg.MaxConns))
			_ = conn.Close()
			continue
		}
		l.track(conn, true)
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			defer l.track(conn, false)
			defer func() { <-l.slots }()
			l.handleConn(ctx, conn)
		}()
	}
}

func (l *Lair) drainAll() {
	done := make(chan struct{})
	go func() {
		l.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return
	case <-time.After(l.cfg.ShutdownTimeout.D()):
		l.logger.Warn("some sessions were still running when the shutdown wait ran out; closing them")
	}
	l.mu.Lock()
	for c := range l.conns {
		_ = c.Close()
	}
	l.mu.Unlock()
	<-done
}

func (l *Lair) welcome(ctx context.Context, raw net.Conn) (*Tunnel, error) {
	if l.tlsCfg == nil {
		return WrapTunnel(raw, nil), nil
	}
	b := NewBatcher(raw)
	tc := tls.Server(b, l.tlsCfg)
	hctx, cancel := context.WithTimeout(ctx, l.cfg.HandshakeTimeout.D())
	err := tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	state := tc.ConnectionState()
	bind, err := state.ExportKeyingMaterial("nakis/bind", nil, 32)
	if err != nil {
		return nil, err
	}
	mc := WrapTunnel(tc, b)
	mc.bind = bind
	return mc, nil
}

var errTurnedAway = errors.New("turned away")

func (l *Lair) admit(mc *Tunnel) error {
	frame, prefix, err := mc.ReadFirst(l.cfg.IdleTimeout.D(), min(l.cfg.HandshakeTimeout.D(), firstBody))
	if err != nil {
		return err
	}
	if frame == nil {
		l.refuse(mc, errors.New("not a nakis frame"))
		l.decoy(mc, prefix)
		return errTurnedAway
	}
	if len(frame) < ProofSize {
		PutBuf(frame)
		l.refuse(mc, ErrBadMac)
		l.decoy(mc, nil)
		return errTurnedAway
	}
	if err := l.guard.Accept(frame[:ProofSize], mc.bind); err != nil {
		PutBuf(frame)
		l.refuse(mc, err)
		l.decoy(mc, nil)
		return errTurnedAway
	}
	if len(frame) == ProofSize {
		PutBuf(frame)
		return nil
	}
	mc.Unread(frame, ProofSize)
	return nil
}

func (l *Lair) refuse(mc *Tunnel, err error) {
	remote := mc.RemoteAddr().String()
	l.turned.Add(1)
	if l.turnNote.CompareAndSwap(false, true) {
		time.AfterFunc(time.Minute, func() {
			n := l.turned.Swap(0)
			l.turnNote.Store(false)
			l.logger.Warn(fmt.Sprintf("turned away %d connection(s) in the last minute that didn't present a valid proof; if one of them is yours, check the uuid and the clock", n))
		})
	}
	var stale *StaleError
	if errors.As(err, &stale) && l.skewNote.CompareAndSwap(false, true) {
		l.logger.Warn(fmt.Sprintf("a client's clock is %v away from mine; the allowed gap is %v", stale.Skew.Round(time.Second), ProofWindow), "remote", remote)
		time.AfterFunc(10*time.Second, func() { l.skewNote.Store(false) })
		return
	}
	l.logger.Debug("proof refused", "remote", remote, "err", err)
}

func (l *Lair) handleConn(ctx context.Context, raw net.Conn) {
	defer raw.Close()
	defer func() {
		if r := recover(); r != nil {
			l.logger.Error("handleConn panic", "remote", raw.RemoteAddr().String(), "err", r)
		}
	}()

	mc, err := l.welcome(ctx, raw)
	if err != nil {
		l.logger.Debug("handshake failed", "remote", raw.RemoteAddr().String(), "err", err)
		return
	}
	defer mc.Close()
	if err := l.admit(mc); err != nil {
		return
	}

	for {
		_ = raw.SetReadDeadline(time.Now().Add(l.cfg.IdleTimeout.D()))
		again, err := l.serveOne(ctx, mc)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, ErrNap) && ctx.Err() == nil {
				l.logger.Debug("nakis request ended", "remote", raw.RemoteAddr().String(), "err", err)
			}
			return
		}
		if !again {
			l.logger.Debug("tunnel not reusable, closing", "remote", raw.RemoteAddr().String())
			return
		}
	}
}

func readN(mc *Tunnel, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(mc, buf)
	return buf, err
}

func (l *Lair) serveOne(ctx context.Context, mc *Tunnel) (bool, error) {
	version, err := mc.ReadByte()
	if err != nil {
		return false, err
	}
	if version != HelloVersion {
		return false, fmt.Errorf("nakis: invalid protocol version 0x%x", version)
	}
	cmd, err := mc.ReadByte()
	if err != nil {
		return false, err
	}
	if cmd != CmdHug {
		return false, fmt.Errorf("nakis: unknown command 0x%x", cmd)
	}

	idLen, err := mc.ReadByte()
	if err != nil {
		return false, err
	}
	if idLen > 0 {
		if _, err := readN(mc, int(idLen)); err != nil {
			return false, err
		}
	}
	hostLen, err := mc.ReadByte()
	if err != nil {
		return false, err
	}
	if hostLen == 0 {
		return false, errors.New("nakis: connect host empty")
	}
	host, err := readN(mc, int(hostLen))
	if err != nil {
		return false, err
	}
	pb, err := readN(mc, 2)
	if err != nil {
		return false, err
	}
	_ = mc.SetReadDeadline(time.Time{})

	target := net.JoinHostPort(string(host), strconv.Itoa(int(binary.BigEndian.Uint16(pb))))
	return l.hug(ctx, mc, target), nil
}

func (l *Lair) hug(ctx context.Context, mc *Tunnel, target string) bool {
	l.logger.Debug("nakis tcp", "remote", mc.RemoteAddr().String(), "target", target)

	up, err := l.dialTarget(ctx, target)
	if err != nil {
		l.logger.Warn("couldn't connect to "+target+" for a client", "err", err)
		_ = mc.Send(nil, OopsBytes(errnoOf(err), err.Error()))
		return false
	}
	defer up.Close()

	return newNest(l, mc, up).run()
}

func errnoOf(err error) byte {
	var e syscall.Errno
	if errors.As(err, &e) {
		return byte(e)
	}
	return 0
}

var errPrivate = errors.New("target address is private; set allow_private to permit it")

func isPrivate(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

const (
	dialWidth   = 4
	dialStagger = 120 * time.Millisecond
)

func (l *Lair) dialer() *net.Dialer {
	cc := Congestion(l.cfg.Congestion, l.warnCongestion)
	return &net.Dialer{
		Timeout:   l.cfg.DialTimeout.D(),
		KeepAlive: l.cfg.Keepalive.D(),
		Control: func(network, address string, rc syscall.RawConn) error {
			if !l.cfg.AllowPrivate {
				if host, _, err := net.SplitHostPort(address); err == nil && isPrivate(host) {
					return errPrivate
				}
			}
			if cc != nil {
				return cc(network, address, rc)
			}
			return nil
		},
	}
}

func (l *Lair) addresses(ctx context.Context, host string) ([]string, error) {
	ips, err := l.names.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("no usable address")
	}
	ips = Interleave(ips)
	if len(ips) > dialWidth {
		ips = ips[:dialWidth]
	}
	return ips, nil
}

func (l *Lair) dialTarget(ctx context.Context, target string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	ips, err := l.addresses(ctx, host)
	if err != nil {
		return nil, err
	}
	d := l.dialer()
	if len(ips) == 1 {
		return d.DialContext(ctx, "tcp", net.JoinHostPort(ips[0], port))
	}

	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		c   net.Conn
		err error
	}
	out := make(chan result, len(ips))
	for i, ip := range ips {
		go func() {
			if i > 0 {
				t := time.NewTimer(time.Duration(i) * dialStagger)
				defer t.Stop()
				select {
				case <-t.C:
				case <-raceCtx.Done():
					out <- result{err: raceCtx.Err()}
					return
				}
			}
			c, err := d.DialContext(raceCtx, "tcp", net.JoinHostPort(ip, port))
			out <- result{c, err}
		}()
	}
	var last error
	for i := range ips {
		r := <-out
		if r.err == nil {
			cancel()
			go func(left int) {
				for ; left > 0; left-- {
					if x := <-out; x.c != nil {
						_ = x.c.Close()
					}
				}
			}(len(ips) - i - 1)
			return r.c, nil
		}
		last = r.err
	}
	return nil, last
}

const serverDrain = 5 * time.Second

type nest struct {
	srv    *Lair
	tun    *Tunnel
	target net.Conn

	mu     sync.Mutex
	cond   *sync.Cond
	box    *Box
	closed bool
	eof    bool

	gate *Gate

	wMu     sync.Mutex
	greeted bool

	napSeen      atomic.Bool
	broken       atomic.Bool
	feedWG       sync.WaitGroup
	gatherFinish chan struct{}
}

func newNest(srv *Lair, tun *Tunnel, target net.Conn) *nest {
	cfg := srv.cfg
	n := &nest{
		srv:          srv,
		tun:          tun,
		target:       target,
		box:          NewBox(cfg.MergePack, 0),
		gatherFinish: make(chan struct{}),
	}
	n.cond = sync.NewCond(&n.mu)
	n.gate = NewGate(GateOptions{
		Pack:  cfg.SendPack,
		Tail:  cfg.SendTail,
		Quiet: cfg.SendQuiet,
		Head:  Headroom,
		Plan:  personaPlan(false, 0, 0),
		Pad:   true,
		Fill:  personaFill,
	}, n.write)
	return n
}

func (n *nest) write(wire []byte, pad int) error {
	n.wMu.Lock()
	defer n.wMu.Unlock()
	if n.greeted {
		return n.fail(n.tun.SendWirePad(wire, pad))
	}
	n.greeted = true
	pre := GetBuf(len(wire) + 1)
	pre[Headroom] = RespCozy
	copy(pre[Headroom+1:], wire[Headroom:])
	err := n.tun.SendWirePad(pre, pad)
	PutBuf(pre)
	return n.fail(err)
}

func (n *nest) fail(err error) error {
	if err != nil {
		n.broken.Store(true)
	}
	return err
}

func (n *nest) sendNap() error {
	n.wMu.Lock()
	defer n.wMu.Unlock()
	if !n.greeted {
		n.greeted = true
		if err := n.tun.Send(nil, CozyByte); err != nil {
			return err
		}
	}
	return n.tun.Nap()
}

func (n *nest) stop() {
	n.mu.Lock()
	n.closed = true
	n.box.Drain()
	n.cond.Broadcast()
	n.mu.Unlock()
	_ = n.target.Close()
}

func (n *nest) deposit(p []byte) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	for n.box.Size() >= n.srv.cfg.MaxQueue && !n.closed {
		n.cond.Wait()
	}
	if n.closed {
		return false
	}
	n.box.Sprinkle(p)
	n.cond.Broadcast()
	return true
}

func (n *nest) gather() {
	defer close(n.gatherFinish)
	for {
		p, err := n.tun.ReadFrame()
		if err != nil {
			if errors.Is(err, ErrNap) {
				n.napSeen.Store(true)
			} else {
				n.broken.Store(true)
			}
			n.mu.Lock()
			n.eof = true
			n.cond.Broadcast()
			n.mu.Unlock()
			return
		}
		if !n.deposit(p) {
			PutBuf(p)
		}
	}
}

func (n *nest) feed() {
	defer n.feedWG.Done()
	for {
		n.mu.Lock()
		for n.box.Empty() && !n.eof && !n.closed {
			n.cond.Wait()
		}
		if n.closed {
			n.mu.Unlock()
			return
		}
		if n.box.Empty() {
			n.mu.Unlock()
			n.stop()
			return
		}
		d, merged := n.box.Bundle(nil)
		n.cond.Broadcast()
		n.mu.Unlock()

		_, err := n.target.Write(d)
		if !merged {
			PutBuf(d)
		}
		if err != nil {
			n.srv.logger.Debug("target write failed", "err", err)
			n.stop()
			return
		}
	}
}

func (n *nest) mill() {
	wire := GetBuf(Headroom + PackCap)
	defer PutBuf(wire)
	half := PackCap >> 1
	defer func() {
		n.gate.Flush()
		n.gate.Close()
	}()

	for {
		k, err := n.target.Read(wire[Headroom:])
		if k > 0 {
			if k >= half {
				n.gate.Flush()
				if n.write(wire[:Headroom+k], 0) != nil {
					return
				}
			} else {
				n.gate.Feed(wire[Headroom : Headroom+k])
			}
			if n.broken.Load() {
				return
			}
		}
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
				n.srv.logger.Debug("target read ended", "err", err)
			}
			return
		}
	}
}

func (n *nest) run() bool {
	if lead := n.tun.TakePending(); lead != nil {
		n.box.Sprinkle(lead)
	}
	n.feedWG.Add(1)
	go n.feed()
	go n.gather()

	n.mill()
	n.stop()
	n.feedWG.Wait()
	n.mu.Lock()
	n.box.Dispose()
	n.mu.Unlock()

	if n.broken.Load() || n.sendNap() != nil {
		return false
	}
	_ = n.tun.SetReadDeadline(time.Now().Add(serverDrain))
	<-n.gatherFinish
	if n.broken.Load() || !n.napSeen.Load() {
		return false
	}
	_ = n.tun.SetReadDeadline(time.Time{})
	return true
}

const (
	firstBody = 3 * time.Second
	decoyWait = time.Second
	decoyHead = 4096
)

var httpMethods = []string{"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ", "PRI "}

const decoyWelcome = "<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n<style>\nhtml { color-scheme: light dark; }\nbody { width: 35em; margin: 0 auto;\nfont-family: Tahoma, Verdana, Arial, sans-serif; }\n</style>\n</head>\n<body>\n<h1>Welcome to nginx!</h1>\n<p>If you see this page, the nginx web server is successfully installed and\nworking. Further configuration is required.</p>\n\n<p>For online documentation and support please refer to\n<a href=\"http://nginx.org/\">nginx.org</a>.<br/>\nCommercial support is available at\n<a href=\"http://nginx.com/\">nginx.com</a>.</p>\n\n<p><em>Thank you for using nginx.</em></p>\n</body>\n</html>\n"

func errorPage(code int, text string) string {
	return fmt.Sprintf("<html>\r\n<head><title>%d %s</title></head>\r\n<body>\r\n<center><h1>%d %s</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n", code, text, code, text)
}

func decoyReply(head []byte) []byte {
	line := string(head)
	if i := strings.Index(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	status, text, body, isHead := 400, "Bad Request", errorPage(400, "Bad Request"), false
	for _, m := range httpMethods {
		if strings.HasPrefix(line, m) {
			isHead = m == "HEAD "
			if strings.HasPrefix(line[len(m):], "/ ") || strings.HasPrefix(line[len(m):], "/index.html ") {
				status, text, body = 200, "OK", decoyWelcome
			} else {
				status, text, body = 404, "Not Found", errorPage(404, "Not Found")
			}
			break
		}
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "HTTP/1.1 %d %s\r\nServer: nginx\r\nDate: %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, text, time.Now().UTC().Format(http.TimeFormat), len(body))
	if !isHead {
		out.WriteString(body)
	}
	return out.Bytes()
}

func (l *Lair) decoy(mc *Tunnel, prefix []byte) {
	_ = mc.Conn.SetDeadline(time.Now().Add(decoyWait))
	head := append([]byte(nil), prefix...)
	buf := make([]byte, 1024)
	for len(head) < decoyHead && !bytes.Contains(head, []byte("\r\n\r\n")) {
		n, err := mc.rd.Read(buf)
		head = append(head, buf[:n]...)
		if err != nil {
			break
		}
	}
	_, _ = mc.Conn.Write(decoyReply(head))
}
