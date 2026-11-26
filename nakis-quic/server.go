package main

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
)

const maxAssocs = 96

var errPrivate = errors.New("target is not allowed")

type Lair struct {
	cfg    ServerConfig
	logger *slog.Logger
	guard  *Guard
	tlsCfg *tls.Config
	qcfg   *quic.Config
	names  *NameCache

	tr    *quic.Transport
	ln    *quic.Listener
	wire  net.PacketConn
	conns atomic.Int64
	wg    sync.WaitGroup

	mu     sync.Mutex
	active map[*quic.Conn]struct{}
}

func NewLair(cfg ServerConfig, logger *slog.Logger) (*Lair, error) {
	id, err := ParseUUID(cfg.UUID)
	if err != nil {
		return nil, problem("S01", "uuid: "+err.Error(), "")
	}
	tlsCfg, err := serverTLS(cfg.TLSCert, cfg.TLSKey, cfg.ECHKeys, cfg.ALPN)
	if err != nil {
		return nil, problem("S03", err.Error(), "nakis-quic cert makes a self-signed pair")
	}
	var lookup LookupFunc
	if p := NewDNSPool(cfg.DNS); p != nil {
		lookup = p.LookupIPAddr
	}
	return &Lair{
		cfg:    cfg,
		logger: logger,
		guard:  NewGuard(id),
		tlsCfg: tlsCfg,
		qcfg: quicConfig(
			cfg.IdleTimeout.D(),
			cfg.Keepalive.D(),
			cfg.HandshakeTimeout.D(),
			cfg.UDP,
			cfg.MaxStreams,
			cfg.InitialStreamWindow,
			cfg.MaxStreamWindow,
			cfg.InitialConnectionWindow,
			cfg.MaxConnectionWindow,
		),
		names:  NewNames(dnsTTL, lookup),
		active: map[*quic.Conn]struct{}{},
	}, nil
}

func (l *Lair) Listen() error {
	ua, err := net.ResolveUDPAddr("udp", l.cfg.Listen)
	if err != nil {
		return problem("S02", "listen: "+err.Error(), "")
	}
	uc, err := net.ListenUDP("udp", ua)
	if err != nil {
		return problem("S07", "can't listen on udp "+l.cfg.Listen+": "+err.Error(), "is another program using that port?")
	}
	l.wire = uc
	l.tr = &quic.Transport{
		Conn: uc,
		VerifySourceAddress: func(net.Addr) bool {
			return l.conns.Load() >= int64(l.cfg.MaxConns)/2
		},
	}
	l.ln, err = l.tr.Listen(l.tlsCfg, l.qcfg)
	if err != nil {
		_ = uc.Close()
		return err
	}
	l.logger.Info("nakis-quic server is listening", "addr", uc.LocalAddr().String(), "udp", l.cfg.UDP, "ech", len(l.cfg.ECHKeys) > 0)
	return nil
}

func (l *Lair) Addr() net.Addr { return l.ln.Addr() }

func (l *Lair) ListenAndServe(ctx context.Context) error {
	if err := l.Listen(); err != nil {
		return err
	}
	return l.Serve(ctx)
}

func (l *Lair) Serve(ctx context.Context) error {
	var pause acceptPause
	var serr error
	for {
		conn, err := l.ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, quic.ErrServerClosed) {
				break
			}
			if !pause.wait(ctx, err) {
				serr = err
				break
			}
			l.logger.Warn("accept is failing, backing off", "err", err)
			continue
		}
		pause.reset()
		if l.conns.Load() >= int64(l.cfg.MaxConns) {
			_ = conn.CloseWithError(quietCode, "")
			continue
		}
		l.conns.Add(1)
		l.track(conn, true)
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			defer l.conns.Add(-1)
			defer l.track(conn, false)
			defer func() {
				if r := recover(); r != nil {
					l.logger.Error("recovered from a crash in a connection", "err", r)
					_ = conn.CloseWithError(quietCode, "")
				}
			}()
			l.serveConn(ctx, conn)
		}()
	}
	_ = l.ln.Close()
	done := make(chan struct{})
	go func() {
		l.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(l.cfg.ShutdownTimeout.D()):
		l.logger.Warn("connections were still open when the shutdown wait ran out; closing them")
		l.mu.Lock()
		for c := range l.active {
			_ = c.CloseWithError(byeCode, "")
		}
		l.mu.Unlock()
		<-done
	}
	_ = l.tr.Close()
	_ = l.wire.Close()
	return serr
}

func (l *Lair) track(c *quic.Conn, on bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if on {
		l.active[c] = struct{}{}
	} else {
		delete(l.active, c)
	}
}

type connAssocs struct {
	whisk atomic.Bool
	mu    sync.Mutex
	m     map[uint16]*srvAssoc
	next  uint16
}

func (c *connAssocs) add(mk func(id uint16) *srvAssoc) *srvAssoc {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= maxAssocs {
		return nil
	}
	for {
		c.next++
		if c.next == 0 {
			c.next = 1
		}
		if _, busy := c.m[c.next]; !busy {
			break
		}
	}
	a := mk(c.next)
	c.m[a.id] = a
	return a
}

func (c *connAssocs) get(id uint16) *srvAssoc {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[id]
}

func (c *connAssocs) drop(id uint16) {
	c.mu.Lock()
	delete(c.m, id)
	c.mu.Unlock()
}

func (l *Lair) authenticate(ctx context.Context, conn *quic.Conn) error {
	actx, cancel := context.WithTimeout(ctx, l.cfg.HandshakeTimeout.D())
	defer cancel()
	us, err := conn.AcceptUniStream(actx)
	if err != nil {
		return err
	}
	_ = us.SetReadDeadline(time.Now().Add(l.cfg.HandshakeTimeout.D()))
	var msg [ProofSize]byte
	if _, err := io.ReadFull(us, msg[:]); err != nil {
		return err
	}
	state := conn.ConnectionState().TLS
	bind, err := state.ExportKeyingMaterial(bindLabel, nil, 32)
	if err != nil {
		return err
	}
	return l.guard.Accept(msg[:], bind)
}

func (l *Lair) serveConn(ctx context.Context, conn *quic.Conn) {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := l.authenticate(cctx, conn); err != nil {
		l.logger.Debug("turned a connection away", "err", err)
		_ = conn.CloseWithError(quietCode, "")
		return
	}
	go func() {
		for {
			rs, err := conn.AcceptUniStream(cctx)
			if err != nil {
				return
			}
			rs.CancelRead(abortCode)
		}
	}()
	assocs := &connAssocs{m: map[uint16]*srvAssoc{}}
	if l.cfg.UDP {
		go func() {
			for {
				p, err := conn.ReceiveDatagram(cctx)
				if err != nil {
					return
				}
				id, t, data, ok := parseDatagram(p)
				if !ok {
					continue
				}
				if a := assocs.get(id); a != nil {
					a.deliver(t, data)
				}
			}
		}()
	}
	var streams sync.WaitGroup
	for {
		st, err := conn.AcceptStream(cctx)
		if err != nil {
			break
		}
		streams.Add(1)
		go func() {
			defer streams.Done()
			defer func() {
				if r := recover(); r != nil {
					l.logger.Error("recovered from a crash in a stream", "err", r)
					qHalf{st}.abort()
				}
			}()
			l.handleStream(cctx, conn, st, assocs)
		}()
	}
	cancel()
	_ = conn.CloseWithError(0, "")
	streams.Wait()
}

func (l *Lair) handleStream(ctx context.Context, conn *quic.Conn, st *quic.Stream, assocs *connAssocs) {
	_ = st.SetReadDeadline(time.Now().Add(l.cfg.HandshakeTimeout.D()))
	cmd, t, err := readHello(st)
	_ = st.SetReadDeadline(time.Time{})
	if err != nil {
		qHalf{st}.abort()
		return
	}
	switch cmd {
	case cmdHug:
		l.hug(ctx, st, t)
	case cmdPounce:
		l.pounce(ctx, conn, st, assocs)
	case cmdWhisker:
		l.whisker(st, assocs)
	}
}

func (l *Lair) hug(ctx context.Context, st *quic.Stream, t target) {
	dctx, cancel := context.WithTimeout(ctx, l.cfg.DialTimeout.D())
	c, err := l.dial(dctx, t)
	cancel()
	if err != nil {
		code, msg := oopsFor(err)
		l.logger.Warn("couldn't connect to a target for a client", "reason", msg)
		l.logger.Debug("target was", "target", t.String(), "err", err)
		_, _ = st.Write(oopsBytes(code, msg))
		_ = st.Close()
		return
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	if _, err := st.Write(cozyBytes(0, false)); err != nil {
		_ = c.Close()
		qHalf{st}.abort()
		return
	}
	relay(qHalf{st}, tHalf{c}, l.cfg.HalfCloseTimeout.D())
}

func (l *Lair) pounce(ctx context.Context, conn *quic.Conn, st *quic.Stream, assocs *connAssocs) {
	if !l.cfg.UDP {
		_, _ = st.Write(oopsBytes(oopsDenied, "udp is turned off on this server"))
		_ = st.Close()
		return
	}
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		_, _ = st.Write(oopsBytes(oopsOther, "udp socket failed"))
		_ = st.Close()
		return
	}
	a := assocs.add(func(id uint16) *srvAssoc {
		return &srvAssoc{l: l, conn: conn, st: st, id: id, pc: pc, sent: map[netip.Addr]struct{}{}}
	})
	if a == nil {
		_ = pc.Close()
		_, _ = st.Write(oopsBytes(oopsBusy, "too many udp associations on this connection"))
		_ = st.Close()
		return
	}
	defer assocs.drop(a.id)
	a.last.Store(time.Now().UnixNano())
	if _, err := st.Write(cozyBytes(a.id, true)); err != nil {
		_ = pc.Close()
		qHalf{st}.abort()
		return
	}
	a.run(ctx)
}

func (l *Lair) whisker(st *quic.Stream, assocs *connAssocs) {
	if !assocs.whisk.CompareAndSwap(false, true) {
		qHalf{st}.abort()
		return
	}
	if _, err := st.Write(cozyBytes(0, false)); err != nil {
		qHalf{st}.abort()
		return
	}
	var b [8]byte
	for {
		if _, err := io.ReadFull(st, b[:]); err != nil {
			qHalf{st}.abort()
			return
		}
		if _, err := st.Write(b[:]); err != nil {
			qHalf{st}.abort()
			return
		}
	}
}

func isPrivate(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, p := range []string{"100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4", "0.0.0.0/8"} {
		if netip.MustParsePrefix(p).Contains(ip) {
			return true
		}
	}
	return false
}

func (l *Lair) allowed(ip netip.Addr) bool {
	return l.cfg.AllowPrivate || !isPrivate(ip)
}

func (l *Lair) addrs(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	list, err := l.names.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, s := range Interleave(list) {
		if ip, err := netip.ParseAddr(s); err == nil {
			out = append(out, ip.Unmap())
		}
	}
	return out, nil
}

func (l *Lair) dial(ctx context.Context, t target) (net.Conn, error) {
	ips, err := l.addrs(ctx, t.host)
	if err != nil {
		return nil, err
	}
	var allowed []netip.Addr
	for _, ip := range ips {
		if l.allowed(ip) {
			allowed = append(allowed, ip)
		}
	}
	if len(allowed) == 0 {
		return nil, errPrivate
	}
	var last error
	each := max(l.cfg.DialTimeout.D()/time.Duration(min(len(allowed), 3)), time.Second)
	for _, ip := range allowed {
		actx, cancel := context.WithTimeout(ctx, each)
		var d net.Dialer
		c, err := d.DialContext(actx, "tcp", netip.AddrPortFrom(ip, t.port).String())
		cancel()
		if err == nil {
			return c, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

func (l *Lair) resolveUDP(host string) (netip.Addr, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), l.cfg.DialTimeout.D())
	defer cancel()
	ips, err := l.addrs(ctx, host)
	if err != nil {
		return netip.Addr{}, false
	}
	for _, ip := range ips {
		if l.allowed(ip) {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

func oopsFor(err error) (byte, string) {
	var de *net.DNSError
	switch {
	case errors.Is(err, errPrivate):
		return oopsDenied, "target not allowed"
	case errors.As(err, &de) && de.IsNotFound:
		return oopsName, "name not found"
	case errors.As(err, &de):
		return oopsName, "name lookup failed"
	case errors.Is(err, syscall.ECONNREFUSED):
		return oopsRefused, "connection refused"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return oopsUnreachable, "unreachable"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, syscall.ETIMEDOUT):
		return oopsTimeout, "timed out"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return oopsTimeout, "timed out"
	}
	return oopsOther, "connect failed"
}

func (l *Lair) Conns() int { return int(l.conns.Load()) }