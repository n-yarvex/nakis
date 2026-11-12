package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	uotHost     = "udp.nakis.arpa"
	udpQueueMax = 1 << 20
	udpBatchMax = 32 << 10
	udpDestCap  = 4096
	udpNameCap  = 256
	udpPadMax   = 400
	udpTick     = 10 * time.Second
	udpGiveUp   = 50
)

var errMangled = errors.New("nakis: malformed udp record")

type udpAddr struct {
	host string
	port uint16
}

func (a udpAddr) appendTo(b []byte) ([]byte, error) {
	if ip, err := netip.ParseAddr(a.host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			v := ip.As4()
			b = append(b, 1)
			b = append(b, v[:]...)
		} else {
			v := ip.As16()
			b = append(b, 4)
			b = append(b, v[:]...)
		}
	} else {
		if len(a.host) == 0 || len(a.host) > 255 {
			return nil, errMangled
		}
		b = append(b, 3, byte(len(a.host)))
		b = append(b, a.host...)
	}
	return binary.BigEndian.AppendUint16(b, a.port), nil
}

func readAddr(r io.Reader, atyp byte) (udpAddr, error) {
	var a udpAddr
	switch atyp {
	case 1, 4:
		raw := make([]byte, map[byte]int{1: 4, 4: 16}[atyp])
		if _, err := io.ReadFull(r, raw); err != nil {
			return a, err
		}
		ip, _ := netip.AddrFromSlice(raw)
		a.host = ip.String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return a, err
		}
		if n[0] == 0 {
			return a, errMangled
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return a, err
		}
		a.host = string(name)
	default:
		return a, errMangled
	}
	var pb [2]byte
	if _, err := io.ReadFull(r, pb[:]); err != nil {
		return a, err
	}
	a.port = binary.BigEndian.Uint16(pb[:])
	return a, nil
}

func appendRecord(b []byte, a udpAddr, data []byte) ([]byte, error) {
	if len(data) > 0xFFFF {
		return nil, errMangled
	}
	b, err := a.appendTo(b)
	if err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...), nil
}

func readRecord(r *bufio.Reader, buf []byte) (udpAddr, []byte, error) {
	atyp, err := r.ReadByte()
	if err != nil {
		return udpAddr{}, nil, err
	}
	a, err := readAddr(r, atyp)
	if err != nil {
		return a, nil, midRecord(err)
	}
	var lb [2]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return a, nil, midRecord(err)
	}
	n := int(binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return a, nil, midRecord(err)
	}
	return a, buf[:n], nil
}

func midRecord(err error) error {
	if errors.Is(err, ErrNap) || errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: cut short", errMangled)
	}
	return err
}

func socksUDPHead(a udpAddr) ([]byte, error) {
	return a.appendTo([]byte{0, 0, 0})
}

func parseSocksUDP(p []byte) (udpAddr, []byte, bool) {
	var a udpAddr
	if len(p) < 4 || p[2] != 0 {
		return a, nil, false
	}
	r := bytes.NewReader(p[4:])
	a, err := readAddr(r, p[3])
	if err != nil {
		return a, nil, false
	}
	return a, p[len(p)-r.Len():], true
}

func randBelow(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return mrand.IntN(n)
	}
	return int(v.Int64())
}

func sendWithPad(mc *Tunnel, payload []byte) error {
	wire := GetBuf(Headroom + len(payload))
	defer PutBuf(wire)
	copy(wire[Headroom:], payload)
	return mc.SendWirePad(wire, 4+randBelow(udpPadMax))
}

type jitterMux struct {
	jitter time.Duration
	send   func([]byte) error

	mu     sync.Mutex
	cond   *sync.Cond
	q      [][]byte
	size   int
	closed bool
	failed atomic.Bool
	stop   chan struct{}
	done   chan struct{}
}

func newJitterMux(jitter time.Duration, send func([]byte) error) *jitterMux {
	m := &jitterMux{jitter: jitter, send: send, stop: make(chan struct{}), done: make(chan struct{})}
	m.cond = sync.NewCond(&m.mu)
	go m.run()
	return m
}

func (m *jitterMux) push(rec []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.failed.Load() || m.size+len(rec) > udpQueueMax {
		return false
	}
	cp := GetBuf(len(rec))
	copy(cp, rec)
	m.q = append(m.q, cp)
	m.size += len(rec)
	m.cond.Signal()
	return true
}

func (m *jitterMux) nap() {
	t := time.NewTimer(time.Duration(mrand.Int64N(int64(m.jitter))) + time.Microsecond)
	defer t.Stop()
	select {
	case <-t.C:
	case <-m.stop:
	}
}

func (m *jitterMux) take() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.q) == 0 {
		return nil
	}
	var out []byte
	i := 0
	for i < len(m.q) && (i == 0 || len(out)+len(m.q[i]) <= udpBatchMax) {
		out = append(out, m.q[i]...)
		m.size -= len(m.q[i])
		PutBuf(m.q[i])
		i++
	}
	m.q = m.q[:copy(m.q, m.q[i:])]
	return out
}

func (m *jitterMux) abandon() {
	m.failed.Store(true)
	m.mu.Lock()
	for _, p := range m.q {
		PutBuf(p)
	}
	m.q, m.size = nil, 0
	m.mu.Unlock()
}

func (m *jitterMux) run() {
	defer close(m.done)
	for {
		m.mu.Lock()
		for len(m.q) == 0 && !m.closed {
			m.cond.Wait()
		}
		empty := len(m.q) == 0
		m.mu.Unlock()
		if empty {
			return
		}
		if m.jitter > 0 {
			m.nap()
		}
		for {
			batch := m.take()
			if batch == nil {
				break
			}
			if err := m.send(batch); err != nil {
				m.abandon()
				return
			}
		}
	}
}

func (m *jitterMux) close() {
	m.mu.Lock()
	if !m.closed {
		m.closed = true
		close(m.stop)
	}
	m.cond.Broadcast()
	m.mu.Unlock()
	<-m.done
}

type uotServe struct {
	l    *Lair
	mc   *Tunnel
	pc   net.PacketConn
	mux  *jitterMux
	last atomic.Int64

	mu    sync.Mutex
	sent  map[netip.Addr]time.Time
	names map[string]netip.Addr
}

func (l *Lair) uot(ctx context.Context, mc *Tunnel) bool {
	l.logger.Debug("nakis udp", "remote", mc.RemoteAddr().String())
	if !l.cfg.UDP {
		_ = mc.Send(nil, OopsBytes(0, "udp is switched off on this server"))
		return false
	}
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		l.logger.Warn("couldn't open a udp socket for a client", "err", err)
		_ = mc.Send(nil, OopsBytes(errnoOf(err), err.Error()))
		return false
	}
	defer pc.Close()
	if sendWithPad(mc, CozyByte) != nil {
		return false
	}
	s := &uotServe{l: l, mc: mc, pc: pc, sent: map[netip.Addr]time.Time{}, names: map[string]netip.Addr{}}
	s.last.Store(time.Now().UnixNano())
	s.mux = newJitterMux(l.cfg.UDPJitter.D(), func(b []byte) error { return mc.Send(nil, b) })
	return s.run(ctx)
}

func (s *uotServe) run(ctx context.Context) bool {
	pumped := make(chan struct{})
	go func() {
		defer close(pumped)
		s.pump()
	}()
	quit := make(chan struct{})
	var idled atomic.Bool
	go func() {
		t := time.NewTicker(udpTick)
		defer t.Stop()
		for {
			select {
			case <-quit:
				return
			case <-ctx.Done():
				_ = s.mc.Close()
				return
			case <-t.C:
				if time.Since(time.Unix(0, s.last.Load())) > s.l.cfg.UDPIdleTimeout.D() {
					idled.Store(true)
					_ = s.mc.Close()
					return
				}
			}
		}
	}()

	err := s.consume(ctx)
	close(quit)
	_ = s.pc.Close()
	<-pumped
	s.mux.close()
	if idled.Load() {
		s.l.logger.Debug("udp association idle for too long, closed", "remote", s.mc.RemoteAddr().String())
		return false
	}
	if !errors.Is(err, ErrNap) || s.mux.failed.Load() {
		return false
	}
	return s.mc.Nap() == nil
}

func (s *uotServe) consume(ctx context.Context) error {
	br := bufio.NewReaderSize(s.mc, 16<<10)
	buf := make([]byte, 0xFFFF)
	for {
		a, data, err := readRecord(br, buf)
		if err != nil {
			return err
		}
		s.last.Store(time.Now().UnixNano())
		s.forward(ctx, a, data)
	}
}

func (s *uotServe) resolve(ctx context.Context, host string) (netip.Addr, bool) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.WithZone("").Unmap(), true
	}
	s.mu.Lock()
	ip, ok := s.names[host]
	s.mu.Unlock()
	if ok {
		return ip, true
	}
	rctx, cancel := context.WithTimeout(ctx, s.l.cfg.DialTimeout.D())
	defer cancel()
	list, err := s.l.names.Resolve(rctx, host)
	if err != nil {
		return netip.Addr{}, false
	}
	var pick netip.Addr
	for _, item := range list {
		ip, err := netip.ParseAddr(item)
		if err != nil {
			continue
		}
		ip = ip.WithZone("").Unmap()
		if !s.l.cfg.AllowPrivate && blockedAddr(ip) {
			continue
		}
		if !pick.IsValid() || (ip.Is4() && !pick.Is4()) {
			pick = ip
		}
	}
	if !pick.IsValid() {
		return pick, false
	}
	s.mu.Lock()
	if len(s.names) >= udpNameCap {
		clear(s.names)
	}
	s.names[host] = pick
	s.mu.Unlock()
	return pick, true
}

func (s *uotServe) forward(ctx context.Context, a udpAddr, data []byte) {
	if a.port == 0 {
		return
	}
	ip, ok := s.resolve(ctx, a.host)
	if !ok {
		return
	}
	if !s.l.cfg.AllowPrivate && blockedAddr(ip) {
		s.l.logger.Debug("udp target refused, address is private", "target", a.host)
		return
	}
	if _, err := s.pc.WriteTo(data, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, a.port))); err != nil {
		s.l.logger.Debug("udp send failed", "err", err)
		return
	}
	s.note(ip)
}

func (s *uotServe) note(ip netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, known := s.sent[ip]; !known && len(s.sent) >= udpDestCap {
		var oldest netip.Addr
		var at time.Time
		for k, v := range s.sent {
			if !oldest.IsValid() || v.Before(at) {
				oldest, at = k, v
			}
		}
		delete(s.sent, oldest)
	}
	s.sent[ip] = time.Now()
}

func (s *uotServe) allowed(ip netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.sent[ip]
	return ok
}

func (s *uotServe) pump() {
	buf := make([]byte, 0xFFFF)
	var rec []byte
	strikes := 0
	for {
		n, from, err := s.pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if strikes++; strikes >= udpGiveUp {
				s.l.logger.Debug("udp socket keeps failing, closing the association", "err", err)
				_ = s.mc.Close()
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		strikes = 0
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		ap := ua.AddrPort()
		ip := ap.Addr().WithZone("").Unmap()
		if !s.allowed(ip) {
			continue
		}
		rec, err = appendRecord(rec[:0], udpAddr{host: ip.String(), port: ap.Port()}, buf[:n])
		if err != nil {
			continue
		}
		s.last.Store(time.Now().UnixNano())
		s.mux.push(rec)
	}
}

type socksReq struct {
	cmd  byte
	host string
	port uint16
}

var replyFail = []byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}

func socksBound(ip net.IP, port int) []byte {
	var b []byte
	if v4 := ip.To4(); v4 != nil {
		b = append([]byte{5, 0, 0, 1}, v4...)
	} else {
		b = append([]byte{5, 0, 0, 4}, ip.To16()...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port))
}

type udpAssoc struct {
	k      *Kitten
	app    net.Conn
	relay  net.PacketConn
	pc     *purrConn
	mux    *jitterMux
	remote *net.TCPAddr
	want   uint16
	peer   atomic.Pointer[net.UDPAddr]
}

func (k *Kitten) handleUDP(ctx context.Context, app net.Conn, ref *sessionRef, req socksReq) {
	local, lok := app.LocalAddr().(*net.TCPAddr)
	remote, rok := app.RemoteAddr().(*net.TCPAddr)
	if !lok || !rok {
		_, _ = app.Write(replyFail)
		return
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP, Zone: local.Zone})
	if err != nil {
		k.logger.Warn("couldn't open the udp relay socket", "err", err)
		_, _ = app.Write(replyFail)
		return
	}
	defer relay.Close()

	k.mu.Lock()
	k.used++
	k.mu.Unlock()
	pc, err := k.dialTCP(ctx, uotHost, 0)
	if err != nil {
		if ctx.Err() == nil {
			k.logger.Warn("couldn't open a udp tunnel", "err", err)
		}
		_, _ = app.Write(replyFail)
		return
	}
	if !ref.bind(pc.mc) {
		_ = pc.mc.Close()
		return
	}
	if err := sendWithPad(pc.mc, pc.first); err != nil {
		pc.broken.Store(true)
		pc.release()
		_, _ = app.Write(replyFail)
		return
	}
	_ = app.SetWriteDeadline(time.Now().Add(k.cfg.HandshakeTimeout.D()))
	_, err = app.Write(socksBound(local.IP, relay.LocalAddr().(*net.UDPAddr).Port))
	_ = app.SetWriteDeadline(time.Time{})
	if err != nil {
		pc.broken.Store(true)
		pc.release()
		return
	}

	a := &udpAssoc{k: k, app: app, relay: relay, pc: pc, remote: remote}
	if ip, perr := netip.ParseAddr(req.host); perr == nil && !ip.IsUnspecified() {
		a.want = req.port
	}
	a.mux = newJitterMux(k.cfg.UDPJitter.D(), func(b []byte) error {
		err := pc.mc.Send(nil, b)
		if err != nil {
			pc.broken.Store(true)
		}
		return err
	})
	a.run(ctx)
	pc.release()
}

func (a *udpAssoc) run(ctx context.Context) {
	upDone := make(chan struct{})
	go func() {
		defer close(upDone)
		a.up()
	}()
	downDone := make(chan struct{})
	go func() {
		defer close(downDone)
		a.down()
	}()
	ctlDone := make(chan struct{})
	go func() {
		defer close(ctlDone)
		_, _ = io.Copy(io.Discard, a.app)
	}()

	select {
	case <-ctlDone:
	case <-downDone:
	case <-upDone:
	case <-ctx.Done():
	}
	_ = a.relay.Close()
	<-upDone
	a.mux.close()
	if a.mux.failed.Load() {
		a.pc.broken.Store(true)
	}
	if !a.pc.broken.Load() && !a.pc.napSent.Load() {
		a.pc.napSent.Store(true)
		if err := a.pc.mc.Nap(); err != nil {
			a.pc.broken.Store(true)
		}
	}
	_ = a.pc.mc.SetReadDeadline(time.Now().Add(a.k.drainWindow()))
	<-downDone
}

func (a *udpAssoc) up() {
	buf := make([]byte, 0xFFFF+300)
	var rec []byte
	strikes := 0
	for {
		n, from, err := a.relay.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if strikes++; strikes >= udpGiveUp {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		strikes = 0
		ua, ok := from.(*net.UDPAddr)
		if !ok || !ua.IP.Equal(a.remote.IP) {
			continue
		}
		cur := a.peer.Load()
		if cur == nil {
			if a.want != 0 && uint16(ua.Port) != a.want {
				continue
			}
			a.peer.CompareAndSwap(nil, ua)
			cur = a.peer.Load()
		}
		if cur.Port != ua.Port {
			continue
		}
		dst, data, ok := parseSocksUDP(buf[:n])
		if !ok || dst.port == 0 || dst.host == uotHost {
			continue
		}
		if rec, err = appendRecord(rec[:0], dst, data); err != nil {
			continue
		}
		a.mux.push(rec)
	}
}

func (a *udpAssoc) down() {
	mc := a.pc.mc
	if err := mc.ReadReply(); err != nil {
		a.pc.broken.Store(true)
		var mew *MewError
		if errors.As(err, &mew) {
			a.k.logger.Warn("the server wouldn't carry udp", "err", err)
		}
		return
	}
	br := bufio.NewReaderSize(mc, 16<<10)
	buf := make([]byte, 0xFFFF)
	var out []byte
	for {
		src, data, err := readRecord(br, buf)
		if err != nil {
			if errors.Is(err, ErrNap) {
				a.pc.napSeen.Store(true)
			} else {
				a.pc.broken.Store(true)
			}
			return
		}
		peer := a.peer.Load()
		if peer == nil {
			continue
		}
		head, err := socksUDPHead(src)
		if err != nil {
			continue
		}
		out = append(append(out[:0], head...), data...)
		_, _ = a.relay.WriteTo(out, peer)
	}
}
