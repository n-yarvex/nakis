package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	recordMax = 0xFFFF
	sentCap   = 2048
	udpBufSz  = 64 << 10
)

type deliverer interface {
	deliver(t target, data []byte)
}

func (b *Bond) datagrams() {
	for {
		p, err := b.conn.ReceiveDatagram(b.conn.Context())
		if err != nil {
			return
		}
		id, t, data, ok := parseDatagram(p)
		if !ok {
			continue
		}
		if v, ok := b.assocs.Load(id); ok {
			v.(deliverer).deliver(t, data)
		}
	}
}

func sendRecord(st *quic.Stream, wmu *sync.Mutex, t target, data []byte) error {
	rec, err := appendRecord(nil, t, data)
	if err != nil {
		return err
	}
	wmu.Lock()
	defer wmu.Unlock()
	_, err = st.Write(rec)
	return err
}

type udpAssoc struct {
	k      *Kitten
	app    net.Conn
	relay  *net.UDPConn
	lane   *Lane
	id     uint16
	remote *net.TCPAddr
	want   uint16
	peer   atomic.Pointer[net.UDPAddr]
	wmu    sync.Mutex
	last   atomic.Int64
}

func (k *Kitten) handleUDP(ctx context.Context, app net.Conn, ref *sessionRef, req socksReq) {
	local, lok := app.LocalAddr().(*net.TCPAddr)
	remote, rok := app.RemoteAddr().(*net.TCPAddr)
	if !lok || !rok || !k.cfg.UDP {
		_, _ = app.Write(replyFail)
		return
	}
	relayConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP, Zone: local.Zone})
	if err != nil {
		k.logger.Warn("couldn't open the udp relay socket", "err", err)
		_, _ = app.Write(replyFail)
		return
	}
	defer relayConn.Close()

	lane, err := k.lane(ctx)
	if err != nil {
		if ctx.Err() == nil {
			k.logger.Warn("couldn't open a udp stream", "err", err)
		}
		_, _ = app.Write(replyFail)
		return
	}
	defer lane.release()
	if !ref.bind(lane) {
		qHalf{lane.st}.abort()
		return
	}
	hello, _ := helloBytes(cmdPounce, target{})
	_, err = lane.st.Write(hello)
	var id uint16
	if err == nil {
		id, err = readReply(lane.st, true)
	}
	if err != nil {
		var pe *PeerError
		if errors.As(err, &pe) {
			k.logger.Warn("the server won't relay udp", "reason", pe.Msg, "code", "NQ-R03")
		}
		qHalf{lane.st}.abort()
		_, _ = app.Write(replyFail)
		return
	}
	_ = app.SetWriteDeadline(time.Now().Add(k.cfg.HandshakeTimeout.D()))
	_, err = app.Write(socksBound(local.IP, relayConn.LocalAddr().(*net.UDPAddr).Port))
	_ = app.SetWriteDeadline(time.Time{})
	if err != nil {
		qHalf{lane.st}.abort()
		return
	}

	a := &udpAssoc{k: k, app: app, relay: relayConn, lane: lane, id: id, remote: remote}
	if ip, perr := netip.ParseAddr(req.host); perr == nil && !ip.IsUnspecified() {
		a.want = req.port
	}
	a.last.Store(time.Now().UnixNano())
	lane.b.assocs.Store(id, a)
	defer lane.b.assocs.Delete(id)
	a.run(ctx)
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
	idle := time.NewTicker(5 * time.Second)
	defer idle.Stop()
loop:
	for {
		select {
		case <-ctlDone:
			break loop
		case <-downDone:
			break loop
		case <-upDone:
			break loop
		case <-ctx.Done():
			break loop
		case <-a.lane.b.conn.Context().Done():
			break loop
		case <-idle.C:
			if time.Since(time.Unix(0, a.last.Load())) > a.k.cfg.UDPIdleTimeout.D() {
				break loop
			}
		}
	}
	_ = a.relay.Close()
	qHalf{a.lane.st}.abort()
	_ = a.app.Close()
	<-upDone
	<-downDone
}

func (a *udpAssoc) up() {
	buf := getBuf(udpBufSz)
	defer putBuf(buf)
	for {
		n, from, err := a.relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !from.IP.Equal(a.remote.IP) {
			continue
		}
		if a.want != 0 && uint16(from.Port) != a.want {
			continue
		}
		t, data, ok := parseSocksUDP(buf[:n])
		if !ok {
			continue
		}
		a.peer.Store(from)
		a.last.Store(time.Now().UnixNano())
		if err := sendRecord(a.lane.st, &a.wmu, t, data); err != nil {
			return
		}
	}
}

func (a *udpAssoc) down() {
	buf := getBuf(recordMax)
	defer putBuf(buf)
	for {
		t, data, err := readRecord(a.lane.st, buf)
		if err != nil {
			return
		}
		a.deliver(t, data)
	}
}

func (a *udpAssoc) deliver(t target, data []byte) {
	peer := a.peer.Load()
	if peer == nil {
		return
	}
	head, err := socksUDPHead(t)
	if err != nil {
		return
	}
	a.last.Store(time.Now().UnixNano())
	pkt := getBuf(len(head) + len(data))
	copy(pkt, head)
	copy(pkt[len(head):], data)
	_, _ = a.relay.WriteToUDP(pkt[:len(head)+len(data)], peer)
	putBuf(pkt)
}

type srvAssoc struct {
	l    *Lair
	conn *quic.Conn
	st   *quic.Stream
	id   uint16
	pc   *net.UDPConn
	wmu  sync.Mutex
	last atomic.Int64

	mu   sync.Mutex
	sent map[netip.Addr]struct{}
}

func (s *srvAssoc) note(ip netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sent) >= sentCap {
		for k := range s.sent {
			delete(s.sent, k)
			break
		}
	}
	s.sent[ip] = struct{}{}
}

func (s *srvAssoc) allowedFrom(ip netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.sent[ip]
	return ok
}

func (s *srvAssoc) deliver(t target, data []byte) {
	ip, ok := s.l.resolveUDP(t.host)
	if !ok {
		return
	}
	s.note(ip)
	s.last.Store(time.Now().UnixNano())
	_, _ = s.pc.WriteToUDPAddrPort(data, netip.AddrPortFrom(ip, t.port))
}

func (s *srvAssoc) pump() {
	buf := getBuf(udpBufSz)
	defer putBuf(buf)
	strikes := 0
	for {
		n, from, err := s.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if strikes++; strikes >= 50 {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		strikes = 0
		ip := from.Addr().Unmap()
		if !s.allowedFrom(ip) {
			continue
		}
		s.last.Store(time.Now().UnixNano())
		if err := sendRecord(s.st, &s.wmu, target{host: ip.String(), port: from.Port()}, buf[:n]); err != nil {
			if s.conn.Context().Err() != nil {
				return
			}
		}
	}
}

func (s *srvAssoc) run(ctx context.Context) {
	downDone := make(chan struct{})
	go func() {
		defer close(downDone)
		buf := getBuf(recordMax)
		defer putBuf(buf)
		for {
			t, data, err := readRecord(s.st, buf)
			if err != nil {
				return
			}
			s.deliver(t, data)
		}
	}()
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		s.pump()
	}()
	idle := time.NewTicker(5 * time.Second)
	defer idle.Stop()
loop:
	for {
		select {
		case <-downDone:
			break loop
		case <-pumpDone:
			break loop
		case <-ctx.Done():
			break loop
		case <-idle.C:
			if time.Since(time.Unix(0, s.last.Load())) > s.l.cfg.UDPIdleTimeout.D() {
				break loop
			}
		}
	}
	_ = s.pc.Close()
	qHalf{s.st}.abort()
	<-pumpDone
	<-downDone
}