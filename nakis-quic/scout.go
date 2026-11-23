package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	scoreCap = 4096
	dnsTTL   = 30 * time.Second
)

var errSkipped = errors.New("dial skipped")

type hostPort struct{ host, port string }

type scoreCard struct {
	lat       int64
	fails     int
	coolUntil time.Time
}

type scout struct {
	servers   []hostPort
	id        []byte
	tlsCfg    *tls.Config
	qcfg      *quic.Config
	handshake time.Duration
	step      time.Duration
	dns       *NameCache
	spare     func(*Bond)
	probe     time.Duration

	bookMu sync.Mutex
	book   map[string]*scoreCard
	rtt    int64
}

func (s *scout) avgRTT() int64 {
	s.bookMu.Lock()
	defer s.bookMu.Unlock()
	return s.rtt
}

func (s *scout) grade(addr string, d time.Duration, ok bool) {
	s.bookMu.Lock()
	defer s.bookMu.Unlock()
	card := s.book[addr]
	if card == nil {
		if len(s.book) >= scoreCap {
			for k := range s.book {
				delete(s.book, k)
				break
			}
		}
		card = &scoreCard{}
		s.book[addr] = card
	}
	if !ok {
		card.fails = min(card.fails+1, 10)
		card.coolUntil = time.Now().Add(min(time.Duration(card.fails)*2*time.Second, time.Minute))
		card.lat = min(card.lat*2+int64(time.Second), int64(30*time.Second))
		return
	}
	card.fails = 0
	card.coolUntil = time.Time{}
	if card.lat == 0 || card.lat >= int64(time.Second) {
		card.lat = int64(d)
	} else {
		card.lat += (int64(d) - card.lat) / 4
	}
	if d > 0 {
		if s.rtt == 0 {
			s.rtt = int64(d)
		} else {
			s.rtt += (int64(d) - s.rtt) / 8
		}
	}
}

func (s *scout) cost(addr string, now time.Time) int64 {
	card := s.book[addr]
	if card == nil {
		return int64(100 * time.Millisecond)
	}
	if now.Before(card.coolUntil) {
		return card.lat + int64(2*time.Second)
	}
	if card.lat > 0 {
		return card.lat
	}
	return int64(100 * time.Millisecond)
}

func (s *scout) candidates(ctx context.Context) ([]string, error) {
	var addrs []string
	var lastErr error
	for _, sv := range s.servers {
		ips, err := s.dns.Resolve(ctx, sv.host)
		if err != nil {
			lastErr = err
			continue
		}
		for _, ip := range Interleave(ips) {
			addrs = append(addrs, net.JoinHostPort(ip, sv.port))
		}
	}
	if len(addrs) == 0 {
		if lastErr == nil {
			lastErr = errors.New("no usable address")
		}
		return nil, lastErr
	}
	now := time.Now()
	costs := make(map[string]int64, len(addrs))
	s.bookMu.Lock()
	for _, a := range addrs {
		costs[a] = s.cost(a, now)
	}
	s.bookMu.Unlock()
	sort.SliceStable(addrs, func(i, j int) bool { return costs[addrs[i]] < costs[addrs[j]] })
	return addrs, nil
}

func (s *scout) socket(ctx context.Context, remote *net.UDPAddr) (net.PacketConn, error) {
	network := "udp4"
	if remote.IP.To4() == nil {
		network = "udp6"
	}
	return net.ListenUDP(network, &net.UDPAddr{})
}

func (s *scout) dialTo(ctx context.Context, addr string) (*Bond, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	pc, err := s.socket(ctx, ua)
	if err != nil {
		if ctx.Err() == nil {
			s.grade(addr, 0, false)
		}
		return nil, err
	}
	tr := &quic.Transport{Conn: pc}
	hctx, cancel := context.WithTimeout(ctx, s.handshake)
	conn, err := tr.Dial(hctx, ua, s.tlsCfg, s.qcfg)
	cancel()
	if err == nil {
		err = s.prove(conn)
	}
	if err != nil {
		if conn != nil {
			_ = conn.CloseWithError(0, "")
		}
		_ = tr.Close()
		_ = pc.Close()
		if ctx.Err() == nil {
			s.grade(addr, 0, false)
		}
		return nil, err
	}
	s.grade(addr, time.Since(start), true)
	b := &Bond{conn: conn, tr: tr, pc: pc, addr: addr, born: time.Now()}
	if s.probe > 0 {
		b.sick = max(3*s.probe, 4*time.Second)
	}
	go func() {
		<-conn.Context().Done()
		b.close(0)
	}()
	go b.datagrams()
	if s.probe > 0 {
		go b.probe(s.probe, max(7*s.probe, 12*time.Second))
	}
	return b, nil
}

func (s *scout) prove(conn *quic.Conn) error {
	state := conn.ConnectionState().TLS
	bind, err := state.ExportKeyingMaterial(bindLabel, nil, 32)
	if err != nil {
		return err
	}
	us, err := conn.OpenUniStream()
	if err != nil {
		return err
	}
	if _, err := us.Write(MakeProof(s.id, bind)); err != nil {
		return err
	}
	return us.Close()
}

func (s *scout) dialOne(ctx context.Context) (*Bond, error) {
	addrs, err := s.candidates(ctx)
	if err != nil {
		return nil, err
	}
	lastErr := errors.New("all dials failed")
	for _, a := range addrs {
		b, err := s.dialTo(ctx, a)
		if err == nil {
			return b, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

type raceResult struct {
	b   *Bond
	err error
}

func (s *scout) pace() time.Duration {
	if s.step > 0 {
		return s.step
	}
	return min(max(time.Duration(s.avgRTT())/2, 50*time.Millisecond), 250*time.Millisecond)
}

func (s *scout) race(ctx context.Context, width int) (*Bond, error) {
	addrs, err := s.candidates(ctx)
	if err != nil {
		return nil, err
	}
	if len(addrs) > width {
		addrs = addrs[:width]
	}
	if hedge := min(width, 3); len(addrs) < hedge {
		for i := 0; len(addrs) < hedge; i++ {
			addrs = append(addrs, addrs[i%len(addrs)])
		}
	}
	step := s.pace()
	rctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	unlink := context.AfterFunc(ctx, cancel)
	begin := time.Now()
	results := make(chan raceResult, len(addrs))
	started, pending := 0, 0
	launch := func() {
		addr := addrs[started]
		started++
		pending++
		go func() {
			res := raceResult{err: errSkipped}
			defer func() {
				if r := recover(); r != nil {
					res = raceResult{err: fmt.Errorf("dial panic: %v", r)}
				}
				results <- res
			}()
			b, err := s.dialTo(rctx, addr)
			res = raceResult{b: b, err: err}
		}()
	}
	finish := func() {
		unlink()
		grace := min(max(3*time.Since(begin), 300*time.Millisecond), 3*time.Second)
		time.AfterFunc(grace, cancel)
		left := pending
		go func() {
			for ; left > 0; left-- {
				if r := <-results; r.b != nil {
					if s.spare != nil {
						s.spare(r.b)
					} else {
						r.b.close(byeCode)
					}
				}
			}
			cancel()
		}()
	}

	launch()
	if len(addrs) > 1 {
		launch()
	}
	timer := time.NewTimer(step)
	defer timer.Stop()
	var lastErr error
	for {
		select {
		case r := <-results:
			pending--
			if r.err == nil {
				finish()
				return r.b, nil
			}
			if !errors.Is(r.err, errSkipped) {
				lastErr = r.err
			}
			if started < len(addrs) {
				launch()
			} else if pending == 0 {
				unlink()
				cancel()
				if lastErr == nil {
					lastErr = errors.New("all dials skipped")
				}
				return nil, lastErr
			}
		case <-timer.C:
			if started < len(addrs) {
				launch()
				timer.Reset(step)
			}
		case <-ctx.Done():
			finish()
			cancel()
			return nil, ctx.Err()
		}
	}
}
