package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const drainCap = 30 * time.Second

type Bond struct {
	conn *quic.Conn
	tr   *quic.Transport
	pc   net.PacketConn
	addr string
	born time.Time

	uses   atomic.Int64
	live   atomic.Int64
	retire atomic.Bool
	since  atomic.Int64
	pong   atomic.Int64
	rtt    atomic.Int64
	sick   time.Duration
	assocs sync.Map
	once   sync.Once
}

func (b *Bond) dead() bool { return b.conn.Context().Err() != nil }

func (b *Bond) close(code quic.ApplicationErrorCode) {
	b.once.Do(func() {
		_ = b.conn.CloseWithError(code, "")
		_ = b.tr.Close()
		_ = b.pc.Close()
	})
}

func (b *Bond) healthy() bool {
	if b.sick <= 0 {
		return true
	}
	now := time.Now()
	last := b.pong.Load()
	if last == 0 {
		return now.Sub(b.born) < 2*b.sick
	}
	return now.UnixNano()-last < int64(b.sick)
}

func (b *Bond) markRetired() {
	if b.retire.CompareAndSwap(false, true) {
		b.since.Store(time.Now().UnixNano())
	}
}

type Lane struct {
	st   *quic.Stream
	b    *Bond
	once sync.Once
}

func (l *Lane) release() {
	l.once.Do(func() { l.b.live.Add(-1) })
}

func (b *Bond) open() (*Lane, error) {
	st, err := b.conn.OpenStream()
	if err != nil {
		return nil, err
	}
	b.uses.Add(1)
	b.live.Add(1)
	return &Lane{st: st, b: b}, nil
}

func (b *Bond) openSync(ctx context.Context) (*Lane, error) {
	st, err := b.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	b.uses.Add(1)
	b.live.Add(1)
	return &Lane{st: st, b: b}, nil
}

type purrPool struct {
	maxSize int
	maxAge  time.Duration
	maxUses int64
	soft    int64

	mu     sync.Mutex
	bonds  []*Bond
	closed bool
}

func newPurrPool(maxSize int, maxAge time.Duration, maxUses int, soft int) *purrPool {
	return &purrPool{maxSize: maxSize, maxAge: maxAge, maxUses: int64(maxUses), soft: int64(soft)}
}

func (p *purrPool) usable(b *Bond) bool {
	return !b.retire.Load() && !b.dead() && b.healthy()
}

func (p *purrPool) take(skip map[*Bond]bool) *Bond {
	p.mu.Lock()
	defer p.mu.Unlock()
	var best *Bond
	for _, b := range p.bonds {
		if !p.usable(b) || skip[b] {
			continue
		}
		if b.live.Load() >= p.soft {
			continue
		}
		if best == nil || b.live.Load() < best.live.Load() || (b.live.Load() == best.live.Load() && b.rtt.Load() > 0 && b.rtt.Load() < best.rtt.Load()) {
			best = b
		}
	}
	return best
}

func (p *purrPool) takeAny() *Bond {
	p.mu.Lock()
	defer p.mu.Unlock()
	var best *Bond
	for _, b := range p.bonds {
		if b.retire.Load() || b.dead() {
			continue
		}
		if best == nil || b.live.Load() < best.live.Load() {
			best = b
		}
	}
	return best
}

func (p *purrPool) put(b *Bond) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.bonds) >= p.maxSize+p.retiring() {
		return false
	}
	p.bonds = append(p.bonds, b)
	return true
}

func (p *purrPool) retiring() int {
	n := 0
	for _, b := range p.bonds {
		if b.retire.Load() {
			n++
		}
	}
	return n
}

func (p *purrPool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, b := range p.bonds {
		if p.usable(b) {
			n++
		}
	}
	return n
}

func (p *purrPool) load() (live int64, bonds int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, b := range p.bonds {
		if p.usable(b) {
			live += b.live.Load()
			bonds++
		}
	}
	return
}

func (p *purrPool) sweep() {
	var gone []*Bond
	p.mu.Lock()
	now := time.Now()
	keep := p.bonds[:0]
	for _, b := range p.bonds {
		if b.dead() {
			gone = append(gone, b)
			continue
		}
		if !b.retire.Load() && ((p.maxAge > 0 && now.Sub(b.born) >= p.maxAge) || (p.maxUses > 0 && b.uses.Load() >= p.maxUses)) {
			b.markRetired()
		}
		if b.retire.Load() && (b.live.Load() == 0 || now.UnixNano()-b.since.Load() > int64(drainCap)) {
			gone = append(gone, b)
			continue
		}
		keep = append(keep, b)
	}
	clear(p.bonds[len(keep):])
	p.bonds = keep
	p.mu.Unlock()
	for _, b := range gone {
		b.close(byeCode)
	}
}

func (p *purrPool) closeAll() {
	p.mu.Lock()
	p.closed = true
	all := p.bonds
	p.bonds = nil
	p.mu.Unlock()
	for _, b := range all {
		b.close(byeCode)
	}
}

func (b *Bond) probe(every, dead time.Duration) {
	ctx, cancel := context.WithTimeout(b.conn.Context(), 5*time.Second)
	st, err := b.conn.OpenStreamSync(ctx)
	cancel()
	if err != nil {
		return
	}
	hello, _ := helloBytes(cmdWhisker, target{})
	if _, err := st.Write(hello); err != nil {
		return
	}
	_ = st.SetReadDeadline(time.Now().Add(dead))
	if _, err := readReply(st, false); err != nil {
		b.close(byeCode)
		return
	}
	b.pong.Store(time.Now().UnixNano())
	tick := time.NewTicker(every)
	defer tick.Stop()
	var ping, pong [8]byte
	for {
		select {
		case <-b.conn.Context().Done():
			return
		case <-tick.C:
		}
		now := time.Now()
		binary.BigEndian.PutUint64(ping[:], uint64(now.UnixNano()))
		_ = st.SetWriteDeadline(now.Add(dead))
		if _, err := st.Write(ping[:]); err != nil {
			b.close(byeCode)
			return
		}
		_ = st.SetReadDeadline(now.Add(dead))
		if _, err := io.ReadFull(st, pong[:]); err != nil {
			b.close(byeCode)
			return
		}
		rtt := time.Since(now)
		b.rtt.Store(int64(rtt))
		b.pong.Store(time.Now().UnixNano())
	}
}
