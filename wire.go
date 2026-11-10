package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const BufMax = 1 << 16

var tiers [17]sync.Pool

func init() {
	for i := range tiers {
		size := 1 << i
		tiers[i].New = func() any { return make([]byte, size) }
	}
}

func GetBuf(n int) []byte {
	if n <= 0 {
		return nil
	}
	if n > BufMax {
		return make([]byte, n)
	}
	return tiers[bits.Len(uint(n-1))].Get().([]byte)[:n]
}

func PutBuf(b []byte) {
	c := cap(b)
	if c == 0 || c > BufMax || c&(c-1) != 0 {
		return
	}
	tiers[bits.Len(uint(c))-1].Put(b[:c])
}

const (
	Headroom = 2
	FrameMax = 0xFFFE
	padMark  = 0xFFFF
	letter   = 0x41

	HelloVersion byte = 1

	CmdHug byte = 1

	RespCozy byte = 0
	RespOops byte = 2
)

var (
	ErrNap      = errors.New("nakis: nap")
	ErrOversize = errors.New("nakis: frame too large")
	CozyByte    = []byte{RespCozy}
)

type MewError struct {
	Code byte
	Msg  string
}

func (e *MewError) Error() string {
	return fmt.Sprintf("nakis peer code %d: %s", e.Code, e.Msg)
}

func HelloBytes(host string, port uint16) ([]byte, error) {
	if len(host) == 0 || len(host) > 255 {
		return nil, errors.New("nakis: bad host length")
	}
	cmd := CmdHug
	buf := make([]byte, 0, 5+len(host)+2)
	buf = append(buf, HelloVersion, cmd, 0, byte(len(host)))
	buf = append(buf, host...)
	return binary.BigEndian.AppendUint16(buf, port), nil
}

func OopsBytes(code byte, msg string) []byte {
	if len(msg) > 250 {
		msg = msg[:250]
	}
	buf := make([]byte, 0, 3+len(msg))
	buf = append(buf, RespOops, code, byte(len(msg)))
	return append(buf, msg...)
}

type Batcher struct {
	net.Conn
	mu  sync.Mutex
	on  bool
	buf []byte
}

func NewBatcher(c net.Conn) *Batcher {
	return &Batcher{Conn: c}
}

func (b *Batcher) begin(hint int) {
	b.mu.Lock()
	b.on = true
	if b.buf == nil {
		b.buf = GetBuf(hint)[:0]
	}
	b.mu.Unlock()
}

func (b *Batcher) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.on {
		return b.Conn.Write(p)
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *Batcher) flush() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.on = false
	if len(b.buf) == 0 {
		return nil
	}
	_, err := b.Conn.Write(b.buf)
	PutBuf(b.buf)
	b.buf = nil
	return err
}

func recordHint(n int) int {
	return n + (n/16000+1)*24
}

type Tunnel struct {
	net.Conn
	rd    io.Reader
	batch *Batcher

	rMu  sync.Mutex
	held []byte
	rest []byte

	wMu sync.Mutex

	moved  atomic.Int64
	bind   []byte
	sealed bool
	life   lifespan
}

func WrapTunnel(c net.Conn, b *Batcher) *Tunnel {
	m := &Tunnel{Conn: c, batch: b, rd: c}
	if b == nil {
		m.rd = bufio.NewReaderSize(c, 16<<10)
	}
	return m
}

func (c *Tunnel) pull() ([]byte, error) {
	for {
		var h [2]byte
		if _, err := io.ReadFull(c.rd, h[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(h[:]))
		switch n {
		case 0:
			return nil, ErrNap
		case padMark:
			if _, err := io.ReadFull(c.rd, h[:]); err != nil {
				return nil, err
			}
			skip := int64(binary.BigEndian.Uint16(h[:]))
			if _, err := io.CopyN(io.Discard, c.rd, skip); err != nil {
				return nil, err
			}
			c.moved.Add(4 + skip)
			continue
		}
		p := GetBuf(n)
		if _, err := io.ReadFull(c.rd, p); err != nil {
			PutBuf(p)
			return nil, err
		}
		c.moved.Add(int64(2 + n))
		return p, nil
	}
}

func (c *Tunnel) Moved() int64 { return c.moved.Load() }

var longAgo = time.Unix(1, 0)

func (c *Tunnel) Dirty() bool {
	c.rMu.Lock()
	defer c.rMu.Unlock()
	if len(c.rest) > 0 || len(c.held) > 0 {
		return true
	}
	br, buffered := c.rd.(*bufio.Reader)
	if buffered && br.Buffered() > 0 {
		return true
	}
	_ = c.Conn.SetReadDeadline(longAgo)
	var err error
	if buffered {
		_, err = br.Peek(1)
	} else {
		var one [1]byte
		_, err = c.rd.Read(one[:])
	}
	_ = c.Conn.SetReadDeadline(time.Time{})
	var ne net.Error
	return !(errors.As(err, &ne) && ne.Timeout())
}

func (c *Tunnel) ReadFirst(idle, rest time.Duration) (frame, prefix []byte, err error) {
	var h [2]byte
	_ = c.Conn.SetReadDeadline(time.Now().Add(idle))
	if _, err = io.ReadFull(c.rd, h[:]); err != nil {
		return nil, nil, err
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if h[0] >= letter || n == 0 {
		return nil, h[:], nil
	}
	_ = c.Conn.SetReadDeadline(time.Now().Add(rest))
	frame = GetBuf(n)
	got, err := io.ReadFull(c.rd, frame)
	if err != nil {
		prefix = append(h[:], frame[:got]...)
		PutBuf(frame)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, prefix, nil
		}
		return nil, nil, err
	}
	c.moved.Add(int64(2 + n))
	_ = c.Conn.SetReadDeadline(time.Time{})
	return frame, nil, nil
}

func (c *Tunnel) Unread(held []byte, off int) {
	c.rMu.Lock()
	defer c.rMu.Unlock()
	c.held, c.rest = held, held[off:]
}

func (c *Tunnel) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.rMu.Lock()
	defer c.rMu.Unlock()
	if len(c.rest) == 0 {
		p, err := c.pull()
		if err != nil {
			return 0, err
		}
		c.held, c.rest = p, p
	}
	n := copy(b, c.rest)
	c.rest = c.rest[n:]
	if len(c.rest) == 0 {
		PutBuf(c.held)
		c.held, c.rest = nil, nil
	}
	return n, nil
}

func (c *Tunnel) ReadFrame() ([]byte, error) {
	c.rMu.Lock()
	defer c.rMu.Unlock()
	if len(c.rest) > 0 {
		return c.takeRest(), nil
	}
	return c.pull()
}

func (c *Tunnel) TakePending() []byte {
	c.rMu.Lock()
	defer c.rMu.Unlock()
	if len(c.rest) == 0 {
		return nil
	}
	return c.takeRest()
}

func (c *Tunnel) takeRest() []byte {
	out := GetBuf(len(c.rest))
	copy(out, c.rest)
	PutBuf(c.held)
	c.held, c.rest = nil, nil
	return out
}

func (c *Tunnel) ReadByte() (byte, error) {
	var b [1]byte
	_, err := io.ReadFull(c, b[:])
	return b[0], err
}

const recordPlain = 16384

func (c *Tunnel) put(p []byte) error {
	c.moved.Add(int64(len(p)))
	if c.batch == nil || len(p) <= recordPlain {
		_, err := c.Conn.Write(p)
		return err
	}
	c.batch.begin(recordHint(len(p)))
	_, err := c.Conn.Write(p)
	if ferr := c.batch.flush(); err == nil {
		err = ferr
	}
	return err
}

func (c *Tunnel) SendWire(wire []byte) error {
	n := len(wire) - Headroom
	if n <= 0 {
		return nil
	}
	if n > FrameMax {
		return ErrOversize
	}
	binary.BigEndian.PutUint16(wire, uint16(n))
	c.wMu.Lock()
	defer c.wMu.Unlock()
	return c.put(wire)
}

func (c *Tunnel) SendWirePad(wire []byte, pad int) error {
	n := len(wire) - Headroom
	if pad < 4 || n <= 0 || n > FrameMax || len(wire)+pad > BufMax {
		return c.SendWire(wire)
	}
	out := GetBuf(len(wire) + pad)
	defer PutBuf(out)
	copy(out, wire)
	binary.BigEndian.PutUint16(out, uint16(n))
	tail := out[len(wire):]
	binary.BigEndian.PutUint16(tail, padMark)
	binary.BigEndian.PutUint16(tail[2:], uint16(pad-4))
	_, _ = rand.Read(tail[4:])
	c.wMu.Lock()
	defer c.wMu.Unlock()
	return c.put(out)
}

func (c *Tunnel) Send(head, body []byte) error {
	total := len(head) + len(body)
	for off := 0; off < total; {
		n := min(total-off, FrameMax)
		wire := GetBuf(Headroom + n)
		fill := copyRange(wire[Headroom:], head, body, off)
		if fill != n {
			PutBuf(wire)
			return io.ErrShortWrite
		}
		err := c.SendWire(wire)
		PutBuf(wire)
		if err != nil {
			return err
		}
		off += n
	}
	return nil
}

func copyRange(dst, head, body []byte, off int) int {
	n := 0
	if off < len(head) {
		n = copy(dst, head[off:])
		off = len(head)
	}
	return n + copy(dst[n:], body[off-len(head):])
}

func (c *Tunnel) Write(b []byte) (int, error) {
	if err := c.Send(nil, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *Tunnel) Nap() error {
	c.wMu.Lock()
	defer c.wMu.Unlock()
	var zero [2]byte
	return c.put(zero[:])
}

func (c *Tunnel) ReadReply() error {
	code, err := c.ReadByte()
	if err != nil {
		return err
	}
	switch code {
	case RespCozy:
		return nil
	case RespOops:
	default:
		return fmt.Errorf("nakis: unknown response code 0x%x", code)
	}
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return err
	}
	msg := make([]byte, h[1])
	if _, err := io.ReadFull(c, msg); err != nil {
		return err
	}
	return &MewError{Code: h[0], Msg: string(msg)}
}

func (c *Tunnel) rawConn() net.Conn {
	if c.batch != nil {
		return c.batch.Conn
	}
	return c.Conn
}

type idleWatch struct {
	c    net.Conn
	done chan struct{}
	dead atomic.Bool
}

func (c *Tunnel) Watch() *idleWatch {
	w := &idleWatch{c: c.rawConn(), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		var one [1]byte
		if _, err := w.c.Read(one[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
			w.dead.Store(true)
		}
	}()
	return w
}

func (w *idleWatch) Dead() bool { return w.dead.Load() }

func (w *idleWatch) Stop() bool {
	_ = w.c.SetReadDeadline(time.Unix(1, 0))
	<-w.done
	_ = w.c.SetReadDeadline(time.Time{})
	return !w.dead.Load()
}

var setCongestion func(fd uintptr, name string) error

func Congestion(name string, warn func(error)) func(network, address string, c syscall.RawConn) error {
	if name == "" {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		err := errors.New("congestion control selection needs linux")
		if setCongestion != nil {
			var serr error
			if cerr := c.Control(func(fd uintptr) { serr = setCongestion(fd, name) }); cerr != nil {
				serr = cerr
			}
			err = serr
		}
		if err != nil && warn != nil {
			warn(err)
		}
		return nil
	}
}
