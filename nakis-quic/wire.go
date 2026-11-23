package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
	"sync"

	"github.com/quic-go/quic-go"
)

const (
	helloVersion byte = 1
	cmdHug       byte = 1
	cmdPounce    byte = 2
	cmdWhisker   byte = 3

	respCozy byte = 0
	respOops byte = 2

	quietCode quic.ApplicationErrorCode = 0x100
	byeCode   quic.ApplicationErrorCode = 0x101

	bufMax = 1 << 16
)

const (
	oopsOther byte = iota
	oopsRefused
	oopsUnreachable
	oopsTimeout
	oopsName
	oopsDenied
	oopsBusy
)

var (
	errMangled = errors.New("nakis-quic: malformed frame")
	errProto   = errors.New("nakis-quic: protocol error")
)

var tiers [17]sync.Pool

func init() {
	for i := range tiers {
		size := 1 << i
		tiers[i].New = func() any { return make([]byte, size) }
	}
}

func getBuf(n int) []byte {
	if n <= 0 {
		return nil
	}
	if n > bufMax {
		return make([]byte, n)
	}
	return tiers[bits.Len(uint(n-1))].Get().([]byte)[:n]
}

func putBuf(b []byte) {
	c := cap(b)
	if c == 0 || c > bufMax || c&(c-1) != 0 {
		return
	}
	tiers[bits.Len(uint(c))-1].Put(b[:c])
}

type PeerError struct {
	Code byte
	Msg  string
}

func (e *PeerError) Error() string {
	return fmt.Sprintf("the server said no (code %d): %s", e.Code, e.Msg)
}

type target struct {
	host string
	port uint16
}

func (t target) String() string {
	return fmt.Sprintf("%s:%d", t.host, t.port)
}

func (t target) appendTo(b []byte) ([]byte, error) {
	if ip, err := netip.ParseAddr(t.host); err == nil {
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
		if len(t.host) == 0 || len(t.host) > 255 {
			return nil, errMangled
		}
		b = append(b, 3, byte(len(t.host)))
		b = append(b, t.host...)
	}
	return binary.BigEndian.AppendUint16(b, t.port), nil
}

func readTarget(r io.Reader) (target, error) {
	var t target
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return t, err
	}
	switch atyp[0] {
	case 1, 4:
		raw := make([]byte, 4)
		if atyp[0] == 4 {
			raw = make([]byte, 16)
		}
		if _, err := io.ReadFull(r, raw); err != nil {
			return t, err
		}
		ip, _ := netip.AddrFromSlice(raw)
		t.host = ip.String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return t, err
		}
		if n[0] == 0 {
			return t, errMangled
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return t, err
		}
		t.host = string(name)
	default:
		return t, errMangled
	}
	var pb [2]byte
	if _, err := io.ReadFull(r, pb[:]); err != nil {
		return t, err
	}
	t.port = binary.BigEndian.Uint16(pb[:])
	return t, nil
}

func splitTarget(p []byte) (target, []byte, bool) {
	var t target
	if len(p) < 1 {
		return t, nil, false
	}
	var n int
	switch p[0] {
	case 1:
		n = 1 + 4
	case 4:
		n = 1 + 16
	case 3:
		if len(p) < 2 || p[1] == 0 {
			return t, nil, false
		}
		n = 2 + int(p[1])
	default:
		return t, nil, false
	}
	if len(p) < n+2 {
		return t, nil, false
	}
	switch p[0] {
	case 1, 4:
		ip, _ := netip.AddrFromSlice(p[1:n])
		t.host = ip.String()
	default:
		t.host = string(p[2:n])
	}
	t.port = binary.BigEndian.Uint16(p[n : n+2])
	return t, p[n+2:], true
}

func helloBytes(cmd byte, t target) ([]byte, error) {
	b := []byte{helloVersion, cmd}
	if cmd != cmdHug {
		return b, nil
	}
	return t.appendTo(b)
}

func readHello(r io.Reader) (byte, target, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, target{}, err
	}
	if h[0] != helloVersion {
		return 0, target{}, errProto
	}
	switch h[1] {
	case cmdHug:
		t, err := readTarget(r)
		return h[1], t, err
	case cmdPounce, cmdWhisker:
		return h[1], target{}, nil
	}
	return 0, target{}, errProto
}

func oopsBytes(code byte, msg string) []byte {
	if len(msg) > 200 {
		msg = msg[:200]
	}
	b := []byte{respOops, code, byte(len(msg))}
	return append(b, msg...)
}

func cozyBytes(id uint16, withID bool) []byte {
	if !withID {
		return []byte{respCozy}
	}
	return []byte{respCozy, byte(id >> 8), byte(id)}
}

func readReply(r io.Reader, withID bool) (uint16, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	switch b[0] {
	case respCozy:
		if !withID {
			return 0, nil
		}
		var id [2]byte
		if _, err := io.ReadFull(r, id[:]); err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint16(id[:]), nil
	case respOops:
		var h [2]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return 0, err
		}
		msg := make([]byte, h[1])
		if _, err := io.ReadFull(r, msg); err != nil {
			return 0, err
		}
		return 0, &PeerError{Code: h[0], Msg: string(msg)}
	}
	return 0, errProto
}

func appendDatagram(b []byte, id uint16, t target, data []byte) ([]byte, error) {
	b = binary.BigEndian.AppendUint16(b, id)
	b, err := t.appendTo(b)
	if err != nil {
		return nil, err
	}
	return append(b, data...), nil
}

func parseDatagram(p []byte) (uint16, target, []byte, bool) {
	if len(p) < 2 {
		return 0, target{}, nil, false
	}
	t, rest, ok := splitTarget(p[2:])
	return binary.BigEndian.Uint16(p), t, rest, ok
}

func appendRecord(b []byte, t target, data []byte) ([]byte, error) {
	at := len(b)
	b = append(b, 0, 0)
	b, err := t.appendTo(b)
	if err != nil {
		return nil, err
	}
	b = append(b, data...)
	n := len(b) - at - 2
	if n > 0xFFFF {
		return nil, errMangled
	}
	binary.BigEndian.PutUint16(b[at:], uint16(n))
	return b, nil
}

func readRecord(r io.Reader, buf []byte) (target, []byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return target{}, nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n > len(buf) {
		return target{}, nil, errMangled
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return target{}, nil, err
	}
	t, rest, ok := splitTarget(buf[:n])
	if !ok {
		return t, nil, errMangled
	}
	return t, rest, nil
}
