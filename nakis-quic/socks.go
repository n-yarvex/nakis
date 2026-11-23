package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

type socksReq struct {
	cmd  byte
	host string
	port uint16
}

var (
	replyOK     = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	replyFail   = []byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}
	replyNoCmd  = []byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0}
	replyNoAddr = []byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0}
)

func socksRequest(c net.Conn) (socksReq, error) {
	var r socksReq
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return r, err
	}
	if head[0] != 5 {
		return r, errProto
	}
	if _, err := io.CopyN(io.Discard, c, int64(head[1])); err != nil {
		return r, err
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return r, err
	}
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return r, err
	}
	if req[0] != 5 {
		return r, errProto
	}
	switch req[3] {
	case 1, 3, 4:
	default:
		_, _ = c.Write(replyNoAddr)
		return r, fmt.Errorf("socks5: address type %d is not supported", req[3])
	}
	t, err := readTarget(io.MultiReader(io.LimitReader(byteReader(req[3]), 1), c))
	if err != nil {
		return r, err
	}
	if req[1] != 1 && req[1] != 3 {
		_, _ = c.Write(replyNoCmd)
		return r, fmt.Errorf("socks5: command %d is not supported", req[1])
	}
	return socksReq{cmd: req[1], host: t.host, port: t.port}, nil
}

type byteReader byte

func (b byteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = byte(b)
	return 1, nil
}

func socksBound(ip net.IP, port int) []byte {
	var b []byte
	if v4 := ip.To4(); v4 != nil {
		b = append([]byte{5, 0, 0, 1}, v4...)
	} else {
		b = append([]byte{5, 0, 0, 4}, ip.To16()...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port))
}

func socksUDPHead(t target) ([]byte, error) {
	return t.appendTo([]byte{0, 0, 0})
}

func parseSocksUDP(p []byte) (target, []byte, bool) {
	if len(p) < 5 || p[2] != 0 {
		return target{}, nil, false
	}
	return splitTarget(p[3:])
}
