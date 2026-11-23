package main

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const abortCode quic.StreamErrorCode = 0x101

type half interface {
	io.ReadWriter
	closeWrite() error
	abort()
}

type qHalf struct{ *quic.Stream }

func (q qHalf) closeWrite() error { return q.Stream.Close() }

func (q qHalf) abort() {
	q.Stream.CancelRead(abortCode)
	q.Stream.CancelWrite(abortCode)
}

type tHalf struct{ net.Conn }

func (t tHalf) closeWrite() error {
	if cw, ok := t.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return t.Conn.Close()
}

func (t tHalf) abort() { _ = t.Conn.Close() }

type plainW struct{ io.Writer }
type plainR struct{ io.Reader }

func relay(a, b half, wait time.Duration) {
	done := make(chan struct{}, 2)
	var once sync.Once
	kill := func() {
		once.Do(func() {
			a.abort()
			b.abort()
		})
	}
	pipe := func(dst, src half) {
		buf := getBuf(32 << 10)
		_, err := io.CopyBuffer(plainW{dst}, plainR{src}, buf)
		putBuf(buf)
		if err == nil {
			err = dst.closeWrite()
		}
		if err != nil {
			kill()
		}
		done <- struct{}{}
	}
	go pipe(a, b)
	go pipe(b, a)
	<-done
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
		kill()
		<-done
	}
	kill()
}
