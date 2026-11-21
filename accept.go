package main

import (
	"context"
	"errors"
	"net"
	"time"
)

type acceptPause struct {
	d time.Duration
}

func (p *acceptPause) reset() { p.d = 0 }

func (p *acceptPause) wait(ctx context.Context, err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	if p.d == 0 {
		p.d = 5 * time.Millisecond
	} else {
		p.d = min(p.d*2, time.Second)
	}
	t := time.NewTimer(p.d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
