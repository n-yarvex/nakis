package main

import (
	"context"
	"errors"
	"net"
	"time"
)

type acceptPause struct{ d time.Duration }

func (a *acceptPause) reset() { a.d = 0 }

func (a *acceptPause) wait(ctx context.Context, err error) bool {
	if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
		return false
	}
	if a.d == 0 {
		a.d = 5 * time.Millisecond
	} else {
		a.d = min(a.d*2, time.Second)
	}
	t := time.NewTimer(a.d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
