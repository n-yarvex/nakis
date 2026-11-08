package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	ProofSize   = 8 + nonceLen + sha256.Size
	nonceLen    = 16
	ProofWindow = 30 * time.Second
	keepSeen    = 2*ProofWindow + 5*time.Second
	seenLimit   = 1 << 18
	proofLabel  = "nakis/auth/v1"
)

var (
	ErrBadMac = errors.New("kitsune: bad proof")
	ErrReplay = errors.New("kitsune: proof already used")
	ErrFull   = errors.New("kitsune: replay cache full")
)

type StaleError struct{ Skew time.Duration }

func (e *StaleError) Error() string {
	return fmt.Sprintf("kitsune: timestamp is %v off the server clock", e.Skew.Round(time.Millisecond))
}

func ParseUUID(s string) ([]byte, error) {
	raw := strings.ReplaceAll(s, "-", "")
	if len(raw) != 32 {
		return nil, errors.New("uuid wants 32 hex chars")
	}
	return hex.DecodeString(raw)
}

func proof(id, stamp, nonce, binding []byte) []byte {
	h := hmac.New(sha256.New, id)
	h.Write([]byte(proofLabel))
	h.Write(stamp)
	h.Write(nonce)
	h.Write(binding)
	return h.Sum(nil)
}

func MakeProof(id, binding []byte) []byte {
	buf := make([]byte, ProofSize)
	binary.BigEndian.PutUint64(buf[:8], uint64(time.Now().UnixNano()))
	_, _ = rand.Read(buf[8 : 8+nonceLen])
	copy(buf[8+nonceLen:], proof(id, buf[:8], buf[8:8+nonceLen], binding))
	return buf
}

type Guard struct {
	id    []byte
	start time.Time

	mu    sync.Mutex
	seen  map[[nonceLen]byte]time.Time
	sweep time.Time
}

func NewGuard(id []byte) *Guard {
	return &Guard{id: id, start: time.Now(), seen: map[[nonceLen]byte]time.Time{}}
}

func (g *Guard) Accept(msg, binding []byte) error {
	if len(msg) != ProofSize {
		return ErrBadMac
	}
	stamp, nonce := msg[:8], msg[8:8+nonceLen]
	if !hmac.Equal(msg[8+nonceLen:], proof(g.id, stamp, nonce, binding)) {
		return ErrBadMac
	}
	at := time.Unix(0, int64(binary.BigEndian.Uint64(stamp)))
	now := time.Now()
	if skew := now.Sub(at); skew > ProofWindow || skew < -ProofWindow {
		return &StaleError{Skew: skew}
	}
	if at.Before(g.start.Add(-time.Second)) {
		return ErrReplay
	}

	var key [nonceLen]byte
	copy(key[:], nonce)
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.After(g.sweep) {
		for k, t := range g.seen {
			if now.Sub(t) > keepSeen {
				delete(g.seen, k)
			}
		}
		g.sweep = now.Add(10 * time.Second)
	}
	if _, dup := g.seen[key]; dup {
		return ErrReplay
	}
	if len(g.seen) >= seenLimit {
		return ErrFull
	}
	g.seen[key] = now
	return nil
}
