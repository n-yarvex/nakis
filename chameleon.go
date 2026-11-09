package main

import (
	"math"
	"math/rand/v2"
	"time"
)

const personaFill = 2 * time.Millisecond

const (
	lifeBytesLo = 8 << 20
	lifeBytesHi = 256 << 20
)

func logUniform(lo, hi float64) int {
	return int(math.Exp(math.Log(lo) + rand.Float64()*(math.Log(hi)-math.Log(lo))))
}

var tlsPorts = map[string]bool{
	"443": true, "465": true, "563": true, "636": true, "853": true,
	"993": true, "995": true, "5223": true, "8443": true,
}

func tlsLike(port string) bool { return tlsPorts[port] }

func personaPlan(up, inner bool, need int) []Range {
	count := 2 + rand.IntN(3)
	lo, hi := 60.0, 1400.0
	if up {
		count++
		lo, hi = 40, 1200
	}
	bulky := 5
	if inner {
		count += 2
		bulky = 3
	}
	count = min(count, ShapeSlots)
	plan := make([]Range, 0, count)
	for i := 0; i < count; i++ {
		l, h := lo, hi
		switch {
		case i == 0 && up:
			l, h = 110, 900
		case i == 0:
			l, h = 100, 1500
		case rand.IntN(bulky) == 0:
			l, h = 1400, 4000
		}
		t := min(max(logUniform(l, h), 24), ShapeCap)
		if i == 0 && up {
			t = max(t, need)
		}
		plan = append(plan, Range{t, t})
	}
	return plan
}

type lifespan struct {
	uses  int
	bytes int64
}

func newLife(maxUses int) lifespan {
	l := lifespan{bytes: int64(logUniform(lifeBytesLo, lifeBytesHi))}
	if maxUses > 0 {
		lowest := (maxUses + 1) / 2
		l.uses = lowest + rand.IntN(maxUses-lowest+1)
	}
	return l
}

func (l lifespan) drawn() bool { return l.bytes > 0 }

func (l lifespan) spent(uses int, moved int64) bool {
	return (l.uses > 0 && uses >= l.uses) || (l.bytes > 0 && moved >= l.bytes)
}
