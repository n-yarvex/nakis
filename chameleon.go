package main

import (
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"sync"
	"time"
)

const (
	personaFill   = 2 * time.Millisecond
	throttleFloor = 192 * 1024
	budgetFloor   = 256 * 1024
	calmAfter     = 10 * time.Minute
)

func logUniform(lo, hi float64) int {
	return int(math.Exp(math.Log(lo) + rand.Float64()*(math.Log(hi)-math.Log(lo))))
}

func personaPlan(up bool, heat, need int) []Range {
	count := 2 + rand.IntN(3) + heat
	lo, hi := 60.0, 1400.0
	if up {
		count++
		lo, hi = 40, 1200
	}
	count = min(count, ShapeSlots)
	widen := 1 + 0.25*float64(heat)
	plan := make([]Range, 0, count)
	for i := 0; i < count; i++ {
		l, h := lo/widen, hi*widen
		switch {
		case i == 0 && up:
			l, h = 110, 900*widen
		case i == 0:
			l, h = 100, 1500*widen
		case rand.IntN(5) == 0:
			l, h = 1400, 4000*widen
		}
		t := min(max(logUniform(l, h), 24), ShapeCap)
		if i == 0 && up {
			t = max(t, need)
		}
		plan = append(plan, Range{t, t})
	}
	return plan
}

type adapter struct {
	log    *slog.Logger
	window time.Duration

	mu        sync.Mutex
	heat      int
	budget    int64
	lastEvent time.Time
	failures  int
	best      float64
	bestAt    time.Time
}

func newAdapter(log *slog.Logger, window time.Duration) *adapter {
	if window <= 0 {
		window = time.Second
	}
	return &adapter{log: log, window: window}
}

func (a *adapter) level() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.heat
}

func (a *adapter) usesCap(configured int) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.heat >= 2:
		return 1
	case a.heat == 1 && (configured == 0 || configured > 2):
		return 2
	}
	return configured
}

func (a *adapter) spent(moved int64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.budget > 0 && moved >= a.budget
}

func (a *adapter) observe(peak float64) float64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	if peak >= a.best || time.Since(a.bestAt) > calmAfter {
		a.best, a.bestAt = peak, time.Now()
	}
	return a.best
}

func (a *adapter) throttled(onset int64, share int64, peak, now float64) {
	a.mu.Lock()
	a.heat = min(a.heat+1, 4)
	a.lastEvent = time.Now()
	want := max(onset*share/10, budgetFloor)
	if a.budget == 0 || want < a.budget {
		a.budget = want
	}
	heat, budget := a.heat, a.budget
	a.mu.Unlock()
	a.log.Warn(fmt.Sprintf("a download slowed from about %s to %s after roughly %s went through one tunnel; that looks like per-flow throttling. From now on I'll retire tunnels after %s and vary the first packets more (alert level %d)",
		rate(peak), rate(now), size(onset), size(budget), heat))
}

func (a *adapter) handshakeFailed(streak int) {
	a.mu.Lock()
	if streak < 5 || streak <= a.failures {
		a.mu.Unlock()
		return
	}
	a.failures = streak
	a.heat = max(a.heat, 1)
	a.lastEvent = time.Now()
	a.mu.Unlock()
	a.log.Warn(fmt.Sprintf("%d tunnel attempts in a row failed. That's either a flaky link or something cutting the connections; I'll keep backing off and mix up the first packets more", streak))
}

func (a *adapter) handshakeOK() {
	a.mu.Lock()
	a.failures = 0
	a.mu.Unlock()
}

func (a *adapter) cool() {
	a.mu.Lock()
	if a.heat == 0 || time.Since(a.lastEvent) < calmAfter {
		a.mu.Unlock()
		return
	}
	a.heat--
	a.lastEvent = time.Now()
	if a.heat == 0 {
		a.budget = 0
	} else if a.budget > 0 {
		a.budget = a.budget * 3 / 2
	}
	heat := a.heat
	a.mu.Unlock()
	a.log.Info(fmt.Sprintf("it's been quiet for a while, relaxing the alert level to %d", heat))
}

func rate(bps float64) string { return size(int64(bps)) + "/s" }

func size(n int64) string {
	switch {
	case n >= 10<<20:
		return fmt.Sprintf("%.0f MB", float64(n)/(1<<20))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%d KB", n>>10)
}

type rateWatch struct {
	a        *adapter
	moved    func() int64
	start    time.Time
	winStart time.Time
	winBytes int64
	rates    []float64
	peak     float64
	onset    int64
	fired    bool
	entered  int64
}

func newRateWatch(a *adapter, moved func() int64) *rateWatch {
	now := time.Now()
	return &rateWatch{a: a, moved: moved, start: now, winStart: now, entered: moved()}
}

func (r *rateWatch) add(n int) {
	r.winBytes += int64(n)
	now := time.Now()
	span := now.Sub(r.winStart)
	if span < r.a.window {
		return
	}
	got := float64(r.winBytes) / span.Seconds()
	r.winStart, r.winBytes = now, 0
	r.rates = append(r.rates, got)
	if got > r.peak {
		r.peak, r.onset = got, r.moved()
	}
	best := r.a.observe(r.peak)
	if r.fired || len(r.rates) < 2 || best < throttleFloor {
		return
	}
	last, prev := r.rates[len(r.rates)-1], r.rates[len(r.rates)-2]
	flat := math.Abs(last-prev) <= 0.35*math.Max(last, prev)
	switch {
	case len(r.rates) >= 4 && r.peak >= throttleFloor && last <= 0.3*r.peak && prev <= 0.3*r.peak && flat:
		r.fired = true
		r.a.throttled(r.onset, 7, r.peak, last)
	case r.entered >= budgetFloor && last <= 0.3*best && prev <= 0.3*best && flat:
		r.fired = true
		r.a.throttled(r.entered, 5, best, last)
	}
}
