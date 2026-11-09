package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type tuning struct {
	poolHi int
	raceN  int
}

type Kitten struct {
	cfg    ClientConfig
	scout  *scout
	pool   *purrPool
	plan   []Range
	logger *slog.Logger

	hinted  atomic.Bool
	firstUp atomic.Bool
	sem     chan struct{}
	kick    chan struct{}

	tuneNow  atomic.Pointer[tuning]
	tuneFast tuning
	tuneMid  tuning
	tuneSlow tuning

	mu      sync.Mutex
	want    int
	flying  int
	used    int
	miss    int
	calm    int
	fails   int
	hold    time.Time
	hits    uint64
	misses  uint64
	tuneLap int

	ctx      context.Context
	cancel   context.CancelFunc
	loop     sync.WaitGroup
	sessions sync.WaitGroup
}

func NewKitten(cfg ClientConfig, logger *slog.Logger) (*Kitten, error) {
	id, err := ParseUUID(cfg.UUID)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	var tlsCfg *tls.Config
	if cfg.TLS {
		tlsCfg, err = TLSClientConfig(ClientOptions{
			ServerName: cfg.SNI,
			Pins:       cfg.TLSPins,
			ECHConfig:  cfg.ECHConfig,
		})
		if err != nil {
			return nil, err
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	k := &Kitten{
		cfg:      cfg,
		logger:   logger,
		sem:      make(chan struct{}, spawnCap),
		kick:     make(chan struct{}, 1),
		want:     cfg.PoolLo,
		ctx:      ctx,
		cancel:   cancel,
		tuneFast: tuning{poolHi: cfg.PoolHi + 64, raceN: 10},
		tuneMid:  tuning{poolHi: cfg.PoolHi, raceN: cfg.RaceCount},
		tuneSlow: tuning{poolHi: cfg.PoolLo + 8, raceN: 3},
	}
	mid := k.tuneMid
	k.tuneNow.Store(&mid)
	for _, r := range cfg.ShapeUp {
		k.plan = append(k.plan, Range{Min: r[0], Max: r[1]})
	}
	k.pool = newPurrPool(cfg.PoolHi, cfg.PoolMaxAge.D(), cfg.PoolMaxUses)

	s := &scout{
		id:        id,
		tlsCfg:    tlsCfg,
		handshake: cfg.HandshakeTimeout.D(),
		step:      raceStep,
		dns:       NewNames(dnsTTL, nil),
		spare:     k.stash,
		book:      map[string]*scoreCard{},
	}
	s.dialer = net.Dialer{
		Timeout:   cfg.DialTimeout.D(),
		KeepAlive: cfg.Keepalive.D(),
		Control: Congestion(cfg.Congestion, func(err error) {
			logger.Warn("couldn't switch the congestion control, carrying on with the system default", "wanted", cfg.Congestion, "err", err)
		}),
	}
	for _, item := range strings.Split(cfg.Server, ",") {
		host, port, err := net.SplitHostPort(strings.TrimSpace(item))
		if err != nil {
			cancel()
			return nil, err
		}
		s.servers = append(s.servers, hostPort{host, port})
	}
	k.scout = s

	logger.Info("client ready",
		"server", cfg.Server,
		"tls", cfg.TLS,
		"ech", cfg.ECHConfig != "",
		"shape_up", cfg.ShapeUp,
		"send_pack", cfg.SendPack,
		"send_tail", cfg.SendTail,
		"send_quiet", cfg.SendQuiet,
	)
	return k, nil
}

func (k *Kitten) hintOnce(err error) {
	if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		return
	}
	if k.hinted.CompareAndSwap(false, true) {
		k.logger.Warn("the server hung up on a tunnel without answering. Usually that means a wrong uuid, or clocks more than 30s apart", "err", err)
		time.AfterFunc(30*time.Second, func() { k.hinted.Store(false) })
	}
}

func (k *Kitten) stash(mc *Tunnel) {
	k.pool.put(mc, 0)
}

func (k *Kitten) poke() {
	select {
	case k.kick <- struct{}{}:
	default:
	}
}

func approach(cur, target int) int {
	step := (target - cur) / 3
	if step == 0 {
		switch {
		case target > cur:
			step = 1
		case target < cur:
			step = -1
		}
	}
	return cur + step
}

func (k *Kitten) pickTuning(fails, total int, hitRate float64, rtt int64) tuning {
	switch {
	case fails >= 3:
		return k.tuneFast
	case total < 8:
		return k.tuneMid
	case hitRate < 0.5:
		return k.tuneFast
	case fails == 0 && hitRate > 0.9 && rtt > 0 && rtt < int64(300*time.Millisecond):
		return k.tuneSlow
	default:
		return k.tuneMid
	}
}

func (k *Kitten) retune() {
	k.mu.Lock()
	k.tuneLap++
	if k.tuneLap < 3 {
		k.mu.Unlock()
		return
	}
	k.tuneLap = 0
	fails := k.fails
	hits, misses := k.hits, k.misses
	k.mu.Unlock()

	total := int(hits + misses)
	rate := -1.0
	if total >= 8 {
		rate = float64(hits) / float64(total)
	}
	cur := k.tuneNow.Load()
	goal := k.pickTuning(fails, total, rate, k.scout.avgRTT())
	next := tuning{
		poolHi: approach(cur.poolHi, goal.poolHi),
		raceN:  approach(cur.raceN, goal.raceN),
	}
	next.poolHi = min(max(next.poolHi, k.cfg.PoolLo+4), max(k.cfg.PoolHi, 128))
	next.raceN = min(max(next.raceN, 2), 12)
	k.tuneNow.Store(&next)
}

func (k *Kitten) spawn() {
	select {
	case k.sem <- struct{}{}:
	case <-k.ctx.Done():
		k.mu.Lock()
		k.flying--
		k.mu.Unlock()
		return
	}
	defer func() { <-k.sem }()

	pause := time.NewTimer(time.Duration(rand.Int63n(int64(120 * time.Millisecond))))
	select {
	case <-pause.C:
	case <-k.ctx.Done():
		pause.Stop()
	}
	mc, err := k.scout.dialOne(k.ctx)

	k.mu.Lock()
	k.flying--
	was := k.fails
	if err != nil {
		k.fails++
		k.hold = time.Now().Add(500 * time.Millisecond << uint(min(k.fails, 6)))
	} else {
		k.fails = 0
	}
	fails := k.fails
	k.mu.Unlock()
	if err == nil {
		if was >= 3 {
			k.logger.Info("tunnels to the server are working again")
		} else if k.firstUp.CompareAndSwap(false, true) {
			k.logger.Info("first tunnel to the server is up")
		}
	}

	if err == nil {
		k.stash(mc)
		return
	}
	if k.ctx.Err() == nil && (fails == 1 || fails%10 == 0) {
		k.logger.Warn(fmt.Sprintf("couldn't open a tunnel to the server (%d failed in a row), will keep retrying with a growing pause", fails), "err", err)
	}
}

func (k *Kitten) topUp() {
	if k.cfg.noWarm {
		return
	}
	idle := k.pool.size()
	k.mu.Lock()
	if time.Now().Before(k.hold) {
		k.mu.Unlock()
		return
	}
	n := min(k.want-idle-k.flying, spawnCap-k.flying)
	if n <= 0 {
		k.mu.Unlock()
		return
	}
	k.flying += n
	k.mu.Unlock()
	for i := 0; i < n; i++ {
		go k.spawn()
	}
}

func (k *Kitten) tick() {
	k.mu.Lock()
	need := k.used + 1
	k.used = 0
	prev := k.want
	switch {
	case k.miss > 0:
		k.want += max(k.miss*4, 4)
		k.calm = 0
	case need > k.want:
		k.want = need + need/2
		k.calm = 0
	default:
		k.calm++
		if k.calm >= 10 && k.want > k.cfg.PoolLo && k.want > need*2 {
			k.want = max(k.want-k.want/8, k.cfg.PoolLo)
			k.calm = 0
		}
	}
	k.want = min(max(k.want, k.cfg.PoolLo), k.tuneNow.Load().poolHi)
	k.miss = 0
	now := k.want
	k.mu.Unlock()

	if now != prev {
		k.logger.Debug("pool want adjusted", "want", now, "prev", prev)
	}
	k.pool.sweep()
	k.retune()
}

func (k *Kitten) run() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	last := time.Now()
	for {
		select {
		case <-k.ctx.Done():
			return
		case <-k.kick:
		case <-ticker.C:
		}
		if time.Since(last) >= time.Second {
			k.tick()
			last = time.Now()
		}
		k.topUp()
	}
}

func (k *Kitten) Start() {
	k.loop.Add(1)
	go func() {
		defer k.loop.Done()
		k.run()
	}()
	k.poke()
}

func (k *Kitten) Shutdown(timeout time.Duration) {
	k.cancel()
	done := make(chan struct{})
	go func() {
		k.loop.Wait()
		k.sessions.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		k.logger.Warn("some sessions were still running when the shutdown wait ran out; closing them", "waited", timeout)
	}
	k.pool.closeAll()
}

func (k *Kitten) lease(ctx context.Context) (*purrConn, error) {
	if mc, uses, ok := k.pool.take(); ok {
		k.mu.Lock()
		k.hits++
		k.mu.Unlock()
		return k.fresh(&purrConn{mc: mc, home: k.pool, uses: uses + 1}), nil
	}
	k.mu.Lock()
	k.miss++
	k.misses++
	k.mu.Unlock()
	mc, err := k.scout.race(ctx, k.tuneNow.Load().raceN)
	if err != nil {
		return nil, err
	}
	return k.fresh(&purrConn{mc: mc, home: k.pool, uses: 1}), nil
}

func (k *Kitten) drainWindow() time.Duration {
	d := clientDrain
	if rtt := time.Duration(k.scout.avgRTT()) * 2; rtt > d {
		d = min(rtt, maxDrain)
	}
	return d
}

func (k *Kitten) fresh(pc *purrConn) *purrConn {
	if !pc.mc.life.drawn() {
		pc.mc.life = newLife(k.cfg.PoolMaxUses)
	}
	return pc
}

func (k *Kitten) dialTCP(ctx context.Context, host string, port uint16) (*purrConn, error) {
	hello, err := HelloBytes(host, port)
	if err != nil {
		return nil, err
	}
	pc, err := k.lease(ctx)
	if err != nil {
		return nil, err
	}
	pc.first = hello
	pc.inner = tlsLike(strconv.Itoa(int(port)))
	if !pc.mc.sealed {
		pc.first = append(MakeProof(k.scout.id, pc.mc.bind), hello...)
		pc.mc.sealed = true
	}
	return pc, nil
}

func (k *Kitten) flight(first int, inner bool) (plan []Range, pad bool, fill time.Duration) {
	if len(k.plan) == 0 {
		return personaPlan(true, inner, first), true, personaFill
	}
	plan = append([]Range(nil), k.plan...)
	plan[0].Min = max(plan[0].Min, first)
	plan[0].Max = max(plan[0].Max, plan[0].Min)
	return plan, false, k.cfg.ShapeWait.D()
}

func (k *Kitten) ServeSOCKS5(ctx context.Context, listenAddr string) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		return err
	}
	k.logger.Info("SOCKS5 proxy is listening", "addr", ln.Addr().String())

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetKeepAlive(true)
		}
		k.sessions.Add(1)
		go func() {
			defer k.sessions.Done()
			k.handleSocks(ctx, conn)
		}()
	}
}

func (k *Kitten) handleSocks(ctx context.Context, app net.Conn) {
	defer app.Close()
	defer func() {
		if r := recover(); r != nil {
			k.logger.Error("recovered from a crash while serving a SOCKS5 connection", "err", r)
		}
	}()

	_ = app.SetDeadline(time.Now().Add(k.cfg.HandshakeTimeout.D()))
	host, port, err := SocksGreet(app)
	_ = app.SetDeadline(time.Time{})
	if err != nil {
		k.logger.Debug("socks5 handshake failed", "remote", app.RemoteAddr().String(), "err", err)
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	k.logger.Debug("nakis tcp", "remote", app.RemoteAddr().String(), "target", target)

	k.mu.Lock()
	k.used++
	k.mu.Unlock()

	pc, err := k.dialTCP(ctx, host, port)
	if err != nil {
		k.logger.Warn("couldn't reach "+target+" through the tunnel", "err", err)
		return
	}
	k.shuttle(app, pc, target)
	pc.release()
}

type purrPool struct {
	maxSize int
	maxAge  time.Duration
	maxUses int

	mu     sync.Mutex
	idle   []purrItem
	closed bool
}

type purrItem struct {
	mc      *Tunnel
	watch   *idleWatch
	expires time.Time
	uses    int
}

func newPurrPool(maxSize int, maxAge time.Duration, maxUses int) *purrPool {
	return &purrPool{maxSize: maxSize, maxAge: maxAge, maxUses: maxUses}
}

func (p *purrPool) take() (*Tunnel, int, bool) {
	var stale []*Tunnel
	defer func() {
		for _, mc := range stale {
			_ = mc.Close()
		}
	}()
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for len(p.idle) > 0 {
		it := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		if now.Before(it.expires) && it.watch.Stop() {
			return it.mc, it.uses, true
		}
		stale = append(stale, it.mc)
	}
	return nil, 0, false
}

func (p *purrPool) put(mc *Tunnel, uses int) {
	if p.maxUses > 0 && uses >= p.maxUses {
		_ = mc.Close()
		return
	}
	p.mu.Lock()
	if p.closed || len(p.idle) >= p.maxSize {
		p.mu.Unlock()
		_ = mc.Close()
		return
	}
	p.idle = append(p.idle, purrItem{mc: mc, watch: mc.Watch(), expires: time.Now().Add(p.maxAge), uses: uses})
	p.mu.Unlock()
}

func (p *purrPool) sweep() {
	var stale []*Tunnel
	p.mu.Lock()
	now := time.Now()
	keep := p.idle[:0]
	for _, it := range p.idle {
		if now.Before(it.expires) && !it.watch.Dead() {
			keep = append(keep, it)
		} else {
			stale = append(stale, it.mc)
		}
	}
	clear(p.idle[len(keep):])
	p.idle = keep
	p.mu.Unlock()
	for _, mc := range stale {
		_ = mc.Close()
	}
}

func (p *purrPool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.idle)
}

func (p *purrPool) closeAll() {
	p.mu.Lock()
	p.closed = true
	all := p.idle
	p.idle = nil
	p.mu.Unlock()
	for _, it := range all {
		_ = it.mc.Close()
	}
}

type purrConn struct {
	mc      *Tunnel
	home    *purrPool
	uses    int
	first   []byte
	inner   bool
	napSent atomic.Bool
	napSeen atomic.Bool
	broken  atomic.Bool
}

func (p *purrConn) release() {
	if p.broken.Load() || !p.napSent.Load() || !p.napSeen.Load() || p.mc.Dirty() || p.mc.life.spent(p.uses, p.mc.Moved()) {
		_ = p.mc.Close()
		return
	}
	_ = p.mc.SetDeadline(time.Time{})
	p.home.put(p.mc, p.uses)
}

const (
	spawnCap    = 16
	raceStep    = 50 * time.Millisecond
	dnsTTL      = 30 * time.Second
	clientDrain = 500 * time.Millisecond
	maxDrain    = 5 * time.Second
)

const (
	scoreCap = 4096
)

var errSkipped = errors.New("dial skipped")

type hostPort struct{ host, port string }

type scoreCard struct {
	lat       int64
	fails     int
	coolUntil time.Time
}

type scout struct {
	servers   []hostPort
	dialer    net.Dialer
	id        []byte
	tlsCfg    *tls.Config
	handshake time.Duration
	step      time.Duration
	dns       *NameCache
	spare     func(*Tunnel)

	bookMu sync.Mutex
	book   map[string]*scoreCard
	rtt    int64
}

func (s *scout) avgRTT() int64 {
	s.bookMu.Lock()
	defer s.bookMu.Unlock()
	return s.rtt
}

func (s *scout) grade(addr string, d time.Duration, ok bool) {
	s.bookMu.Lock()
	defer s.bookMu.Unlock()
	card := s.book[addr]
	if card == nil {
		if len(s.book) >= scoreCap {
			for k := range s.book {
				delete(s.book, k)
				break
			}
		}
		card = &scoreCard{}
		s.book[addr] = card
	}
	if !ok {
		card.fails = min(card.fails+1, 10)
		card.coolUntil = time.Now().Add(min(time.Duration(card.fails)*2*time.Second, time.Minute))
		card.lat = min(card.lat*2+int64(time.Second), int64(30*time.Second))
		return
	}
	card.fails = 0
	card.coolUntil = time.Time{}
	if card.lat == 0 || card.lat >= int64(time.Second) {
		card.lat = int64(d)
	} else {
		card.lat += (int64(d) - card.lat) / 4
	}
	if d > 0 {
		if s.rtt == 0 {
			s.rtt = int64(d)
		} else {
			s.rtt += (int64(d) - s.rtt) / 8
		}
	}
}

func (s *scout) cost(addr string, now time.Time) int64 {
	card := s.book[addr]
	if card == nil {
		return int64(100 * time.Millisecond)
	}
	if now.Before(card.coolUntil) {
		return card.lat + int64(2*time.Second)
	}
	if card.lat > 0 {
		return card.lat
	}
	return int64(100 * time.Millisecond)
}

func (s *scout) candidates(ctx context.Context) ([]string, error) {
	var addrs []string
	var lastErr error
	for _, sv := range s.servers {
		ips, err := s.dns.Resolve(ctx, sv.host)
		if err != nil {
			lastErr = err
			continue
		}
		for _, ip := range Interleave(ips) {
			addrs = append(addrs, net.JoinHostPort(ip, sv.port))
		}
	}
	if len(addrs) == 0 {
		if lastErr == nil {
			lastErr = errors.New("no address")
		}
		return nil, lastErr
	}
	rand.Shuffle(len(addrs), func(i, j int) { addrs[i], addrs[j] = addrs[j], addrs[i] })
	now := time.Now()
	costs := make(map[string]int64, len(addrs))
	s.bookMu.Lock()
	for _, a := range addrs {
		costs[a] = s.cost(a, now)
	}
	s.bookMu.Unlock()
	sort.SliceStable(addrs, func(i, j int) bool { return costs[addrs[i]] < costs[addrs[j]] })
	return addrs, nil
}

func (s *scout) secure(ctx context.Context, raw net.Conn) (*Tunnel, error) {
	if s.tlsCfg == nil {
		return WrapTunnel(raw, nil), nil
	}
	b := NewBatcher(raw)
	tc := tls.Client(b, s.tlsCfg)
	hctx, cancel := context.WithTimeout(ctx, s.handshake)
	err := tc.HandshakeContext(hctx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	state := tc.ConnectionState()
	bind, err := state.ExportKeyingMaterial("nakis/bind", nil, 32)
	if err != nil {
		return nil, err
	}
	mc := WrapTunnel(tc, b)
	mc.bind = bind
	return mc, nil
}

func (s *scout) dialTo(ctx context.Context, addr string) (*Tunnel, error) {
	start := time.Now()
	raw, err := s.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctx.Err() == nil {
			s.grade(addr, 0, false)
		}
		return nil, err
	}
	mc, err := s.secure(ctx, raw)
	if err != nil {
		_ = raw.Close()
		if ctx.Err() == nil {
			s.grade(addr, 0, false)
		}
		return nil, err
	}
	s.grade(addr, time.Since(start), true)
	return mc, nil
}

func (s *scout) dialOne(ctx context.Context) (*Tunnel, error) {
	addrs, err := s.candidates(ctx)
	if err != nil {
		return nil, err
	}
	lastErr := errors.New("all dials failed")
	for _, a := range addrs {
		mc, err := s.dialTo(ctx, a)
		if err == nil {
			return mc, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

type raceResult struct {
	mc  *Tunnel
	err error
}

func (s *scout) race(ctx context.Context, width int) (*Tunnel, error) {
	addrs, err := s.candidates(ctx)
	if err != nil {
		return nil, err
	}
	if len(addrs) > width {
		addrs = addrs[:width]
	}

	raceCtx, cancel := context.WithCancel(ctx)
	results := make(chan raceResult, len(addrs))
	for i, addr := range addrs {
		go func(i int, addr string) {
			res := raceResult{err: errSkipped}
			defer func() {
				if r := recover(); r != nil {
					res = raceResult{err: fmt.Errorf("dial panic: %v", r)}
				}
				results <- res
			}()
			if i >= 2 {
				t := time.NewTimer(time.Duration(i-1) * s.step)
				defer t.Stop()
				select {
				case <-t.C:
				case <-raceCtx.Done():
					return
				}
			}
			mc, err := s.dialTo(raceCtx, addr)
			res = raceResult{mc: mc, err: err}
		}(i, addr)
	}

	var lastErr error
	for i := range addrs {
		r := <-results
		if r.err == nil {
			go s.adoptLosers(results, len(addrs)-i-1, cancel)
			return r.mc, nil
		}
		if !errors.Is(r.err, errSkipped) {
			lastErr = r.err
		}
	}
	cancel()
	if lastErr == nil {
		lastErr = errors.New("all dials skipped")
	}
	return nil, lastErr
}

func (s *scout) adoptLosers(results <-chan raceResult, left int, cancel context.CancelFunc) {
	for ; left > 0; left-- {
		r := <-results
		if r.err != nil || r.mc == nil {
			continue
		}
		if s.spare != nil {
			s.spare(r.mc)
		} else {
			_ = r.mc.Close()
		}
	}
	cancel()
}

type shuttleRun struct {
	cli    *Kitten
	app    net.Conn
	pc     *purrConn
	target string
	gate   *Gate

	downDone atomic.Bool
	appDead  atomic.Bool
	wg       sync.WaitGroup
}

func (k *Kitten) shuttle(app net.Conn, pc *purrConn, target string) {
	s := &shuttleRun{cli: k, app: app, pc: pc, target: target}
	plan, pad, fill := k.flight(len(pc.first), pc.inner)
	s.gate = NewGate(GateOptions{
		Pack:  k.cfg.SendPack,
		Tail:  k.cfg.SendTail,
		Quiet: k.cfg.SendQuiet,
		Head:  Headroom,
		Plan:  plan,
		Pad:   pad,
		Fill:  fill,
	}, s.send)

	s.wg.Add(2)
	go s.downstream()
	go s.upstream()
	s.wg.Wait()

	s.gate.Close()
	if !pc.napSent.Load() && !pc.broken.Load() {
		pc.napSent.Store(true)
		if err := pc.mc.Nap(); err != nil {
			pc.broken.Store(true)
		}
	}
}

func (s *shuttleRun) send(wire []byte, pad int) error {
	err := s.pc.mc.SendWirePad(wire, pad)
	if err != nil {
		s.pc.broken.Store(true)
	}
	return err
}

func (s *shuttleRun) kickApp() {
	_ = s.app.SetReadDeadline(time.Now())
}

func (s *shuttleRun) deliver(p []byte) {
	if s.appDead.Load() {
		return
	}
	if _, err := s.app.Write(p); err != nil {
		s.appDead.Store(true)
		s.kickApp()
		return
	}
}

func (s *shuttleRun) downstream() {
	defer s.wg.Done()
	defer func() {
		s.downDone.Store(true)
		s.kickApp()
	}()
	mc := s.pc.mc

	if err := mc.ReadReply(); err != nil {
		s.pc.broken.Store(true)
		var mew *MewError
		if errors.As(err, &mew) {
			s.cli.logger.Warn("the server wouldn't connect to "+s.target, "err", err)
		} else {
			s.cli.logger.Debug("tunnel reply failed", "target", s.target, "err", err)
			s.cli.hintOnce(err)
		}
		return
	}
	if rest := mc.TakePending(); rest != nil {
		s.deliver(rest)
		PutBuf(rest)
	}
	for {
		p, err := mc.ReadFrame()
		if err != nil {
			if errors.Is(err, ErrNap) {
				s.pc.napSeen.Store(true)
			} else {
				s.pc.broken.Store(true)
			}
			return
		}
		s.deliver(p)
		PutBuf(p)
	}
}

func (s *shuttleRun) upstream() {
	defer s.wg.Done()
	buf := GetBuf(PackCap)
	defer PutBuf(buf)

	s.gate.Feed(s.pc.first)
	for {
		n, err := s.app.Read(buf)
		if n > 0 {
			s.gate.Feed(buf[:n])
		}
		if err != nil {
			break
		}
	}
	if s.downDone.Load() || s.pc.broken.Load() {
		return
	}
	s.gate.Flush()
	if s.pc.broken.Load() {
		return
	}
	s.pc.napSent.Store(true)
	if err := s.pc.mc.Nap(); err != nil {
		s.pc.broken.Store(true)
		return
	}
	_ = s.pc.mc.SetReadDeadline(time.Now().Add(s.cli.drainWindow()))
}

var (
	replyOK     = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	replyNoCmd  = []byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0}
	replyNoAddr = []byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0}
	errProto    = errors.New("socks5: protocol error")
)

func SocksGreet(c net.Conn) (string, uint16, error) {
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return "", 0, err
	}
	if head[0] != 5 {
		return "", 0, errProto
	}
	if _, err := io.CopyN(io.Discard, c, int64(head[1])); err != nil {
		return "", 0, err
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return "", 0, err
	}

	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return "", 0, err
	}
	if req[0] != 5 {
		return "", 0, errProto
	}

	var host string
	switch req[3] {
	case 1:
		var ip [4]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(ip[:]).String()
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return "", 0, err
		}
		if n[0] == 0 {
			return "", 0, errProto
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return "", 0, err
		}
		host = string(name)
	case 4:
		var ip [16]byte
		if _, err := io.ReadFull(c, ip[:]); err != nil {
			return "", 0, err
		}
		host = net.IP(ip[:]).String()
	default:
		_, _ = c.Write(replyNoAddr)
		return "", 0, fmt.Errorf("socks5: address type %d unsupported", req[3])
	}

	var pb [2]byte
	if _, err := io.ReadFull(c, pb[:]); err != nil {
		return "", 0, err
	}
	if req[1] != 1 {
		_, _ = c.Write(replyNoCmd)
		return "", 0, fmt.Errorf("socks5: command %d unsupported", req[1])
	}
	if _, err := c.Write(replyOK); err != nil {
		return "", 0, err
	}
	return host, uint16(pb[0])<<8 | uint16(pb[1]), nil
}
