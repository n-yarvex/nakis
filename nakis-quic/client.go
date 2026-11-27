package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	spawnCap  = 6
	abortWait = 4 * time.Second
	failFast  = 400 * time.Millisecond
)

type tuning struct {
	poolHi int
	raceN  int
}

type attempt struct {
	done chan struct{}
	err  error
}

type Kitten struct {
	cfg    ClientConfig
	scout  *scout
	pool   *purrPool
	logger *slog.Logger

	hinted  atomic.Bool
	firstUp atomic.Bool
	sem     chan struct{}
	kick    chan struct{}

	tuneNow  atomic.Pointer[tuning]
	tuneFast tuning
	tuneMid  tuning
	tuneSlow tuning

	mu       sync.Mutex
	want     int
	flying   int
	peak     int64
	miss     int
	calm     int
	fails    int
	hold     time.Time
	hits     uint64
	misses   uint64
	tuneLap  int
	building *attempt
	lastFail time.Time
	lastErr  error

	ctx      context.Context
	cancel   context.CancelFunc
	loop     sync.WaitGroup
	sessions sync.WaitGroup

	smu     sync.Mutex
	active  map[*sessionRef]struct{}
	closing bool
}

type sessionRef struct {
	mu      sync.Mutex
	app     net.Conn
	cancel  context.CancelFunc
	lane    *Lane
	aborted bool
}

func (s *sessionRef) bind(l *Lane) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.aborted {
		return false
	}
	s.lane = l
	return true
}

func (s *sessionRef) abort() {
	s.mu.Lock()
	s.aborted = true
	l, cancel := s.lane, s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	_ = s.app.Close()
	if l != nil {
		qHalf{l.st}.abort()
	}
}

func (k *Kitten) beginSession(app net.Conn) (*sessionRef, bool) {
	k.smu.Lock()
	defer k.smu.Unlock()
	if k.closing {
		return nil, false
	}
	ref := &sessionRef{app: app}
	k.active[ref] = struct{}{}
	k.sessions.Add(1)
	return ref, true
}

func (k *Kitten) endSession(ref *sessionRef) {
	k.smu.Lock()
	delete(k.active, ref)
	k.smu.Unlock()
	k.sessions.Done()
}

func (k *Kitten) abortSessions() {
	k.smu.Lock()
	refs := make([]*sessionRef, 0, len(k.active))
	for r := range k.active {
		refs = append(refs, r)
	}
	k.smu.Unlock()
	for _, r := range refs {
		r.abort()
	}
}

func quicConfig(idle, keepalive, handshake time.Duration, datagrams bool, maxStreams int,
	initStream, maxStream, initConn, maxConn uint64) *quic.Config {
	uni := int64(16)
	if maxStreams < 0 {
		uni = -1
	}
	if initStream == 0 {
		initStream = 16 << 20
	}
	if maxStream == 0 {
		maxStream = 256 << 20
	}
	if initConn == 0 {
		initConn = 32 << 20
	}
	if maxConn == 0 {
		maxConn = 1024 << 20
	}
	return &quic.Config{
		HandshakeIdleTimeout:           handshake,
		MaxIdleTimeout:                 idle,
		KeepAlivePeriod:                keepalive,
		EnableDatagrams:                datagrams,
		MaxIncomingStreams:             int64(maxStreams),
		MaxIncomingUniStreams:          uni,
		InitialStreamReceiveWindow:     initStream,
		MaxStreamReceiveWindow:         maxStream,
		InitialConnectionReceiveWindow: initConn,
		MaxConnectionReceiveWindow:     maxConn,
		DisablePathMTUDiscovery:        false,
	}
}

func NewKitten(cfg ClientConfig, logger *slog.Logger) (*Kitten, error) {
	id, err := ParseUUID(cfg.UUID)
	if err != nil {
		return nil, problem("C02", "uuid: "+err.Error(), "")
	}
	tlsCfg, err := clientTLS(cfg.SNI, cfg.TLSPins, cfg.ECHConfig, cfg.ALPN)
	if err != nil {
		return nil, problem("C03", err.Error(), "")
	}
	var lookup LookupFunc
	if p := NewDNSPool(cfg.DNS); p != nil {
		lookup = p.LookupIPAddr
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
		active:   map[*sessionRef]struct{}{},
		tuneFast: tuning{poolHi: cfg.PoolHi, raceN: min(cfg.RaceCount*2, 12)},
		tuneMid:  tuning{poolHi: cfg.PoolHi, raceN: cfg.RaceCount},
		tuneSlow: tuning{poolHi: min(cfg.PoolLo+6, cfg.PoolHi), raceN: 3},
	}
	mid := k.tuneMid
	k.tuneNow.Store(&mid)
	k.pool = newPurrPool(cfg.PoolHi, cfg.PoolMaxAge.D(), cfg.PoolMaxUses, cfg.Streams)
	s := &scout{
		id:     id,
		tlsCfg: tlsCfg,
		qcfg: quicConfig(
			cfg.IdleTimeout.D(),
			cfg.Keepalive.D(),
			cfg.HandshakeTimeout.D(),
			cfg.UDP,
			-1,
			cfg.InitialStreamWindow,
			cfg.MaxStreamWindow,
			cfg.InitialConnectionWindow,
			cfg.MaxConnectionWindow,
		),
		handshake: cfg.HandshakeTimeout.D(),
		probe:     cfg.ProbeInterval.D(),
		step:      cfg.RaceStagger.D(),
		dns:       NewNames(dnsTTL, lookup),
		spare:     k.adopt,
		book:      map[string]*scoreCard{},
	}
	for _, item := range strings.Split(cfg.Server, ",") {
		host, port, err := net.SplitHostPort(item)
		if err != nil {
			cancel()
			return nil, problem("C01", err.Error(), "")
		}
		s.servers = append(s.servers, hostPort{host, port})
	}
	k.scout = s
	logger.Info("nakis-quic client is ready",
		"server", cfg.Server,
		"pool", fmt.Sprintf("%d-%d", cfg.PoolLo, cfg.PoolHi),
		"ech", cfg.ECHConfig != "",
	)
	return k, nil
}

func (k *Kitten) hintOnce(err error) {
	var ae *quic.ApplicationError
	if !errors.As(err, &ae) || ae.ErrorCode != quietCode {
		return
	}
	if k.hinted.CompareAndSwap(false, true) {
		k.logger.Warn("the server closed the connection right after the handshake. That is how it says no: check the uuid, and that both clocks are within 30s of each other", "code", "NQ-R02")
		time.AfterFunc(30*time.Second, func() { k.hinted.Store(false) })
	}
}

func (k *Kitten) poke() {
	select {
	case k.kick <- struct{}{}:
	default:
	}
}

func (k *Kitten) adopt(b *Bond) {
	if !k.pool.put(b) {
		b.close(byeCode)
		return
	}
	go func() {
		<-b.conn.Context().Done()
		k.poke()
	}()
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
	next.poolHi = min(max(next.poolHi, min(k.cfg.PoolLo+2, k.cfg.PoolHi)), k.cfg.PoolHi)
	next.raceN = min(max(next.raceN, 2), 16)
	k.tuneNow.Store(&next)
}

func (k *Kitten) noteFail(err error) {
	k.mu.Lock()
	k.fails++
	fails := k.fails
	k.hold = time.Now().Add(500 * time.Millisecond << uint(min(fails, 6)))
	k.lastFail, k.lastErr = time.Now(), err
	k.mu.Unlock()
	if k.ctx.Err() == nil && (fails == 1 || fails%10 == 0) {
		k.hintOnce(err)
		k.logger.Warn(fmt.Sprintf("couldn't reach the server (%d failed in a row), will keep trying with a growing pause", fails), "code", "NQ-R01", "err", err)
	}
}

func (k *Kitten) noteUp() {
	k.mu.Lock()
	was := k.fails
	k.fails = 0
	k.lastErr = nil
	k.mu.Unlock()
	if was >= 3 {
		k.logger.Info("the server is reachable again, nya~")
	} else if k.firstUp.CompareAndSwap(false, true) {
		k.logger.Info("first connection to the server is up")
	}
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
	ctx, cancel := context.WithTimeout(k.ctx, k.cfg.DialTimeout.D()+k.cfg.HandshakeTimeout.D())
	b, err := k.scout.dialOne(ctx)
	cancel()

	k.mu.Lock()
	k.flying--
	k.mu.Unlock()
	if err != nil {
		k.noteFail(err)
		return
	}
	k.noteUp()
	k.adopt(b)
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
	n := min(min(k.want, k.pool.maxSize)-idle-k.flying, spawnCap-k.flying)
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
	live, _ := k.pool.load()
	k.mu.Lock()
	k.peak = max(k.peak, live)
	need := int(k.peak/int64(k.cfg.Streams)) + 1
	k.peak = 0
	prev := k.want
	switch {
	case k.miss > 0:
		k.want++
		k.calm = 0
	case need > k.want:
		k.want = need
		k.calm = 0
	default:
		k.calm++
		if k.calm >= 10 && k.want > k.cfg.PoolLo && k.want > need {
			k.want--
			k.calm = 0
		}
	}
	k.want = min(max(k.want, k.cfg.PoolLo), min(k.tuneNow.Load().poolHi, k.pool.maxSize))
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
	k.smu.Lock()
	k.closing = true
	k.smu.Unlock()
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
		k.logger.Warn("some sessions were still running when the wait ran out; closing them", "waited", timeout)
		k.abortSessions()
		select {
		case <-done:
		case <-time.After(abortWait):
			k.logger.Error("some sessions did not stop even after being closed; giving up on them")
		}
	}
	k.pool.closeAll()
}

func (k *Kitten) ensure(ctx context.Context) error {
	k.mu.Lock()
	if k.lastErr != nil && time.Since(k.lastFail) < failFast {
		err := k.lastErr
		k.mu.Unlock()
		return err
	}
	at := k.building
	if at == nil {
		at = &attempt{done: make(chan struct{})}
		k.building = at
		k.miss++
		k.misses++
		width := min(k.tuneNow.Load().raceN+k.fails/2, 16)
		go k.runBuild(at, width)
	}
	k.mu.Unlock()
	select {
	case <-at.done:
		return at.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (k *Kitten) runBuild(at *attempt, width int) {
	ctx, cancel := context.WithTimeout(k.ctx, k.cfg.DialTimeout.D()+k.cfg.HandshakeTimeout.D())
	defer cancel()
	b, err := k.scout.race(ctx, width)
	if err != nil {
		k.noteFail(err)
	} else {
		k.noteUp()
		k.adopt(b)
	}
	k.mu.Lock()
	k.building = nil
	k.mu.Unlock()
	at.err = err
	close(at.done)
	k.poke()
}

func (k *Kitten) lane(ctx context.Context) (*Lane, error) {
	skip := map[*Bond]bool{}
	var lastErr error
	for round := 0; round < 8; round++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		b := k.pool.take(skip)
		if b != nil {
			l, err := b.open()
			if err != nil {
				skip[b] = true
				lastErr = err
				continue
			}
			k.mu.Lock()
			k.hits++
			k.mu.Unlock()
			k.notePeak()
			return l, nil
		}
		if k.pool.size() >= k.pool.maxSize {
			if b = k.pool.takeAny(); b != nil {
				l, err := b.openSync(ctx)
				if err == nil {
					k.notePeak()
					return l, nil
				}
				lastErr = err
				skip[b] = true
			}
			continue
		}
		if err := k.ensure(ctx); err != nil {
			return nil, err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no connection had room for another stream")
	}
	return nil, lastErr
}

func (k *Kitten) notePeak() {
	live, _ := k.pool.load()
	k.mu.Lock()
	k.peak = max(k.peak, live)
	k.mu.Unlock()
}

func (k *Kitten) handleSocks(parent context.Context, app net.Conn, ref *sessionRef) {
	defer app.Close()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	ref.mu.Lock()
	ref.cancel = cancel
	aborted := ref.aborted
	ref.mu.Unlock()
	if aborted {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			k.logger.Error("recovered from a crash while serving a SOCKS5 connection", "err", r)
		}
	}()

	_ = app.SetDeadline(time.Now().Add(k.cfg.HandshakeTimeout.D()))
	req, err := socksRequest(app)
	if err == nil && req.cmd == 1 {
		_, err = app.Write(replyOK)
	}
	_ = app.SetDeadline(time.Time{})
	if err != nil {
		k.logger.Debug("socks5 handshake failed", "remote", app.RemoteAddr().String(), "err", err)
		return
	}
	if req.cmd == 3 {
		k.handleUDP(ctx, app, ref, req)
		return
	}
	t := target{host: req.host, port: req.port}
	k.logger.Debug("tcp", "remote", app.RemoteAddr().String(), "target", t.String())
	lane, err := k.lane(ctx)
	if err != nil {
		if ctx.Err() == nil {
			k.logger.Warn("couldn't open a stream for "+t.String(), "err", err)
		}
		return
	}
	defer lane.release()
	if !ref.bind(lane) {
		qHalf{lane.st}.abort()
		return
	}
	hello, err := helloBytes(cmdHug, t)
	if err == nil {
		_, err = lane.st.Write(hello)
	}
	if err != nil {
		qHalf{lane.st}.abort()
		return
	}
	cs := &clientStream{qHalf: qHalf{lane.st}}
	relay(tHalf{app}, cs, k.cfg.HalfCloseTimeout.D())
	var pe *PeerError
	if errors.As(cs.err, &pe) {
		k.logger.Warn("the server couldn't connect to "+t.String(), "reason", pe.Msg, "code", "NQ-R03")
	}
}

type clientStream struct {
	qHalf
	once sync.Once
	err  error
}

func (c *clientStream) Read(p []byte) (int, error) {
	c.once.Do(func() { _, c.err = readReply(c.Stream, false) })
	if c.err != nil {
		return 0, c.err
	}
	return c.Stream.Read(p)
}

func (k *Kitten) Listen(ctx context.Context, listenAddr string) (net.Listener, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", listenAddr)
	if err != nil {
		return nil, problem("C05", "can't listen on "+listenAddr+": "+err.Error(), "is another program using that port?")
	}
	k.logger.Info("SOCKS5 proxy is listening", "addr", ln.Addr().String())
	return ln, nil
}

func (k *Kitten) ServeSOCKS5(ctx context.Context, listenAddr string) error {
	ln, err := k.Listen(ctx, listenAddr)
	if err != nil {
		return err
	}
	return k.Serve(ctx, ln)
}

func (k *Kitten) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	var pause acceptPause
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !pause.wait(ctx, err) {
				return err
			}
			k.logger.Warn("accept is failing, backing off", "err", err)
			continue
		}
		pause.reset()
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetKeepAlive(true)
		}
		ref, ok := k.beginSession(conn)
		if !ok {
			_ = conn.Close()
			continue
		}
		go func() {
			defer k.endSession(ref)
			k.handleSocks(ctx, conn, ref)
		}()
	}
}