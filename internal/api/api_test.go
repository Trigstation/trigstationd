// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package api

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trigstation/trigstationd/internal/accept"
	"github.com/trigstation/trigstationd/internal/b64"
	"github.com/trigstation/trigstationd/internal/clientaddr"
	"github.com/trigstation/trigstationd/internal/pow"
	"github.com/trigstation/trigstationd/internal/ratelimit"
	"github.com/trigstation/trigstationd/internal/record"
	sigstore "github.com/trigstation/trigstationd/internal/signal"
	"github.com/trigstation/trigstationd/internal/store"
)

// testPoWBits is the difficulty the fixtures solve at.
//
// The directory's cost is one SHA-256 whatever the difficulty, so verification
// at 20 bits would be no slower — it is solving that is exponential, and a test
// suite that spent 100 ms per fixture would stop being run. The one test that
// exercises the shipped 20 bits is the vector round trip, whose proof of work
// was solved once and committed.
const testPoWBits = 8

// testNow is the clock every harness starts at unless told otherwise. It is far
// enough from any epoch boundary that nothing here depends on where it sits.
var testNow = time.Unix(1800000000, 0).UTC()

// clock is a settable time source, so that expiry, TTL and rate-limit windows
// can be tested at their boundaries without waiting for one.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// options configure a harness. The zero value is a conforming instance with
// signal channels on, generous limits and the fixture proof-of-work difficulty.
type options struct {
	powBits        int
	maxTTL         int64
	maxRecordBytes int
	noSignal       bool
	pollWindow     time.Duration
	maxWaiters     int
	rate           ratelimit.Options
	now            time.Time
	sourceURL      string
}

// harness is a running instance behind a real HTTP listener.
//
// A real listener rather than a bare ServeHTTP call, because several of the
// properties under test are transport properties: that a 204 carries no body,
// that a long-poll survives its window, that shutdown does not block on one.
type harness struct {
	t       *testing.T
	server  *httptest.Server
	api     *Server
	store   *store.Store
	signal  *sigstore.Store
	limiter *ratelimit.Limiter
	clock   *clock
}

func newHarness(t *testing.T, opts options) *harness {
	t.Helper()

	if opts.powBits == 0 {
		opts.powBits = testPoWBits
	}
	if opts.maxTTL == 0 {
		opts.maxTTL = record.MaxTTL
	}
	if opts.maxRecordBytes == 0 {
		opts.maxRecordBytes = record.MaxEnvelopeBytes
	}
	if opts.now.IsZero() {
		opts.now = testNow
	}
	if opts.sourceURL == "" {
		opts.sourceURL = DefaultSourceURL
	}

	recordStore, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("opening the record store: %v", err)
	}
	t.Cleanup(func() { recordStore.Close() })

	var signalStore *sigstore.Store
	if !opts.noSignal {
		signalStore = sigstore.New(sigstore.Options{
			PollWindow: opts.pollWindow,
			MaxWaiters: opts.maxWaiters,
		})
	}

	limiter := ratelimit.New(opts.rate)
	clk := &clock{t: opts.now}

	handler, err := New(Config{
		Store:      recordStore,
		Signal:     signalStore,
		Limiter:    limiter,
		ClientAddr: clientaddr.New(nil),
		Limits: accept.Limits{
			MaxRecordBytes: opts.maxRecordBytes,
			MaxTTL:         opts.maxTTL,
			PoWBits:        opts.powBits,
			SkewGrace:      accept.DefaultSkewGrace,
		},
		SourceURL: opts.sourceURL,
		Now:       clk.Now,
	})
	if err != nil {
		t.Fatalf("building the handler: %v", err)
	}

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return &harness{
		t:       t,
		server:  srv,
		api:     handler,
		store:   recordStore,
		signal:  signalStore,
		limiter: limiter,
		clock:   clk,
	}
}

// do issues a request against the harness and returns the response with its
// body already read.
func (h *harness) do(method, path string, body []byte, header http.Header) (*http.Response, []byte) {
	h.t.Helper()

	var reader io.Reader
	if body != nil {
		reader = strings.NewReader(string(body))
	}
	req, err := http.NewRequest(method, h.server.URL+path, reader)
	if err != nil {
		h.t.Fatalf("building a request: %v", err)
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	resp, err := h.server.Client().Do(req)
	if err != nil {
		h.t.Fatalf("issuing a request: %v", err)
	}
	defer resp.Body.Close()

	read, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatalf("reading a response body: %v", err)
	}
	return resp, read
}

func (h *harness) status(method, path string, body []byte) int {
	h.t.Helper()
	resp, _ := h.do(method, path, body, nil)
	return resp.StatusCode
}

// get issues a GET and reports the outcome without failing the test.
//
// The concurrency tests run a long-poll on their own goroutine, where the
// testing package forbids Fatalf: it calls runtime.Goexit, which would leave the
// test hanging on a channel that is never sent to rather than failing.
func (h *harness) get(path string) (int, []byte, error) {
	resp, err := h.server.Client().Get(h.server.URL + path)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	read, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, read, nil
}

// publisher is a server publishing under one epoch write key.
//
// The directory never derives a key, so the fixtures do not need internal/derive
// either: any Ed25519 keypair plus lookup_id = SHA-256(wk_pub) satisfies every
// condition §5.2 checks.
type publisher struct {
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	lookupID []byte
}

func newPublisher(seed byte) *publisher {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed + byte(i)
	}
	priv := ed25519.NewKeyFromSeed(s)
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	return &publisher{priv: priv, pub: pub, lookupID: sum[:]}
}

// fixtureCT is a stand-in ciphertext. The directory never decrypts, and the only
// thing it checks is that the value is at least as long as an AEAD tag.
var fixtureCT = func() []byte {
	ct := make([]byte, 64)
	for i := range ct {
		ct[i] = byte(0x40 + i)
	}
	return ct
}()

var fixtureNonce = []byte{0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab}

// envelope returns a fully valid envelope expiring at expiresAt, with a solved
// proof of work at bits.
func (p *publisher) envelope(t *testing.T, expiresAt int64, bits int) record.Envelope {
	t.Helper()

	solved, err := pow.Solve(context.Background(), p.lookupID, expiresAt, bits)
	if err != nil {
		t.Fatalf("solving the proof of work: %v", err)
	}
	sig := record.Sign(p.priv, record.Version, p.lookupID, p.pub, expiresAt, fixtureNonce, fixtureCT)

	return record.Envelope{
		V:         record.Version,
		LookupID:  b64.Encode(p.lookupID),
		WKPub:     b64.Encode(p.pub),
		ExpiresAt: expiresAt,
		CT:        b64.Encode(fixtureCT),
		Nonce:     b64.Encode(fixtureNonce),
		PoW:       b64.Encode(solved),
		Sig:       b64.Encode(sig),
	}
}

// body marshals an envelope for transmission.
func body(t *testing.T, e record.Envelope) []byte {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshalling an envelope: %v", err)
	}
	return b
}

// TestRouterExposesExactlyFourOperations is invariant 7 asserted mechanically.
//
// §10 makes the four operations a design constraint rather than a preference:
// anything that would add a fifth is a proposal to make directories less
// replaceable. The failure mode this guards against is not somebody arguing for
// a fifth operation — it is a health endpoint or a metrics endpoint arriving as
// an obviously reasonable convenience that nobody thinks of as a protocol
// change.
//
// OPTIONS is registered on two routes. §5.5 states in terms that it is HTTP
// transport mechanics for the four operations and not a fifth one, so it is
// asserted as present rather than counted as an operation.
func TestRouterExposesExactlyFourOperations(t *testing.T) {
	h := newHarness(t, options{})

	want := []string{
		"GET /v1/meta",
		"GET /v1/record",
		"GET /v1/signal/{channel_id}",
		"OPTIONS /v1/record",
		"OPTIONS /v1/signal/{channel_id}",
		"POST /v1/signal/{channel_id}",
		"PUT /v1/record",
	}

	got := h.api.Routes()
	sort.Strings(got)
	if len(got) != len(want) {
		t.Fatalf("the router registers %d patterns, want %d:\n got %q\nwant %q", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("registered pattern %d is %q, want %q", i, got[i], want[i])
		}
	}

	// The four operations, named by the section that defines each. §5.4 is one
	// operation with two methods — the specification calls it a pair — and
	// OPTIONS belongs to no operation at all, per §5.5.
	operations := map[string][]string{
		"§5.1 instance capabilities": {"GET /v1/meta"},
		"§5.2 publish":               {"PUT /v1/record"},
		"§5.3 lookup":                {"GET /v1/record"},
		"§5.4 signal channels": {
			"GET /v1/signal/{channel_id}",
			"POST /v1/signal/{channel_id}",
		},
	}
	if len(operations) != 4 {
		t.Fatalf("this test expects %d operations, and the API has four", len(operations))
	}

	accounted := map[string]string{}
	for operation, patterns := range operations {
		for _, pattern := range patterns {
			accounted[pattern] = operation
		}
	}

	for _, pattern := range got {
		method, _, ok := strings.Cut(pattern, " ")
		if !ok {
			t.Fatalf("pattern %q has no method", pattern)
		}
		if method == http.MethodOptions {
			continue
		}
		if _, ok := accounted[pattern]; !ok {
			t.Errorf("%q belongs to no operation of §5: this is the fifth operation invariant 7 forbids", pattern)
		}
	}
}

// TestUnregisteredPathsAre404 is the other half of invariant 7: the paths that
// must not exist, asserted by name.
//
// Each of these is a thing an operator or an operations team would reach for
// without considering it a protocol change, which is exactly why they are named
// individually rather than covered by a general statement about unknown paths.
func TestUnregisteredPathsAre404(t *testing.T) {
	h := newHarness(t, options{})

	paths := []string{
		"/",
		"/health",
		"/healthz",
		"/ready",
		"/readyz",
		"/livez",
		"/metrics",
		"/debug/pprof/",
		"/v1/",
		"/v1/health",
		"/v1/metrics",
		"/v1/stats",
		"/v1/records",
		"/admin",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			if got := h.status(http.MethodGet, path, nil); got != http.StatusNotFound {
				t.Errorf("GET %s = %d, want 404: the API has four operations and no others", path, got)
			}
		})
	}
}

// TestMetaCarriesEverySpecifiedMember checks §5.1's "all seven members are
// REQUIRED" against the wire bytes rather than against a decoded struct, since a
// struct with an omitempty tag would decode identically and emit differently.
func TestMetaCarriesEverySpecifiedMember(t *testing.T) {
	h := newHarness(t, options{})

	resp, read := h.do(http.MethodGet, "/v1/meta", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/meta = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	var members map[string]json.RawMessage
	if err := json.Unmarshal(read, &members); err != nil {
		t.Fatalf("the meta response is not a JSON object: %v", err)
	}

	for _, name := range []string{"v", "record_count", "max_ttl", "max_record_bytes", "pow_bits", "signal", "source_url"} {
		if _, ok := members[name]; !ok {
			t.Errorf("member %q is absent: §5.1 makes all seven REQUIRED", name)
		}
	}
	if len(members) != 7 {
		t.Errorf("the meta response has %d members, want 7: %v", len(members), members)
	}
}

// TestMetaSourceURLIsNeverEmpty is a licence obligation expressed as a test.
//
// AGPL §13 requires that anyone offering a modified version of this program over
// a network gives its users a way to obtain the modified source, and source_url
// is how this implementation discharges that. An empty or absent field is a
// licence violation that an operator cannot see, so it ships populated and the
// service refuses to start without it.
func TestMetaSourceURLIsNeverEmpty(t *testing.T) {
	for _, url := range []string{DefaultSourceURL, "https://git.example.net/fork/trigstationd"} {
		t.Run(url, func(t *testing.T) {
			h := newHarness(t, options{sourceURL: url})

			var m meta
			_, read := h.do(http.MethodGet, "/v1/meta", nil, nil)
			if err := json.Unmarshal(read, &m); err != nil {
				t.Fatalf("decoding the meta response: %v", err)
			}
			if m.SourceURL == "" {
				t.Fatal("source_url is empty: AGPL §13 compliance is not optional")
			}
			if m.SourceURL != url {
				t.Errorf("source_url = %q, want %q", m.SourceURL, url)
			}
		})
	}
}

// TestStartupRefusesAnEmptySourceURL checks the other half: the field cannot be
// configured away. A directory that started with it blank would be serving in
// violation, and a running service is the only kind that matters.
func TestStartupRefusesAnEmptySourceURL(t *testing.T) {
	recordStore, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("opening the record store: %v", err)
	}
	t.Cleanup(func() { recordStore.Close() })

	base := Config{
		Store:      recordStore,
		Limiter:    ratelimit.New(ratelimit.Options{}),
		ClientAddr: clientaddr.New(nil),
		SourceURL:  DefaultSourceURL,
	}

	if _, err := New(base); err != nil {
		t.Fatalf("a complete config was refused: %v", err)
	}

	for _, empty := range []string{"", " ", "\t", "\n"} {
		cfg := base
		cfg.SourceURL = empty
		if _, err := New(cfg); err != ErrNoSourceURL {
			t.Errorf("New with source_url %q returned %v, want ErrNoSourceURL", empty, err)
		}
	}
}

// TestMetaSignalReflectsConfiguration pairs the advertised capability with the
// behaviour of the route, because a client that believes a directory brokers
// signal channels and finds 404 will stop trying it altogether.
func TestMetaSignalReflectsConfiguration(t *testing.T) {
	cases := []struct {
		name       string
		noSignal   bool
		want       bool
		wantStatus int
	}{
		{"enabled", false, true, http.StatusNoContent},
		{"disabled", true, false, http.StatusNotFound},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, options{noSignal: c.noSignal, pollWindow: 20 * time.Millisecond})

			var m meta
			_, read := h.do(http.MethodGet, "/v1/meta", nil, nil)
			if err := json.Unmarshal(read, &m); err != nil {
				t.Fatalf("decoding the meta response: %v", err)
			}
			if m.Signal != c.want {
				t.Errorf("meta signal = %v, want %v", m.Signal, c.want)
			}

			got := h.status(http.MethodPost, "/v1/signal/"+testChannelID(0), []byte("blob"))
			if got != c.wantStatus {
				t.Errorf("POST to a signal channel = %d, want %d", got, c.wantStatus)
			}
		})
	}
}

// TestMetaRecordCountNeverExceedsTheTrueCount is the direction §5.1 makes
// normative.
//
// A client picks its prefix length from this figure, so an overstated count
// yields a narrower prefix and a result set smaller than the k it asked for —
// silently weakening the §8 anonymity guarantee for a client that followed the
// specification exactly. Understating is always safe.
func TestMetaRecordCountNeverExceedsTheTrueCount(t *testing.T) {
	h := newHarness(t, options{})
	expiresAt := testNow.Unix() + 3600

	for i := 0; i < 12; i++ {
		env := newPublisher(byte(i)).envelope(t, expiresAt, testPoWBits)
		if got := h.status(http.MethodPut, "/v1/record", body(t, env)); got != http.StatusNoContent {
			t.Fatalf("publishing fixture %d = %d, want 204", i, got)
		}

		trueCount, err := h.store.Count(context.Background(), h.clock.Now().Unix())
		if err != nil {
			t.Fatalf("counting records: %v", err)
		}

		var m meta
		_, read := h.do(http.MethodGet, "/v1/meta", nil, nil)
		if err := json.Unmarshal(read, &m); err != nil {
			t.Fatalf("decoding the meta response: %v", err)
		}
		if m.RecordCount > trueCount {
			t.Errorf("advertised record_count %d exceeds the true count %d", m.RecordCount, trueCount)
		}
	}
}

// TestUnderstateRoundsDownToTwoSignificantFigures pins the RECOMMENDED
// reduction in §5.1, including the boundary where rounding starts to apply.
func TestUnderstateRoundsDownToTwoSignificantFigures(t *testing.T) {
	cases := []struct{ in, want int64 }{
		{0, 0},
		{1, 1},
		{19, 19},
		{99, 99},
		{100, 100},
		{104, 100},
		{999, 990},
		{1000, 1000},
		{1049, 1000},
		{1050, 1000},
		{9999, 9900},
		{104233, 100000},
		{999999999, 990000000},
	}

	for _, c := range cases {
		if got := understate(c.in); got != c.want {
			t.Errorf("understate(%d) = %d, want %d", c.in, got, c.want)
		}
		if understate(c.in) > c.in {
			t.Errorf("understate(%d) = %d, which exceeds the true count", c.in, understate(c.in))
		}
	}
}

// TestCORSHeadersOnEveryResponse covers §5.5's "every /v1/ response", which
// includes the ones a handler never produces: the mux's 404 for an unregistered
// path and its 405 for a method that is not one of the four. A browser cannot
// read an error it is not allowed to see.
func TestCORSHeadersOnEveryResponse(t *testing.T) {
	h := newHarness(t, options{pollWindow: 20 * time.Millisecond})

	cases := []struct {
		name   string
		method string
		path   string
		body   []byte
	}{
		{"meta", http.MethodGet, "/v1/meta", nil},
		{"put record accepted", http.MethodPut, "/v1/record", body(t, newPublisher(1).envelope(t, testNow.Unix()+3600, testPoWBits))},
		{"put record rejected", http.MethodPut, "/v1/record", []byte("not json")},
		{"get record", http.MethodGet, "/v1/record?bits=0", nil},
		{"get record rejected", http.MethodGet, "/v1/record", nil},
		{"post signal", http.MethodPost, "/v1/signal/" + testChannelID(2), []byte("blob")},
		{"post signal rejected", http.MethodPost, "/v1/signal/short", []byte("blob")},
		{"get signal", http.MethodGet, "/v1/signal/" + testChannelID(3), nil},
		{"unregistered v1 path", http.MethodGet, "/v1/health", nil},
		{"method not allowed", http.MethodDelete, "/v1/record", nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, _ := h.do(c.method, c.path, c.body, nil)
			if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q (status was %d)", got, "*", resp.StatusCode)
			}
			if _, present := resp.Header["Access-Control-Allow-Credentials"]; present {
				t.Error("Access-Control-Allow-Credentials is present: §5.5 forbids it")
			}
		})
	}
}

// TestPreflight covers the two routes §5.5 names.
func TestPreflight(t *testing.T) {
	h := newHarness(t, options{})

	cases := []struct {
		path        string
		wantMethods []string
	}{
		{"/v1/record", []string{"GET", "PUT", "OPTIONS"}},
		{"/v1/signal/" + testChannelID(4), []string{"GET", "POST", "OPTIONS"}},
	}

	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			header := http.Header{}
			header.Set("Origin", "https://client.example.net")
			header.Set("Access-Control-Request-Method", "PUT")
			header.Set("Access-Control-Request-Headers", "Content-Type")

			resp, read := h.do(http.MethodOptions, c.path, nil, header)
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("OPTIONS %s = %d, want 204", c.path, resp.StatusCode)
			}
			if len(read) != 0 {
				t.Errorf("the preflight response carries a body of %d bytes", len(read))
			}
			if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
				t.Errorf("Access-Control-Allow-Origin = %q, want *", got)
			}
			if got := resp.Header.Get("Access-Control-Allow-Headers"); got != "Content-Type" {
				t.Errorf("Access-Control-Allow-Headers = %q, want Content-Type", got)
			}
			allowed := resp.Header.Get("Access-Control-Allow-Methods")
			for _, m := range c.wantMethods {
				if !strings.Contains(allowed, m) {
					t.Errorf("Access-Control-Allow-Methods = %q, missing %s", allowed, m)
				}
			}
			if _, present := resp.Header["Access-Control-Allow-Credentials"]; present {
				t.Error("Access-Control-Allow-Credentials is present: §5.5 forbids it")
			}
		})
	}
}

// TestRateLimitClassesAreIndependent is §6.4's "limits are per class".
//
// A client that exhausts its lookup allowance must not thereby lose the ability
// to publish, or to complete a device pairing already in progress. Under a
// single budget the three interfere, and the symptom — a pairing that fails
// because the user happened to open the app twice first — is not one anybody
// would trace back to a rate limiter.
func TestRateLimitClassesAreIndependent(t *testing.T) {
	exhaust := []struct {
		name  string
		drain func(*harness)
	}{
		{"put", func(h *harness) {
			h.status(http.MethodPut, "/v1/record", []byte("{}"))
		}},
		{"get", func(h *harness) {
			h.status(http.MethodGet, "/v1/record?bits=0", nil)
		}},
		{"signal", func(h *harness) {
			h.status(http.MethodGet, "/v1/signal/"+testChannelID(5), nil)
		}},
	}

	for _, e := range exhaust {
		t.Run(e.name, func(t *testing.T) {
			h := newHarness(t, options{
				pollWindow: 20 * time.Millisecond,
				rate:       ratelimit.Options{PutRecord: 1, GetRecord: 1, Signal: 1},
			})

			// One request of this class is admitted, the second is not.
			e.drain(h)
			e.drain(h)

			// Whichever class was drained, the other two still answer. Each is
			// checked for "not 429" rather than for a particular code, because
			// the point is the allowance and not the outcome.
			checks := []struct {
				name   string
				status int
			}{
				{"put", h.status(http.MethodPut, "/v1/record", []byte("{}"))},
				{"get", h.status(http.MethodGet, "/v1/record?bits=0", nil)},
				{"signal", h.status(http.MethodGet, "/v1/signal/"+testChannelID(6), nil)},
			}
			for _, c := range checks {
				if c.name == e.name {
					if c.status != http.StatusTooManyRequests {
						t.Errorf("the exhausted class %s returned %d, want 429", c.name, c.status)
					}
					continue
				}
				if c.status == http.StatusTooManyRequests {
					t.Errorf("class %s was rate limited by exhausting %s: §6.4 counts them independently",
						c.name, e.name)
				}
			}
		})
	}
}

// testChannelID returns a distinct, canonically encoded 32-byte channel_id.
func testChannelID(n byte) string {
	id := make([]byte, sigstore.ChannelIDBytes)
	for i := range id {
		id[i] = n*17 + byte(i)
	}
	return b64.Encode(id)
}
