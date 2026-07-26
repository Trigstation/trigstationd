// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package api

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/trigstation/trigstationd/internal/b64"
	"github.com/trigstation/trigstationd/internal/ratelimit"
	sigstore "github.com/trigstation/trigstationd/internal/signal"
)

// testPollWindow keeps the long-poll rows of the §5.4 table quick.
//
// §5.4 caps the window at 30 seconds and requires clients to tolerate an
// earlier 204, so a short window is conforming rather than a test-only
// concession. What it does not shorten is the shutdown test, which is about a
// poll that has not yet elapsed.
const testPollWindow = 50 * time.Millisecond

// TestSignalStatusTable walks every row of the §5.4 table end to end.
func TestSignalStatusTable(t *testing.T) {
	cases := []struct {
		name        string
		want        int
		opts        *options
		before      func(t *testing.T, h *harness)
		method      string
		channel     string
		body        []byte
		wantType    string
		wantPayload []byte
	}{
		{
			name:    "POST stored",
			want:    http.StatusNoContent,
			method:  http.MethodPost,
			channel: testChannelID(10),
			body:    []byte("an opaque blob"),
		},
		{
			name:    "POST channel_id is too short",
			want:    http.StatusBadRequest,
			method:  http.MethodPost,
			channel: "tooshort",
			body:    []byte("an opaque blob"),
		},
		{
			name: "POST channel_id is padded",
			want: http.StatusBadRequest,
			// 32 bytes spelled with padding is 44 characters. §4.4 forbids
			// emitting padding, and §5.4 identifies a channel by its decoded
			// bytes — so tolerating a padded spelling would give one rendezvous
			// two names and a way around first-write-wins.
			method:  http.MethodPost,
			channel: testChannelID(11) + "=",
			body:    []byte("an opaque blob"),
		},
		{
			name:    "POST channel_id decodes to the wrong length",
			want:    http.StatusBadRequest,
			method:  http.MethodPost,
			channel: b64.Encode(make([]byte, 16)),
			body:    []byte("an opaque blob"),
		},
		{
			name:    "POST body exceeds the payload limit",
			want:    http.StatusRequestEntityTooLarge,
			method:  http.MethodPost,
			channel: testChannelID(12),
			body:    bytes.Repeat([]byte("x"), sigstore.MaxBlobBytes+1),
		},
		{
			name: "POST to a channel already holding a blob",
			want: http.StatusConflict,
			before: func(t *testing.T, h *harness) {
				if got := h.status(http.MethodPost, "/v1/signal/"+testChannelID(13), []byte("first")); got != http.StatusNoContent {
					t.Fatalf("seeding first-write-wins = %d, want 204", got)
				}
			},
			method:  http.MethodPost,
			channel: testChannelID(13),
			body:    []byte("second"),
		},
		{
			name: "GET delivers a blob that is present",
			want: http.StatusOK,
			before: func(t *testing.T, h *harness) {
				if got := h.status(http.MethodPost, "/v1/signal/"+testChannelID(14), []byte("payload")); got != http.StatusNoContent {
					t.Fatalf("seeding a blob = %d, want 204", got)
				}
			},
			method:      http.MethodGet,
			channel:     testChannelID(14),
			wantType:    "application/octet-stream",
			wantPayload: []byte("payload"),
		},
		{
			name:    "GET long-poll window elapses with no blob",
			want:    http.StatusNoContent,
			method:  http.MethodGet,
			channel: testChannelID(15),
		},
		{
			name:    "GET channel_id is not 32 bytes of unpadded base64url",
			want:    http.StatusBadRequest,
			method:  http.MethodGet,
			channel: "not-a-channel",
		},
		{
			name: "POST rate limited",
			want: http.StatusTooManyRequests,
			opts: &options{rate: ratelimit.Options{Signal: 1}},
			before: func(t *testing.T, h *harness) {
				h.status(http.MethodPost, "/v1/signal/"+testChannelID(16), []byte("first"))
			},
			method:  http.MethodPost,
			channel: testChannelID(17),
			body:    []byte("second"),
		},
		{
			name: "GET rate limited",
			want: http.StatusTooManyRequests,
			opts: &options{rate: ratelimit.Options{Signal: 1}},
			before: func(t *testing.T, h *harness) {
				h.status(http.MethodGet, "/v1/signal/"+testChannelID(18), nil)
			},
			method:  http.MethodGet,
			channel: testChannelID(19),
		},
		{
			name: "POST to a draining instance",
			want: http.StatusTooManyRequests,
			before: func(t *testing.T, h *harness) {
				// A draining instance cannot deliver the blob, so answering
				// "stored" would be a lie the poster acts on. 429 is the only
				// code in the table whose remedy — back off, retry, move on —
				// is what the client should actually do.
				h.api.Drain()
			},
			method:  http.MethodPost,
			channel: testChannelID(20),
			body:    []byte("undeliverable"),
		},
		{
			name:    "POST to an instance advertising signal false",
			want:    http.StatusNotFound,
			opts:    &options{noSignal: true},
			method:  http.MethodPost,
			channel: testChannelID(21),
			body:    []byte("an opaque blob"),
		},
		{
			name:    "GET on an instance advertising signal false",
			want:    http.StatusNotFound,
			opts:    &options{noSignal: true},
			method:  http.MethodGet,
			channel: testChannelID(22),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := options{pollWindow: testPollWindow}
			if c.opts != nil {
				opts = *c.opts
				opts.pollWindow = testPollWindow
			}
			h := newHarness(t, opts)

			if c.before != nil {
				c.before(t, h)
			}

			resp, read := h.do(c.method, "/v1/signal/"+c.channel, c.body, nil)
			if resp.StatusCode != c.want {
				t.Errorf("%s /v1/signal/… = %d, want %d", c.method, resp.StatusCode, c.want)
			}
			if c.wantType != "" {
				if got := resp.Header.Get("Content-Type"); got != c.wantType {
					t.Errorf("Content-Type = %q, want %q", got, c.wantType)
				}
			}
			if c.wantPayload != nil && !bytes.Equal(read, c.wantPayload) {
				t.Errorf("the delivered blob is %q, want %q", read, c.wantPayload)
			}
			if c.wantPayload == nil && len(read) != 0 {
				t.Errorf("the response carries a body of %d bytes", len(read))
			}
		})
	}
}

// TestSignalGetAtCapacityIs429 covers the other half of §5.4's "instance at
// capacity, or shutting down" row, which the table test cannot reach without a
// waiter already in place.
//
// 429 rather than an immediate 204, which §5.4 would permit. A 204 tells the
// client to poll again straight away, hot-looping against the instance that has
// just declined it; 429 means back off or move on, which is the correct
// behaviour when an instance is full.
func TestSignalGetAtCapacityIs429(t *testing.T) {
	h := newHarness(t, options{pollWindow: 30 * time.Second, maxWaiters: 1})

	held := make(chan struct{})
	go func() {
		defer close(held)
		h.get("/v1/signal/" + testChannelID(40))
	}()

	waitFor(t, func() bool { return h.signal.Waiting() == 1 })

	if got := h.status(http.MethodGet, "/v1/signal/"+testChannelID(41), nil); got != http.StatusTooManyRequests {
		t.Errorf("GET at the waiter cap = %d, want 429", got)
	}

	h.api.Drain()
	<-held
}

// TestSignalLongPollIsWokenByAPost checks the path §5.4 exists for: a reader
// waiting, a writer arriving, and the blob delivered without the reader having
// to poll again.
func TestSignalLongPollIsWokenByAPost(t *testing.T) {
	h := newHarness(t, options{pollWindow: 5 * time.Second})
	channel := testChannelID(30)
	payload := []byte("an encrypted offer")

	type result struct {
		status int
		body   []byte
		err    error
	}
	done := make(chan result, 1)

	go func() {
		status, read, err := h.get("/v1/signal/" + channel)
		done <- result{status, read, err}
	}()

	// Wait for the poller to register rather than sleeping a fixed interval.
	waitFor(t, func() bool { return h.signal.Waiting() > 0 })

	if got := h.status(http.MethodPost, "/v1/signal/"+channel, payload); got != http.StatusNoContent {
		t.Fatalf("posting to a waiting channel = %d, want 204", got)
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("the long-poll request failed: %v", r.err)
		}
		if r.status != http.StatusOK {
			t.Errorf("the woken long-poll returned %d, want 200", r.status)
		}
		if !bytes.Equal(r.body, payload) {
			t.Errorf("the delivered blob is %q, want %q", r.body, payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the long-poll was not woken by a post")
	}
}

// TestSignalLongPollEndsOnClientDisconnect is what keeps an abandoned request
// from holding a waiter for the rest of its window.
//
// PAIRING-SPEC.md §6.3 makes polling the normal path, so waiters are the common
// case rather than an edge one, and a client that goes away without releasing
// its waiter would consume the instance-wide budget over time.
func TestSignalLongPollEndsOnClientDisconnect(t *testing.T) {
	h := newHarness(t, options{pollWindow: 30 * time.Second})
	channel := testChannelID(31)

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.server.URL+"/v1/signal/"+channel, nil)
	if err != nil {
		t.Fatalf("building a request: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, err := h.server.Client().Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}()

	waitFor(t, func() bool { return h.signal.Waiting() > 0 })
	cancel()

	<-done
	waitFor(t, func() bool { return h.signal.Waiting() == 0 })
}

// TestGracefulShutdownDrainsLongPolls is the concurrency hazard of the whole
// service, asserted with a stopwatch.
//
// §5.4 lets a directory hold a GET open for 30 seconds. A shutdown that closed
// the listener and then waited for active requests would wait out that window on
// any instance with one idle poller — and an idle poller is the normal state,
// not an unusual one. Draining first turns every open poll into an immediate
// answer.
//
// That answer is 429, not 204. §5.4 binds "at capacity, or shutting down" to
// 429 for either method: a draining instance cannot serve a later poll either,
// so 204 — "nothing yet, ask again" — would send the client straight back to an
// instance on its way down.
//
// The assertion is on both halves: the shutdown completes promptly, and the poll
// returns rather than hanging. Either alone would pass with the bug present.
func TestGracefulShutdownDrainsLongPolls(t *testing.T) {
	h := newHarness(t, options{pollWindow: 30 * time.Second})
	channel := testChannelID(32)

	polled := make(chan int, 1)
	go func() {
		status, _, err := h.get("/v1/signal/" + channel)
		if err != nil {
			// A transport failure is not a 429, and reporting a sentinel keeps
			// the test failing rather than hanging.
			status = -1
		}
		polled <- status
	}()

	waitFor(t, func() bool { return h.signal.Waiting() > 0 })

	// httptest.Server.Close waits for outstanding requests, which is exactly the
	// behaviour http.Server.Shutdown has and exactly what a long-poll would
	// otherwise block.
	shut := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		h.api.Drain()
		h.server.Close()
		shut <- time.Since(start)
	}()

	select {
	case status := <-polled:
		if status != http.StatusTooManyRequests {
			t.Errorf("the drained long-poll returned %d, want 429", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the long-poll did not return within five seconds of a drain")
	}

	select {
	case elapsed := <-shut:
		if elapsed > 5*time.Second {
			t.Errorf("shutdown took %v with one long-poll open, want under five seconds", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not complete within five seconds with a long-poll open")
	}
}

// TestSweepsAreCallable exercises the two reclamation entry points the server's
// timers drive.
//
// §6.4 requires limiter state to be discarded on a timer as well as on the
// request path, so that an instance which goes quiet does not retain the last
// keys it saw. Neither sweep changes an answer, so what is asserted is that the
// state goes.
func TestSweepsAreCallable(t *testing.T) {
	h := newHarness(t, options{})
	ctx := context.Background()

	env := newPublisher(70).envelope(t, testNow.Unix()+3600, testPoWBits)
	if got := h.status(http.MethodPut, "/v1/record", body(t, env)); got != http.StatusNoContent {
		t.Fatalf("publishing a fixture = %d, want 204", got)
	}
	if h.limiter.TrackedKeys() == 0 {
		t.Fatal("the publish left no limiter state to reclaim")
	}

	// Nothing has expired yet, so both sweeps are no-ops.
	if err := h.api.SweepRecords(ctx); err != nil {
		t.Fatalf("sweeping records: %v", err)
	}
	h.api.SweepLimiter()

	count, err := h.store.Count(ctx, h.clock.Now().Unix())
	if err != nil {
		t.Fatalf("counting records: %v", err)
	}
	if count != 1 {
		t.Errorf("the sweep removed a live record: count = %d, want 1", count)
	}

	// Past the record's expiry and past the limiter's window.
	h.clock.set(testNow.Add(2 * time.Hour))

	if err := h.api.SweepRecords(ctx); err != nil {
		t.Fatalf("sweeping records: %v", err)
	}
	h.api.SweepLimiter()

	count, err = h.store.Count(ctx, h.clock.Now().Unix())
	if err != nil {
		t.Fatalf("counting records: %v", err)
	}
	if count != 0 {
		t.Errorf("the expired record survived the sweep: count = %d, want 0", count)
	}
	if got := h.limiter.TrackedKeys(); got != 0 {
		t.Errorf("limiter state survived its window: %d keys tracked, want 0", got)
	}
}

// waitFor polls a condition until it holds, so that a concurrency test does not
// depend on a fixed sleep being long enough on a loaded machine.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("a condition did not hold within five seconds")
}
