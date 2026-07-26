// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package signal

import (
	"bytes"
	"context"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trigstation/trigstationd/internal/b64"
	"github.com/trigstation/trigstationd/internal/reject"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// chanID returns a well-formed channel_id: 32 bytes, unpadded base64url.
func chanID(seed byte) string {
	raw := make([]byte, ChannelIDBytes)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return b64.Encode(raw)
}

// reasonString renders a SignalReason with its status code, because the
// constants are small integers and a bare number in a failure message says
// nothing.
func reasonString(r reject.SignalReason) string {
	return strconv.Itoa(int(r)) + " (HTTP " + strconv.Itoa(r.HTTPStatus()) + ")"
}

// noGoroutineLeak fails the test if the goroutine count has not returned to
// where it started. It settles in a loop rather than sleeping a fixed period,
// because a released waiter's goroutine is scheduled, not instant.
func noGoroutineLeak(t *testing.T) {
	t.Helper()
	base := runtime.NumGoroutine()
	t.Cleanup(func() {
		for i := 0; i < 200; i++ {
			if runtime.NumGoroutine() <= base {
				return
			}
			runtime.Gosched()
			time.Sleep(10 * time.Millisecond)
		}
		t.Errorf("goroutine count settled at %d, want no more than the %d at test start",
			runtime.NumGoroutine(), base)
	})
}

// waitForWaiters blocks until the store holds exactly n waiters. Tests that
// assert on the waiter caps have to know the waiters are registered, and
// sleeping a guessed interval instead is how a test suite becomes flaky.
func waitForWaiters(t *testing.T, s *Store, n int) {
	t.Helper()
	for i := 0; i < 500; i++ {
		s.mu.Lock()
		got := s.waiting
		s.mu.Unlock()
		if got == n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.mu.Lock()
	got := s.waiting
	s.mu.Unlock()
	t.Fatalf("waiter count settled at %d, want %d", got, n)
}

// fastPoll is a store whose long-poll window is short enough to test against.
// The window is configuration; the ceiling it is clamped to is the protocol,
// and TestPollWindowCeiling covers that separately.
func fastPoll(window time.Duration) *Store {
	return New(Options{PollWindow: window})
}

// ---------------------------------------------------------------------------
// 1. First write wins (§5.4)
// ---------------------------------------------------------------------------

func TestFirstWriteWins(t *testing.T) {
	noGoroutineLeak(t)

	first := []byte("the legitimate blob")
	second := []byte("the injected blob")

	s := fastPoll(50 * time.Millisecond)
	defer s.Shutdown()
	id := chanID(1)
	now := time.Unix(1753488000, 0)

	if got := s.Post(id, first, now); got != reject.SignalStored {
		t.Fatalf("first Post = %s, want SignalStored", reasonString(got))
	}
	if got := s.Post(id, second, now.Add(time.Second)); got != reject.SignalConflict {
		t.Fatalf("second Post = %s, want SignalConflict", reasonString(got))
	}

	blob, reason := s.Get(context.Background(), id, now.Add(2*time.Second))
	if reason != reject.SignalDelivered {
		t.Fatalf("Get = %s, want SignalDelivered", reasonString(reason))
	}
	// The code alone would pass with an overwrite that happened to be
	// reported as a conflict. The content is the property.
	if !bytes.Equal(blob, first) {
		t.Errorf("Get delivered %q, want the first blob %q", blob, first)
	}
}

// A rejected second write must not disturb the stored blob's expiry either: a
// poster able to push the expiry out could keep a channel occupied for ever.
func TestConflictDoesNotExtendExpiry(t *testing.T) {
	noGoroutineLeak(t)

	s := fastPoll(20 * time.Millisecond)
	defer s.Shutdown()
	id := chanID(2)
	now := time.Unix(1753488000, 0)

	s.Post(id, []byte("first"), now)
	for i := 1; i <= 4; i++ {
		// Each of these is inside the first blob's lifetime, so each is a
		// conflict rather than a fresh store.
		at := now.Add(time.Duration(i) * time.Minute)
		if got := s.Post(id, []byte("later"), at); got != reject.SignalConflict {
			t.Fatalf("Post at +%dm = %s, want SignalConflict", i, reasonString(got))
		}
	}

	if _, reason := s.Get(context.Background(), id, now.Add(MaxTTL)); reason != reject.SignalEmpty {
		t.Errorf("Get at the original expiry = %s, want SignalEmpty", reasonString(reason))
	}
}

// ---------------------------------------------------------------------------
// 2 and 3. Expiry (§4.3, DECISIONS.md D-7)
// ---------------------------------------------------------------------------

func TestTTLExpiryFreesChannel(t *testing.T) {
	noGoroutineLeak(t)

	s := fastPoll(20 * time.Millisecond)
	defer s.Shutdown()
	id := chanID(3)
	now := time.Unix(1753488000, 0)
	expired := now.Add(MaxTTL)

	if got := s.Post(id, []byte("stale"), now); got != reject.SignalStored {
		t.Fatalf("Post = %s, want SignalStored", reasonString(got))
	}

	// A Get after expiry finds nothing, and long-polls rather than delivering.
	if _, reason := s.Get(context.Background(), id, expired); reason != reject.SignalEmpty {
		t.Fatalf("Get after expiry = %s, want SignalEmpty", reasonString(reason))
	}

	// And the channel is free, so a Post succeeds rather than conflicting.
	if got := s.Post(id, []byte("fresh"), expired); got != reject.SignalStored {
		t.Fatalf("Post after expiry = %s, want SignalStored", reasonString(got))
	}
	blob, reason := s.Get(context.Background(), id, expired)
	if reason != reject.SignalDelivered || !bytes.Equal(blob, []byte("fresh")) {
		t.Errorf("Get = %q, %s, want %q delivered", blob, reasonString(reason), "fresh")
	}
}

func TestExpiryIsBoundaryExclusive(t *testing.T) {
	noGoroutineLeak(t)

	s := fastPoll(20 * time.Millisecond)
	defer s.Shutdown()
	now := time.Unix(1753488000, 0)

	tests := []struct {
		name string
		at   time.Time
		want reject.SignalReason
	}{
		{"one nanosecond before expiry", now.Add(MaxTTL - time.Nanosecond), reject.SignalDelivered},
		{"exactly at expiry", now.Add(MaxTTL), reject.SignalEmpty},
		{"after expiry", now.Add(MaxTTL + time.Second), reject.SignalEmpty},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := chanID(byte(40 + i))
			if got := s.Post(id, []byte("blob"), now); got != reject.SignalStored {
				t.Fatalf("Post = %s, want SignalStored", reasonString(got))
			}
			if _, got := s.Get(context.Background(), id, tt.at); got != tt.want {
				t.Errorf("Get = %s, want %s", reasonString(got), reasonString(tt.want))
			}
		})
	}
}

// An expired blob is absent whether or not a sweep has reached it. The store
// is left far below its sweep threshold, and the blob is confirmed still
// resident, so the Get is answered by the expiry rule alone.
func TestExpiredBlobIsAbsentWithoutASweep(t *testing.T) {
	noGoroutineLeak(t)

	s := fastPoll(20 * time.Millisecond)
	defer s.Shutdown()
	id := chanID(5)
	now := time.Unix(1753488000, 0)

	s.Post(id, []byte("stale"), now)

	s.mu.Lock()
	resident := len(s.channels) == 1
	s.mu.Unlock()
	if !resident {
		t.Fatal("test precondition: the blob should still be resident, unswept")
	}

	if _, reason := s.Get(context.Background(), id, now.Add(MaxTTL+time.Hour)); reason != reject.SignalEmpty {
		t.Errorf("Get of an unswept expired blob = %s, want SignalEmpty", reasonString(reason))
	}
}

// The sweep reclaims memory and must change nothing else. Enough channels are
// posted to trip the threshold, then the surviving behaviour is checked.
func TestSweepChangesNoObservableBehaviour(t *testing.T) {
	noGoroutineLeak(t)

	s := fastPoll(20 * time.Millisecond)
	defer s.Shutdown()
	now := time.Unix(1753488000, 0)

	raw := make([]byte, ChannelIDBytes)
	for i := 0; i < 64; i++ {
		raw[0], raw[1] = byte(i), byte(i>>8)
		s.Post(b64.Encode(raw), []byte("blob"), now)
	}

	// Force the sweep rather than posting the thousand channels its threshold
	// would otherwise need. What is under test is that a sweep reclaims only
	// memory, not when it chooses to run.
	s.mu.Lock()
	s.sweepAt = 1
	s.mu.Unlock()

	// Everything above is expired at this point, so the next Post sweeps.
	live := chanID(6)
	if got := s.Post(live, []byte("live"), now.Add(MaxTTL)); got != reject.SignalStored {
		t.Fatalf("Post = %s, want SignalStored", reasonString(got))
	}

	s.mu.Lock()
	remaining := len(s.channels)
	s.mu.Unlock()
	if remaining != 1 {
		t.Errorf("after the sweep the store holds %d channels, want 1", remaining)
	}

	blob, reason := s.Get(context.Background(), live, now.Add(MaxTTL))
	if reason != reject.SignalDelivered || !bytes.Equal(blob, []byte("live")) {
		t.Errorf("Get = %q, %s, want the live blob delivered", blob, reasonString(reason))
	}
}

// ---------------------------------------------------------------------------
// 4, 5 and 6. Long polling (§5.4)
// ---------------------------------------------------------------------------

func TestLongPollReceivesALaterPost(t *testing.T) {
	noGoroutineLeak(t)

	s := fastPoll(5 * time.Second)
	defer s.Shutdown()
	id := chanID(7)
	now := time.Unix(1753488000, 0)

	type result struct {
		blob   []byte
		reason reject.SignalReason
	}
	done := make(chan result, 1)
	go func() {
		blob, reason := s.Get(context.Background(), id, now)
		done <- result{blob, reason}
	}()

	waitForWaiters(t, s, 1)
	if got := s.Post(id, []byte("answer"), now); got != reject.SignalStored {
		t.Fatalf("Post = %s, want SignalStored", reasonString(got))
	}

	select {
	case r := <-done:
		if r.reason != reject.SignalDelivered {
			t.Fatalf("Get = %s, want SignalDelivered", reasonString(r.reason))
		}
		if !bytes.Equal(r.blob, []byte("answer")) {
			t.Errorf("Get delivered %q, want %q", r.blob, "answer")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("long poll did not receive a blob posted after it began")
	}
}

func TestLongPollTimesOutAtTheDeadline(t *testing.T) {
	noGoroutineLeak(t)

	const window = 150 * time.Millisecond
	s := fastPoll(window)
	defer s.Shutdown()

	start := time.Now()
	_, reason := s.Get(context.Background(), chanID(8), time.Unix(1753488000, 0))
	elapsed := time.Since(start)

	if reason != reject.SignalEmpty {
		t.Errorf("timed-out Get = %s, want SignalEmpty", reasonString(reason))
	}
	// 204, not 404: the two carry opposite instructions to the client.
	if got := reason.HTTPStatus(); got != 204 {
		t.Errorf("timed-out Get status = %d, want 204", got)
	}
	// SHOULD hold for the full window.
	if elapsed < window {
		t.Errorf("long poll returned after %v, before its %v window", elapsed, window)
	}
	// MUST NOT hold longer than the window.
	if elapsed > window+2*time.Second {
		t.Errorf("long poll returned after %v, well beyond its %v window", elapsed, window)
	}
}

// §5.4: a directory MUST NOT hold a long-poll open for longer than 30 seconds,
// and §4.3 caps the TTL and the payload. Configuration may lower those, never
// raise them.
func TestOptionsAreClampedToSpecCeilings(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		want Options
	}{
		{
			name: "zero value gives the spec defaults",
			opts: Options{},
			want: Options{TTL: MaxTTL, PollWindow: MaxPollWindow, MaxBlobBytes: MaxBlobBytes,
				MaxWaiters: DefaultMaxWaiters, MaxWaitersPerChannel: DefaultMaxWaitersPerChannel},
		},
		{
			name: "over-large values are clamped down",
			opts: Options{TTL: time.Hour, PollWindow: 45 * time.Second, MaxBlobBytes: 1 << 20},
			want: Options{TTL: MaxTTL, PollWindow: MaxPollWindow, MaxBlobBytes: MaxBlobBytes,
				MaxWaiters: DefaultMaxWaiters, MaxWaitersPerChannel: DefaultMaxWaitersPerChannel},
		},
		{
			name: "lower values are honoured",
			opts: Options{TTL: time.Minute, PollWindow: time.Second, MaxBlobBytes: 1024,
				MaxWaiters: 5, MaxWaitersPerChannel: 2},
			want: Options{TTL: time.Minute, PollWindow: time.Second, MaxBlobBytes: 1024,
				MaxWaiters: 5, MaxWaitersPerChannel: 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New(tt.opts)
			got := Options{s.ttl, s.poll, s.maxBlob, s.maxWaiters, s.maxPerChan}
			if got != tt.want {
				t.Errorf("New(%+v) configured %+v, want %+v", tt.opts, got, tt.want)
			}
		})
	}
}

func TestCancellationReleasesTheWaiterPromptly(t *testing.T) {
	noGoroutineLeak(t)

	const window = 5 * time.Second
	s := fastPoll(window)
	defer s.Shutdown()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		s.Get(ctx, chanID(9), time.Unix(1753488000, 0))
		done <- time.Since(start)
	}()

	waitForWaiters(t, s, 1)
	cancel()

	select {
	case elapsed := <-done:
		// Promptly, not merely eventually: a disconnected client's waiter must
		// not occupy the waiter budget until the deadline.
		if elapsed > window/5 {
			t.Errorf("cancelled long poll returned after %v, want well under the %v window", elapsed, window)
		}
	case <-time.After(window):
		t.Fatal("cancelled long poll ran to its deadline")
	}

	waitForWaiters(t, s, 0)
}

// ---------------------------------------------------------------------------
// 7. Delete on read (§5.4)
// ---------------------------------------------------------------------------

func TestConcurrentGetsDeliverToExactlyOne(t *testing.T) {
	noGoroutineLeak(t)

	const readers = 8
	s := fastPoll(300 * time.Millisecond)
	defer s.Shutdown()
	id := chanID(10)
	now := time.Unix(1753488000, 0)

	s.Post(id, []byte("once"), now)

	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		delivered int
		empty     int
	)
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			blob, reason := s.Get(context.Background(), id, now)
			mu.Lock()
			defer mu.Unlock()
			switch reason {
			case reject.SignalDelivered:
				delivered++
				if !bytes.Equal(blob, []byte("once")) {
					t.Errorf("delivered %q, want %q", blob, "once")
				}
			case reject.SignalEmpty:
				empty++
			default:
				t.Errorf("Get = %s, want SignalDelivered or SignalEmpty", reasonString(reason))
			}
		}()
	}
	wg.Wait()

	if delivered != 1 {
		t.Errorf("%d readers received the blob, want exactly 1", delivered)
	}
	if empty != readers-1 {
		t.Errorf("%d readers came away empty, want %d", empty, readers-1)
	}
}

// The same property, from the other direction: one blob posted while several
// readers are already waiting reaches exactly one of them.
func TestPostToManyWaitersDeliversToExactlyOne(t *testing.T) {
	noGoroutineLeak(t)

	const readers = 6
	s := New(Options{PollWindow: 2 * time.Second, MaxWaitersPerChannel: readers})
	defer s.Shutdown()
	id := chanID(11)
	now := time.Unix(1753488000, 0)

	results := make(chan reject.SignalReason, readers)
	for i := 0; i < readers; i++ {
		go func() {
			_, reason := s.Get(context.Background(), id, now)
			results <- reason
		}()
	}
	waitForWaiters(t, s, readers)

	s.Post(id, []byte("once"), now)

	delivered := 0
	for i := 0; i < readers; i++ {
		if <-results == reject.SignalDelivered {
			delivered++
		}
	}
	if delivered != 1 {
		t.Errorf("%d of %d waiters received the blob, want exactly 1", delivered, readers)
	}
}

// ---------------------------------------------------------------------------
// 9. Shutdown
// ---------------------------------------------------------------------------

func TestShutdownReleasesAnOpenLongPoll(t *testing.T) {
	noGoroutineLeak(t)

	const window = 10 * time.Second
	s := fastPoll(window)

	done := make(chan reject.SignalReason, 1)
	go func() {
		_, reason := s.Get(context.Background(), chanID(12), time.Unix(1753488000, 0))
		done <- reason
	}()
	waitForWaiters(t, s, 1)

	start := time.Now()
	s.Shutdown()
	shutdownTook := time.Since(start)

	if shutdownTook > time.Second {
		t.Errorf("Shutdown took %v with a long poll open, want prompt", shutdownTook)
	}
	select {
	case reason := <-done:
		// 429, not 204: §5.4 binds "at capacity, or shutting down" to 429 for
		// either method, and a draining instance cannot serve a later poll
		// either. 204 would send the client straight back to an instance on
		// its way down.
		if reason != reject.SignalRateLimited {
			t.Errorf("released long poll = %s, want SignalRateLimited", reasonString(reason))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("long poll hung past Shutdown")
	}

	// Idempotent, and closed to further work.
	s.Shutdown()
	if _, reason := s.Get(context.Background(), chanID(12), time.Now()); reason != reject.SignalRateLimited {
		t.Errorf("Get after Shutdown = %s, want SignalRateLimited", reasonString(reason))
	}
	if got := s.Post(chanID(12), []byte("late"), time.Now()); got != reject.SignalRateLimited {
		t.Errorf("Post after Shutdown = %s, want SignalRateLimited", reasonString(got))
	}
}

// ---------------------------------------------------------------------------
// 10. Waiter caps
// ---------------------------------------------------------------------------

func TestWaiterCaps(t *testing.T) {
	tests := []struct {
		name     string
		opts     Options
		channels int
		perChan  int
	}{
		{
			name:     "per-channel cap",
			opts:     Options{PollWindow: 5 * time.Second, MaxWaiters: 64, MaxWaitersPerChannel: 3},
			channels: 1,
			perChan:  3,
		},
		{
			name:     "global cap",
			opts:     Options{PollWindow: 5 * time.Second, MaxWaiters: 4, MaxWaitersPerChannel: 2},
			channels: 2,
			perChan:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			noGoroutineLeak(t)

			s := New(tt.opts)
			defer s.Shutdown()
			now := time.Unix(1753488000, 0)

			for c := 0; c < tt.channels; c++ {
				for w := 0; w < tt.perChan; w++ {
					go s.Get(context.Background(), chanID(byte(20+c)), now) //nolint
				}
			}
			waitForWaiters(t, s, tt.channels*tt.perChan)

			// One more on an existing channel exceeds the per-channel cap in
			// the first case and the global cap in the second.
			if _, reason := s.Get(context.Background(), chanID(20), now); reason != reject.SignalRateLimited {
				t.Errorf("Get past the cap = %s, want SignalRateLimited", reasonString(reason))
			}
			// A fresh channel is refused too when the global cap is reached,
			// and admitted when only the per-channel cap is.
			want := reject.SignalEmpty
			if tt.channels*tt.perChan >= tt.opts.MaxWaiters {
				want = reject.SignalRateLimited
			}
			ctx, cancel := context.WithCancel(context.Background())
			fresh := make(chan reject.SignalReason, 1)
			go func() {
				_, reason := s.Get(ctx, chanID(99), now)
				fresh <- reason
			}()
			if want == reject.SignalRateLimited {
				if got := <-fresh; got != want {
					t.Errorf("Get on a fresh channel past the global cap = %s, want %s",
						reasonString(got), reasonString(want))
				}
			} else {
				waitForWaiters(t, s, tt.channels*tt.perChan+1)
			}
			cancel()
			if want != reject.SignalRateLimited {
				<-fresh
			}

			// Rejected waiters leave no trace behind them.
			s.Shutdown()
			s.mu.Lock()
			leftover := len(s.channels)
			s.mu.Unlock()
			if leftover != 0 {
				t.Errorf("%d channels left after Shutdown, want 0", leftover)
			}
		})
	}
}

// A cap rejection must be immediate. Queueing behind the cap would turn the
// bound into a delay rather than a refusal, which is not a bound at all.
func TestCapRejectionDoesNotBlock(t *testing.T) {
	noGoroutineLeak(t)

	s := New(Options{PollWindow: 10 * time.Second, MaxWaiters: 1})
	defer s.Shutdown()
	now := time.Unix(1753488000, 0)

	ctx, cancel := context.WithCancel(context.Background())
	held := make(chan struct{})
	go func() {
		s.Get(ctx, chanID(21), now)
		close(held)
	}()
	waitForWaiters(t, s, 1)

	start := time.Now()
	_, reason := s.Get(context.Background(), chanID(22), now)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("capped Get took %v, want an immediate refusal", elapsed)
	}
	if reason != reject.SignalRateLimited {
		t.Errorf("capped Get = %s, want SignalRateLimited", reasonString(reason))
	}

	cancel()
	<-held
}

// ---------------------------------------------------------------------------
// 11. Payload limit (§4.3)
// ---------------------------------------------------------------------------

func TestBlobSizeLimit(t *testing.T) {
	noGoroutineLeak(t)

	tests := []struct {
		name string
		size int
		want reject.SignalReason
	}{
		{"empty", 0, reject.SignalStored},
		{"one byte under the limit", MaxBlobBytes - 1, reject.SignalStored},
		{"exactly at the limit", MaxBlobBytes, reject.SignalStored},
		{"one byte over the limit", MaxBlobBytes + 1, reject.SignalTooLarge},
		{"far over the limit", 4 * MaxBlobBytes, reject.SignalTooLarge},
	}

	s := fastPoll(20 * time.Millisecond)
	defer s.Shutdown()
	now := time.Unix(1753488000, 0)

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := chanID(byte(60 + i))
			blob := bytes.Repeat([]byte{0xA5}, tt.size)
			if got := s.Post(id, blob, now); got != tt.want {
				t.Fatalf("Post of %d bytes = %s, want %s", tt.size, reasonString(got), reasonString(tt.want))
			}
			if tt.want != reject.SignalStored {
				// A rejected body is not stored, so the channel is still free.
				if got := s.Post(id, []byte("small"), now); got != reject.SignalStored {
					t.Errorf("Post after an oversized rejection = %s, want SignalStored", reasonString(got))
				}
				return
			}
			blob2, reason := s.Get(context.Background(), id, now)
			if reason != reject.SignalDelivered || len(blob2) != tt.size {
				t.Errorf("Get = %d bytes, %s, want %d bytes delivered", len(blob2), reasonString(reason), tt.size)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 12. channel_id validation (§5.4)
// ---------------------------------------------------------------------------

func TestMalformedChannelIDIsRejected(t *testing.T) {
	noGoroutineLeak(t)

	valid := chanID(30)
	padded := b64.Encode(make([]byte, ChannelIDBytes)) + "="

	tests := []struct {
		name string
		id   string
	}{
		{"empty", ""},
		{"too short by one character", valid[:len(valid)-1]},
		{"too long by one character", valid + "A"},
		{"31 bytes encoded", b64.Encode(make([]byte, 31))},
		{"33 bytes encoded", b64.Encode(make([]byte, 33))},
		{"padded to 44 characters", padded},
		{"standard base64 alphabet, plus", strings.Replace(valid, valid[2:3], "+", 1)},
		{"standard base64 alphabet, slash", strings.Replace(valid, valid[2:3], "/", 1)},
		{"non-alphabet character", valid[:42] + "!"},
		// The base64 decoder skips newlines, so this decodes to 31 bytes
		// rather than failing on the character. The length check catches it.
		{"embedded newline", valid[:20] + "\n" + valid[21:]},
		{"path traversal attempt", strings.Repeat(".", ChannelIDChars)},
		{"whitespace", valid[:42] + " "},
	}

	s := fastPoll(20 * time.Millisecond)
	defer s.Shutdown()
	now := time.Unix(1753488000, 0)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.Post(tt.id, []byte("blob"), now); got != reject.SignalBadChannel {
				t.Errorf("Post = %s, want SignalBadChannel", reasonString(got))
			}
			if _, got := s.Get(context.Background(), tt.id, now); got != reject.SignalBadChannel {
				t.Errorf("Get = %s, want SignalBadChannel", reasonString(got))
			}
		})
	}

	// A malformed identifier is rejected before the size check, so an
	// oversized body on a bad channel still draws 400 rather than 413 — the
	// identifier is the cheaper check and the more specific fault.
	if got := s.Post("nonsense", bytes.Repeat([]byte{0}, MaxBlobBytes+1), now); got != reject.SignalBadChannel {
		t.Errorf("Post with a bad id and an oversized body = %s, want SignalBadChannel", reasonString(got))
	}

	// Nothing above created a channel.
	s.mu.Lock()
	created := len(s.channels)
	s.mu.Unlock()
	if created != 0 {
		t.Errorf("%d channels created by malformed identifiers, want 0", created)
	}
}

func TestWellFormedChannelIDIsAccepted(t *testing.T) {
	noGoroutineLeak(t)

	s := fastPoll(20 * time.Millisecond)
	defer s.Shutdown()
	now := time.Unix(1753488000, 0)

	// Every byte value appears across these, including the encodings that
	// exercise '-' and '_'.
	raw := make([]byte, ChannelIDBytes)
	for i := 0; i < 8; i++ {
		for j := range raw {
			raw[j] = byte(i*32 + j)
		}
		id := b64.Encode(raw)
		if len(id) != ChannelIDChars {
			t.Fatalf("test vector is %d characters, want %d", len(id), ChannelIDChars)
		}
		if got := s.Post(id, []byte("blob"), now); got != reject.SignalStored {
			t.Errorf("Post to %d = %s, want SignalStored", i, reasonString(got))
		}
	}
}

// ---------------------------------------------------------------------------
// 13. The body is opaque (§5.4)
// ---------------------------------------------------------------------------

func TestBodyIsOpaqueAndRoundTripsUnchanged(t *testing.T) {
	noGoroutineLeak(t)

	binary := make([]byte, 512)
	for i := range binary {
		binary[i] = byte(i)
	}

	tests := []struct {
		name string
		blob []byte
	}{
		{"not JSON at all", []byte("{this is not json")},
		{"bare ephemeral public key, as PAIRING-SPEC.md §6.3 posts it", bytes.Repeat([]byte{0x9F}, 32)},
		{"arbitrary binary including NUL and invalid UTF-8", append(binary, 0xFF, 0xFE, 0x00)},
		{"JSON-looking but semantically empty", []byte("{}")},
		{"leading and trailing whitespace preserved", []byte("  \n\t body \r\n ")},
		{"empty body", []byte{}},
	}

	s := fastPoll(20 * time.Millisecond)
	defer s.Shutdown()
	now := time.Unix(1753488000, 0)

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := chanID(byte(70 + i))
			if got := s.Post(id, tt.blob, now); got != reject.SignalStored {
				t.Fatalf("Post = %s, want SignalStored", reasonString(got))
			}
			got, reason := s.Get(context.Background(), id, now)
			if reason != reject.SignalDelivered {
				t.Fatalf("Get = %s, want SignalDelivered", reasonString(reason))
			}
			if !bytes.Equal(got, tt.blob) {
				t.Errorf("round trip changed the body: got %q, want %q", got, tt.blob)
			}
		})
	}
}

// The store copies on Post, so a caller reusing its read buffer cannot mutate
// a blob it has already handed over.
func TestPostCopiesTheCallersBuffer(t *testing.T) {
	noGoroutineLeak(t)

	s := fastPoll(20 * time.Millisecond)
	defer s.Shutdown()
	id := chanID(80)
	now := time.Unix(1753488000, 0)

	buf := []byte("original")
	s.Post(id, buf, now)
	copy(buf, "OVERWRIT")

	got, reason := s.Get(context.Background(), id, now)
	if reason != reject.SignalDelivered {
		t.Fatalf("Get = %s, want SignalDelivered", reasonString(reason))
	}
	if !bytes.Equal(got, []byte("original")) {
		t.Errorf("stored blob is %q, want %q: the store aliased the caller's buffer", got, "original")
	}
}

// ---------------------------------------------------------------------------
// 14. No logging (CLAUDE.md, DIRECTORY-SPEC.md §9)
// ---------------------------------------------------------------------------

// The code to log must not exist — not disabled, not behind a flag, absent. A
// channel_id is derived from a user's selector code, so it is exactly the kind
// of identifier that must never reach a log.
func TestPackageImportsNoLogger(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}

	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		path := filepath.Join(".", e.Name())
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parsing %s: %v", e.Name(), err)
		}
		checked++
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("unquoting an import path in %s: %v", e.Name(), err)
			}
			base := p
			if i := strings.LastIndex(p, "/"); i >= 0 {
				base = p[i+1:]
			}
			if base == "log" || base == "slog" || strings.HasPrefix(p, "log/") {
				t.Errorf("%s imports %q: this package must contain no logging code", e.Name(), p)
			}
		}
	}
	if checked < 2 {
		t.Fatalf("checked %d files, expected at least the store and its tests", checked)
	}
}

// ---------------------------------------------------------------------------
// Race-detector fodder: the whole surface under concurrent use.
// ---------------------------------------------------------------------------

func TestConcurrentPostAndGet(t *testing.T) {
	noGoroutineLeak(t)

	const (
		channels = 16
		posters  = 4
		readers  = 4
	)

	s := New(Options{PollWindow: 200 * time.Millisecond, MaxWaitersPerChannel: readers})
	defer s.Shutdown()
	now := time.Unix(1753488000, 0)

	var wg sync.WaitGroup
	for c := 0; c < channels; c++ {
		id := chanID(byte(c))
		for p := 0; p < posters; p++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s.Post(id, []byte("blob"), now)
			}()
		}
		for r := 0; r < readers; r++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				blob, reason := s.Get(context.Background(), id, now)
				if reason == reject.SignalDelivered && !bytes.Equal(blob, []byte("blob")) {
					t.Errorf("delivered %q, want %q", blob, "blob")
				}
			}()
		}
	}
	wg.Wait()

	s.Shutdown()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.waiting != 0 {
		t.Errorf("%d waiters left after Shutdown, want 0", s.waiting)
	}
}
