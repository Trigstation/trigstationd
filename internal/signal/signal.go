// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

// Package signal implements the in-memory signal channel store of
// DIRECTORY-SPEC.md §5.4: a short-lived rendezvous for two parties who already
// share a secret but cannot reach each other directly.
//
// The store holds one opaque blob per channel, delivers it to exactly one
// reader, and forgets it. Nothing here is persisted (§9), nothing here is
// parsed, and nothing here is logged.
//
// # What the store must not do
//
// It must not interpret the body. Blobs are usually ciphertext, but
// PAIRING-SPEC.md §6.3 legitimately posts bare ephemeral public keys, so any
// content sniffing would reject a conforming exchange. Post takes []byte and
// Get returns the same bytes; no code path between them looks at them.
//
// It must not name a channel. A channel_id is derived from a user's selector
// code (PAIRING-SPEC.md §6.3) or generated as a one-time reply address (§5.4),
// so it is a rendezvous secret in exactly the way a lookup_id is not. Every
// rejection here is a bare reject.SignalReason carrying no value, for the same
// reason the record path returns no diagnostic detail.
//
// # Ownership rules
//
// Post copies the blob it is given, so a caller may reuse its read buffer. Get
// transfers ownership of the stored slice to the caller and drops the store's
// reference to it: delivery is destructive, and the blob exists in one place at
// a time.
//
// # Concurrency
//
// One mutex guards the whole store. The workload is a map lookup and a channel
// send per operation, so finer-grained locking would buy nothing measurable and
// cost the property that makes this reviewable: every transition — store,
// deliver, register a waiter, release a waiter, expire, shut down — happens in
// one critical section, and membership of a channel's waiter set is the single
// source of truth for whether a waiter has been handed a blob.
//
// A waiter is a struct in that set, never a goroutine of the store's own. The
// goroutine doing the waiting is the caller's, blocked in Get. The store
// therefore has no goroutines to leak; what it must guarantee instead is that
// every waiter is removed from the set on every exit path, which
// releaseLocked centralises.
package signal

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/trigstation/trigstationd/internal/b64"
	"github.com/trigstation/trigstationd/internal/reject"
)

// Wire-format and limit constants from DIRECTORY-SPEC.md §4.3 and §5.4. These
// are the spec's ceilings, not preferences: Options may lower them, never
// raise them.
const (
	// ChannelIDBytes is the decoded width of a channel_id: "32 bytes,
	// base64url" (§5.4).
	ChannelIDBytes = 32

	// ChannelIDChars is the encoded width, unpadded: 43 characters. §4.4
	// requires unpadded base64url, so a padded 44-character spelling is not a
	// conforming channel_id and draws SignalBadChannel.
	ChannelIDChars = 43

	// MaxBlobBytes is the signal channel payload limit of §4.3: 64 KB.
	MaxBlobBytes = 64 << 10

	// MaxTTL is the signal channel TTL of §4.3: 300 seconds.
	//
	// The figure matches the device-pairing selector lifetime of
	// PAIRING-SPEC.md §6.6. A shorter TTL would expire the channel while the
	// on-screen code was still live, which is why this is a protocol constant
	// and not a tuning knob.
	MaxTTL = 300 * time.Second

	// MaxPollWindow is the long-poll ceiling of §5.4: "A directory MUST NOT
	// hold a long-poll open for longer than 30 seconds, and SHOULD hold it for
	// the full 30 unless a blob arrives or the client disconnects."
	MaxPollWindow = 30 * time.Second
)

// Waiter caps. An unbounded waiter set is a memory exhaustion vector on a
// service with no accounts, so both a global and a per-channel bound are
// enforced. Reaching either rejects rather than queues.
const (
	// DefaultMaxWaiters bounds concurrent long-polls across the whole
	// instance.
	//
	// A waiter costs the store almost nothing — a small struct and a
	// single-element channel — but each one pins a caller's goroutine and,
	// above this layer, an open connection with its read and write buffers.
	// Connection state, at a few KB apiece, is what actually sizes this: 10,000
	// concurrent long-polls is on the order of tens of MB, which is within the
	// small VPS §9.1 budgets an instance at, and beyond the point where an
	// instance that keeps accepting is doing its operator a favour.
	DefaultMaxWaiters = 10_000

	// DefaultMaxWaitersPerChannel bounds concurrent long-polls on one channel.
	//
	// A channel has two legitimate participants and only one of them polls:
	// PAIRING-SPEC.md §6.3 has a single device polling each of its three
	// channels, and the ICE exchange of §5.4 has the server polling its
	// MailboxID and one client polling its reply channel. Eight leaves room for
	// a reconnect racing the connection it replaces, and for a client running
	// on more than one device, while ensuring one guessed channel identifier
	// cannot consume the global budget: exhausting it would take 1,250 distinct
	// channels rather than one.
	DefaultMaxWaitersPerChannel = 8
)

// minSweepChannels is the floor below which the opportunistic sweep does not
// run. It is a memory reclamation threshold and has no observable effect: an
// expired blob is absent from a Get whether or not a sweep has reached it
// (DECISIONS.md D-7, applied here by analogy with §5.2).
const minSweepChannels = 1024

// Options configures a Store. The zero value gives the spec defaults, which is
// the configuration a directory should be running.
//
// Values above a §4.3 or §5.4 ceiling are clamped down to it rather than
// honoured or rejected. A directory holding a long-poll for 45 seconds, or
// accepting a 128 KB blob, would be non-conforming, and a config file is not
// the place that gets decided.
type Options struct {
	// TTL is how long a stored blob remains available. Clamped to MaxTTL.
	TTL time.Duration

	// PollWindow is how long a Get with no blob waits for one. Clamped to
	// MaxPollWindow.
	PollWindow time.Duration

	// MaxBlobBytes is the largest accepted body. Clamped to MaxBlobBytes.
	MaxBlobBytes int

	// MaxWaiters bounds concurrent long-polls instance-wide.
	MaxWaiters int

	// MaxWaitersPerChannel bounds concurrent long-polls on one channel.
	MaxWaitersPerChannel int
}

// waiter is one caller blocked in Get.
//
// delivered and active are guarded by Store.mu, never by the waiter itself.
// active means "counted in Store.waiting and present in its channel's waiter
// set"; delivered means "a blob has been handed to c". They are separate
// because a waiter that is no longer active may have been released either by a
// delivery or by Shutdown, and the two exit paths differ.
type waiter struct {
	c         chan []byte
	delivered bool
	active    bool
}

// channel is one rendezvous point. It holds at most one blob, because §5.4 is
// first-write-wins: a second blob is never accepted, so a queue would have no
// occupant.
type channel struct {
	blob      []byte
	expiresAt time.Time
	waiters   map[*waiter]struct{}
}

// held reports whether the channel holds a blob that has not expired at now.
//
// Expiry is evaluated here, from the blob and the clock, and nowhere else. An
// expired blob is absent for every purpose whether or not a sweep has run.
func (ch *channel) held(now time.Time) bool {
	return ch.blob != nil && now.Before(ch.expiresAt)
}

// Store is the in-memory signal channel store. The zero value is not usable;
// call New.
type Store struct {
	ttl        time.Duration
	poll       time.Duration
	maxBlob    int
	maxWaiters int
	maxPerChan int

	mu       sync.Mutex
	channels map[string]*channel
	waiting  int
	sweepAt  int
	closed   bool
	done     chan struct{}
}

// New returns a Store configured by opts, with spec defaults for anything
// unset.
func New(opts Options) *Store {
	s := &Store{
		ttl:        clampDuration(opts.TTL, MaxTTL),
		poll:       clampDuration(opts.PollWindow, MaxPollWindow),
		maxBlob:    opts.MaxBlobBytes,
		maxWaiters: opts.MaxWaiters,
		maxPerChan: opts.MaxWaitersPerChannel,
		channels:   make(map[string]*channel),
		sweepAt:    minSweepChannels,
		done:       make(chan struct{}),
	}
	if s.maxBlob <= 0 || s.maxBlob > MaxBlobBytes {
		s.maxBlob = MaxBlobBytes
	}
	if s.maxWaiters <= 0 {
		s.maxWaiters = DefaultMaxWaiters
	}
	if s.maxPerChan <= 0 {
		s.maxPerChan = DefaultMaxWaitersPerChannel
	}
	return s
}

func clampDuration(d, max time.Duration) time.Duration {
	if d <= 0 || d > max {
		return max
	}
	return d
}

// Post stores blob on the channel named by id, per DIRECTORY-SPEC.md §5.4.
//
// First write wins. A POST to a channel already holding an unexpired blob is
// rejected with reject.SignalConflict and the stored blob is left untouched.
// This is a security property rather than an error case: under overwrite
// semantics anyone who guessed or observed a channel identifier could replace a
// legitimate blob and turn the rendezvous into an injection point, whereas
// failing closed reduces that to a denial of service the participants detect
// immediately.
//
// If a reader is already long-polling the channel the blob is handed straight
// to one of them and never stored. The channel is then empty, so an immediately
// following Post is accepted — correctly, because the first blob was delivered
// and delivery is destructive. A poster cannot distinguish this from the reader
// arriving a moment later, and neither can an observer.
//
// now is the directory's current time; expiry is computed from it rather than
// read from a clock inside the store.
func (s *Store) Post(id string, blob []byte, now time.Time) reject.SignalReason {
	key, ok := decodeChannelID(id)
	if !ok {
		return reject.SignalBadChannel
	}
	if len(blob) > s.maxBlob {
		return reject.SignalTooLarge
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		// The store has been shut down and cannot deliver this blob to
		// anybody. Answering "stored" would be a lie the poster acts on; 429
		// is the one outcome in the §5.4 table whose remedy — back off, retry,
		// try elsewhere — is the correct thing for the client to do. See the
		// note in the package report: the spec does not cover an instance
		// draining.
		return reject.SignalRateLimited
	}

	if len(s.channels) >= s.sweepAt {
		s.sweepLocked(now)
	}

	ch := s.channels[key]
	if ch != nil && ch.held(now) {
		return reject.SignalConflict
	}
	if ch == nil {
		ch = &channel{waiters: make(map[*waiter]struct{})}
		s.channels[key] = ch
	} else {
		// Anything still here got past the conflict check, so it has expired.
		// Dropping it now keeps gcLocked able to reclaim the channel and keeps
		// a dead blob from outliving its TTL in memory.
		ch.blob = nil
	}

	// Copy, so that a caller reusing its read buffer cannot mutate a stored
	// blob, and so that a 64 KB read buffer backing a 40-byte blob is not
	// retained for the whole TTL.
	stored := make([]byte, len(blob))
	copy(stored, blob)

	if w := s.takeWaiterLocked(ch); w != nil {
		w.delivered = true
		w.c <- stored // buffered, capacity 1, sent to at most once
		s.gcLocked(key, ch)
		return reject.SignalStored
	}

	ch.blob = stored
	ch.expiresAt = now.Add(s.ttl)
	return reject.SignalStored
}

// Get delivers the blob on the channel named by id, per DIRECTORY-SPEC.md
// §5.4, removing it: delivery is destructive, so of two concurrent Gets on one
// blob exactly one returns it.
//
// With no blob present the call long-polls for up to the configured window,
// which never exceeds the 30 seconds §5.4 permits, and then returns
// reject.SignalEmpty — 204, deliberately not 404, because the client's correct
// response to 204 is to poll again and its correct response to 404 is to try a
// different directory (DECISIONS.md D-14).
//
// The wait ends early when ctx is cancelled, which is how a disconnected client
// releases its waiter, and when the store is shut down. Both return
// SignalEmpty; §5.4 requires clients to tolerate an earlier 204.
//
// One race is resolved in the caller's favour: if a blob is handed over at the
// same moment ctx is cancelled, the blob is returned. It has already been
// removed from the channel by the poster, and re-storing it would resurrect a
// blob into a channel a later poster may by then legitimately hold.
//
// now is the directory's current time and is used to evaluate expiry at the
// moment of the call.
func (s *Store) Get(ctx context.Context, id string, now time.Time) ([]byte, reject.SignalReason) {
	key, ok := decodeChannelID(id)
	if !ok {
		return nil, reject.SignalBadChannel
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, reject.SignalEmpty
	}

	ch := s.channels[key]
	if ch != nil {
		if ch.held(now) {
			blob := ch.blob
			ch.blob = nil
			s.gcLocked(key, ch)
			s.mu.Unlock()
			return blob, reject.SignalDelivered
		}
		// Present but expired: absent for every purpose, and worth dropping
		// while the lock is held.
		ch.blob = nil
	}

	w, reason := s.registerLocked(key, ch)
	if w == nil {
		s.mu.Unlock()
		return nil, reason
	}
	ch = s.channels[key]
	s.mu.Unlock()

	timer := time.NewTimer(s.poll)
	defer timer.Stop()

	select {
	case blob := <-w.c:
		return blob, reject.SignalDelivered
	case <-timer.C:
	case <-ctx.Done():
	case <-s.done:
	}

	// Every losing path converges here, so a waiter is removed from the set
	// exactly once however it stopped waiting.
	s.mu.Lock()
	if w.delivered {
		s.mu.Unlock()
		return <-w.c, reject.SignalDelivered
	}
	s.releaseLocked(key, ch, w)
	s.mu.Unlock()
	return nil, reject.SignalEmpty
}

// Shutdown releases every waiter and drops every stored blob. In-flight
// long-polls return promptly with reject.SignalEmpty rather than running to
// their deadline, so a graceful shutdown never waits 30 seconds on an idle
// poll.
//
// It is idempotent, and it does not wait for the released callers to finish
// returning; there is nothing for them to finish that the store owns.
func (s *Store) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}
	s.closed = true
	close(s.done)

	for key, ch := range s.channels {
		for w := range ch.waiters {
			w.active = false
			delete(ch.waiters, w)
		}
		delete(s.channels, key)
	}
	s.waiting = 0
}

// registerLocked adds a waiter for key, or returns the reason it will not.
//
// ch may be nil, meaning the channel does not exist yet; it is created only
// once the caps have been cleared, so a rejected waiter leaves no trace.
func (s *Store) registerLocked(key string, ch *channel) (*waiter, reject.SignalReason) {
	if s.waiting >= s.maxWaiters {
		return nil, reject.SignalRateLimited
	}
	if ch != nil && len(ch.waiters) >= s.maxPerChan {
		return nil, reject.SignalRateLimited
	}
	if ch == nil {
		ch = &channel{waiters: make(map[*waiter]struct{})}
		s.channels[key] = ch
	}
	w := &waiter{c: make(chan []byte, 1), active: true}
	ch.waiters[w] = struct{}{}
	s.waiting++
	return w, reject.SignalEmpty
}

// releaseLocked removes a waiter that was not delivered to. It is safe to call
// on a waiter Shutdown has already released.
func (s *Store) releaseLocked(key string, ch *channel, w *waiter) {
	if !w.active {
		return
	}
	w.active = false
	delete(ch.waiters, w)
	s.waiting--
	s.gcLocked(key, ch)
}

// takeWaiterLocked removes and returns one waiter from ch, or nil if it has
// none. Which one is unspecified: the participants of a channel are peers, and
// §5.4 promises delivery to exactly one reader, not to a particular reader.
func (s *Store) takeWaiterLocked(ch *channel) *waiter {
	for w := range ch.waiters {
		w.active = false
		delete(ch.waiters, w)
		s.waiting--
		return w
	}
	return nil
}

// gcLocked drops a channel that holds neither a blob nor a waiter.
//
// The identity of the channel struct matters: a waiter holds a pointer to it,
// so a channel with waiters must never be replaced, or a blob posted to the
// replacement would be delivered to nobody. Holding a waiter is therefore part
// of the condition, not just holding a blob.
func (s *Store) gcLocked(key string, ch *channel) {
	if ch.blob == nil && len(ch.waiters) == 0 {
		delete(s.channels, key)
	}
}

// sweepLocked reclaims channels whose blob has expired and which nobody is
// waiting on.
//
// It is memory reclamation and nothing else. Expiry is decided by
// channel.held, so an expired blob is already absent from a Get that arrives
// before the sweep does; running or not running this changes no observable
// behaviour. It is driven by the size of the map rather than by a timer, so the
// store needs no goroutine and no clock of its own, and the amortised cost is
// constant per Post.
func (s *Store) sweepLocked(now time.Time) {
	for key, ch := range s.channels {
		if len(ch.waiters) == 0 && !ch.held(now) {
			delete(s.channels, key)
		}
	}
	s.sweepAt = 2 * len(s.channels)
	if s.sweepAt < minSweepChannels {
		s.sweepAt = minSweepChannels
	}
}

// decodeChannelID validates a channel_id and returns the map key for it.
//
// §5.4 requires "exactly 32 bytes of unpadded base64url", so the encoded form
// is exactly 43 characters with no '='. b64.Decode tolerates padding on input
// for the wire fields, which is right there and wrong here: the status table
// makes a padded channel_id a 400, and tolerating it would also give one
// rendezvous two spellings.
//
// The key is the decoded 32 bytes rather than the text, so that any two
// spellings which denote the same channel are the same channel. Keying on text
// would let a non-canonical encoding of the same 32 bytes address a channel of
// its own, quietly outside the first-write-wins rule that protects the real
// one.
func decodeChannelID(id string) (string, bool) {
	if len(id) != ChannelIDChars || strings.ContainsRune(id, '=') {
		return "", false
	}
	raw, err := b64.DecodeFixed(id, ChannelIDBytes)
	if err != nil {
		return "", false
	}
	return string(raw), true
}
