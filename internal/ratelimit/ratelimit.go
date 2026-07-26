// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

// Package ratelimit implements the per-source rate limits of
// DIRECTORY-SPEC.md §6.2, under the constraints §6.4 places on them.
//
// This is the only place in the service that handles a client address at all.
// Everywhere else the "no request logging" requirement of §9 is satisfied by
// there being nothing to log; here two requirements meet head on. The service
// must resist flooding, and the service must not retain client addresses. §6.4
// resolves that and is normative:
//
//   - The source address MUST NOT be written to disk, to a log, or to any
//     output stream, at any severity, under any configuration.
//   - Limiter state MUST be held in memory only and MUST be discarded when its
//     window elapses.
//   - State MUST be keyed by a truncated form of the address — IPv4 to /24,
//     IPv6 to /64 — not by the full address and not by a hash of it.
//   - No code path may exist that emits either the key or the untruncated
//     address.
//
// # How those constraints shape this package
//
// Truncation, not hashing. A hash of an IPv4 address is not a mitigation: the
// space is 32 bits and any hash of it is reversed by enumeration in seconds.
// Truncation destroys the information instead of obscuring it. makeKey is the
// only function that touches an address, and it discards the host bits before
// returning.
//
// Nothing here can render anything. The implementation imports net/netip, sync
// and time, and nothing else. There is no fmt, no log, no os, no io — no
// facility exists in this package with which an address could reach an output
// stream, at any severity, under any configuration. TestImportsAreAllowlisted
// holds that true after review.
//
// No type declared here has a String, Error or Marshal method, so no value of
// this package renders itself. That matters most for the map key: netip.Addr
// and netip.Prefix are both Stringers, so using either as the key type would
// have made every stray %v a disclosure in dotted-quad. The key type below has
// no methods at all.
//
// The keys are held behind a pointer. fmt dereferences pointers only at the top
// level of an argument, so fmt.Sprintf("%v", limiter) in some future debugging
// session prints an opaque machine address for the state field rather than
// walking the map and rendering every truncated network it holds.
//
// The package returns no errors. Allow answers with a bool, and the caller maps
// false onto reject.RecordRateLimited or reject.SignalRateLimited. An error
// value is a string that travels, and the one thing this package knows is the
// one thing that must not travel.
//
// # Windowing
//
// A fixed window per key: a counter and the instant the window opened. §6.4
// requires state to be "discarded when its window elapses", and a fixed window
// makes that literal — once the window has elapsed the entry carries no
// information about the interval that follows, and it is deleted rather than
// decayed. A sliding-window log would instead retain a timestamp per request
// for the length of the window, which is strictly more address-derived state
// for a smoothness this service does not need.
//
// The known cost of a fixed window is that a client may issue up to twice the
// limit across a window boundary. That is tolerable here and only here: §6.4
// requires limits set generously rather than tightly, because a /24 bucket is
// up to 256 hosts, and §9.1 puts honest publish volume at around one request
// per server per day against a limit of 120 per hour.
//
// Windows are per key rather than globally aligned, so buckets do not all roll
// over on the same instant and a flooder cannot synchronise a burst to it.
//
// # Time
//
// The caller supplies now. Nothing here calls time.Now, which keeps the
// decision path free of a syscall and lets a test cover an hour-long window
// without taking an hour.
package ratelimit

import (
	"net/netip"
	"sync"
	"time"
)

// Class is the group of operations a limit applies to. DIRECTORY-SPEC.md §6.2
// calls for per-source limits on PUT and GET; §5.4 gives the signal channels a
// single 429 row covering both POST and GET, so they share one allowance.
//
// The zero value is ClassPutRecord. A Class outside the declared set is refused
// by Allow rather than admitted, so a future operation added without a limit
// fails closed instead of becoming an unmetered path.
type Class int

const (
	// ClassPutRecord is PUT /v1/record (§5.2).
	ClassPutRecord Class = iota

	// ClassGetRecord is GET /v1/record (§5.3).
	ClassGetRecord

	// ClassSignal is POST and GET on /v1/signal/{channel_id} (§5.4), counted
	// together against one allowance.
	ClassSignal

	numClasses
)

// Defaults. These follow from §9.1: publishes are roughly one per server per
// day and lookups a few per user per day, so every limit here sits orders of
// magnitude above honest use. §6.4 requires exactly that — a /24 key means up
// to 256 hosts share a bucket, and a server behind carrier-grade NAT must not
// be limited by a stranger's behaviour.
const (
	// DefaultPutRecord is 120 publishes per key per window. An honest server
	// publishes on daily epoch rollover, on address change, and on a 6-hourly
	// keepalive: a handful per day, not per hour.
	DefaultPutRecord = 120

	// DefaultGetRecord is 600 lookups per key per window. A lookup happens
	// about once per session (§2), so this is five per minute sustained.
	DefaultGetRecord = 600

	// DefaultSignal is 600 signal operations per key per window, POST and GET
	// combined. Signalling is bursty by nature — PAIRING-SPEC.md §6.3 has both
	// devices polling — so it is set level with lookups rather than below.
	DefaultSignal = 600

	// DefaultWindow is the interval each limit is counted over.
	DefaultWindow = time.Hour

	// DefaultMaxKeys bounds the number of tracked keys, and so the memory an
	// adversary can cause this package to hold. See Options.MaxKeys.
	//
	// §9.1 puts the reference load at ~6 publishes/s and ~20 lookups/s average,
	// or under 100,000 distinct keys in an hour even if every request came from
	// a different /24. Half a million is several times that headroom for about
	// 25 MB.
	DefaultMaxKeys = 500_000
)

// sweepDivisor sets how often the amortised sweep runs, as a fraction of the
// window: at the default that is once every 7.5 minutes of caller-supplied
// time.
//
// The sweep is what discharges the §6.4 obligation to discard state when its
// window elapses. It must not depend on the caller remembering to call Sweep,
// because a limiter whose operator forgot would retain address-derived state
// indefinitely — so Allow runs it too, on the clock the caller passes in. The
// cost is one O(n) pass under the mutex per interval, amortised across every
// request in it.
const sweepDivisor = 8

// Options configures a Limiter. The zero value is valid and selects every
// default.
type Options struct {
	// PutRecord, GetRecord and Signal are the requests permitted per key per
	// Window for each class. A value of zero or less selects the default.
	//
	// There is deliberately no way to express "refuse everything". §6.4 ends by
	// ranking these against each other: abuse resistance is a defence, but
	// being unable to serve records is not a state this service should be
	// configurable into.
	PutRecord int
	GetRecord int
	Signal    int

	// Window is the interval each limit is counted over. Zero or less selects
	// DefaultWindow.
	Window time.Duration

	// MaxKeys bounds the number of tracked keys. Zero or less selects
	// DefaultMaxKeys.
	//
	// The bound is not optional: a map keyed by attacker-chosen /24s is itself
	// a memory exhaustion vector, and unbounded growth would also mean holding
	// address-derived state well past the window §6.4 allots it.
	//
	// At the bound, a request from a key that is already tracked is served
	// normally, and a request from a new key is refused after one attempt to
	// reclaim elapsed entries. See Allow.
	MaxKeys int
}

// key is the truncated address a limit is counted against, together with the
// class it applies to.
//
// It is unexported, has no methods, appears in no exported signature, and is
// never returned, copied out or ranged over outside this file. net holds the
// network bits only — the host bits are gone before the value exists, so even
// the in-memory form cannot identify a host.
//
// Do not give this type a String method, and do not use netip.Addr or
// netip.Prefix in its place: both are Stringers, and a Stringer here turns
// every %v anywhere in the program into a disclosure of the caller's network.
type key struct {
	net [16]byte // network bits, host bits zeroed
	// family distinguishes a truncated IPv4 network from a truncated IPv6 one
	// and marks an address that could not be parsed, so that the three can
	// never collide: 4, 6, or 0.
	family uint8
	class  uint8
}

// counter is the per-key state: when the current window opened and how many
// requests have been admitted in it. It holds no address material, by design —
// everything identifying lives in the map key, which is unreachable from
// outside this file.
type counter struct {
	start time.Time
	n     int
}

// table is the limiter state, and the mutex guarding it.
//
// It is held behind a pointer from Limiter so that a stray fmt verb applied to
// a Limiter renders an opaque machine address here rather than walking the map:
// fmt dereferences only at the top level of an argument. Keeping the mutex on
// this side of the pointer rather than on Limiter is part of the same measure —
// it leaves Limiter free of anything vet must forbid copying, so that no
// diagnostic use of a Limiter value is ever tempting enough to reach for the
// state directly.
type table struct {
	mu        sync.Mutex
	keys      map[key]counter
	nextSweep time.Time
}

// Limiter enforces the §6.2 limits. It is safe for concurrent use; Allow is
// called on every request from many goroutines.
//
// One mutex covers the whole table. The decision path under it is a map lookup
// and an integer compare, which is orders of magnitude cheaper than the ~200
// requests per second §9.1 gives as the peak for the reference load.
//
// The zero value is not usable — construct one with New. Every method checks
// for it and refuses rather than panicking, because a panic in this package
// would print a goroutine trace, and a goroutine trace prints the arguments of
// the frames in it. §6.4 admits no exception for a crash.
type Limiter struct {
	limits        [numClasses]int
	window        time.Duration
	sweepInterval time.Duration
	maxKeys       int

	state *table
}

// New returns a Limiter configured by opts, with defaults substituted for any
// field left at zero.
func New(opts Options) *Limiter {
	l := &Limiter{
		window:  orDurationDefault(opts.Window, DefaultWindow),
		maxKeys: orIntDefault(opts.MaxKeys, DefaultMaxKeys),
		state:   &table{keys: make(map[key]counter)},
	}
	l.limits[ClassPutRecord] = orIntDefault(opts.PutRecord, DefaultPutRecord)
	l.limits[ClassGetRecord] = orIntDefault(opts.GetRecord, DefaultGetRecord)
	l.limits[ClassSignal] = orIntDefault(opts.Signal, DefaultSignal)

	l.sweepInterval = l.window / sweepDivisor
	if l.sweepInterval <= 0 {
		l.sweepInterval = l.window
	}
	return l
}

func orIntDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func orDurationDefault(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

// Allow reports whether a request of class c from addr may proceed at now.
//
// The caller maps false onto reject.RecordRateLimited or
// reject.SignalRateLimited. Nothing is returned that would let a caller
// reconstruct which key was consulted, and there is no diagnostic variant of
// this method for the same reason.
//
// addr is truncated to its /24 or /64 before anything is stored. An IPv4-mapped
// IPv6 address is unmapped first, so a client reaching a dual-stack listener is
// counted at the same granularity as one reaching an IPv4 listener rather than
// being handed a /64 of its own.
//
// An address that does not parse, and a class outside the declared set, are
// both refused rather than admitted: an unmetered path is worth more to a
// flooder than a rejection is worth to anyone else.
//
// now is supplied by the caller. Allow never reads the clock itself.
func (l *Limiter) Allow(addr netip.Addr, c Class, now time.Time) bool {
	if c < 0 || c >= numClasses {
		return false
	}
	if !addr.IsValid() {
		return false
	}
	limit := l.limits[c]
	if limit < 1 {
		return false // a Limiter that did not come from New
	}
	t := l.state
	if t == nil {
		return false // as above
	}
	k := makeKey(addr, c)

	t.mu.Lock()
	defer t.mu.Unlock()

	swept := false
	if !now.Before(t.nextSweep) {
		t.sweepLocked(now, l.window, l.sweepInterval)
		swept = true
	}

	cur, tracked := t.keys[k]
	if tracked && live(cur.start, now, l.window) {
		if cur.n >= limit {
			return false
		}
		cur.n++
		t.keys[k] = cur
		return true
	}

	// Either the key is new, or its window has elapsed and the entry is about
	// to be replaced rather than kept. Only the first case can grow the table.
	if !tracked && len(t.keys) >= l.maxKeys {
		// A new key at the bound. Reclaim whatever has elapsed and try once
		// more; if the table is genuinely full of live keys, refuse.
		//
		// Refusing is the lesser of two bad options and worth stating plainly.
		// Admitting instead would mean an adversary holding MaxKeys distinct
		// networks could switch the limiter off for everyone, which is the
		// exact scenario it exists for. Refusing means that adversary can
		// instead deny service to keys not yet in the table, but keys already
		// tracked keep being served, the table cannot grow, and the condition
		// clears within one window. Neither §6.4 nor §6.2 settles this.
		if !swept {
			t.sweepLocked(now, l.window, l.sweepInterval)
		}
		if len(t.keys) >= l.maxKeys {
			return false
		}
	}

	t.keys[k] = counter{start: now, n: 1}
	return true
}

// Sweep discards every key whose window has elapsed at now.
//
// Allow sweeps on the same schedule from inside the decision path, so under
// traffic no entry outlives its window by more than one sweep interval whether
// or not this is called. What Allow cannot cover is an instance that goes quiet:
// with no requests there is nothing to drive the discard, and the last few keys
// would sit in memory until the next one arrives. An operator's periodic call to
// Sweep closes that, and is the reason this method is exported rather than being
// an implementation detail.
func (l *Limiter) Sweep(now time.Time) {
	t := l.state
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweepLocked(now, l.window, l.sweepInterval)
}

// sweepLocked deletes every elapsed entry and schedules the next pass. The
// caller holds t.mu.
func (t *table) sweepLocked(now time.Time, window, interval time.Duration) {
	for k, cur := range t.keys {
		if !live(cur.start, now, window) {
			delete(t.keys, k)
		}
	}
	t.nextSweep = now.Add(interval)
}

// TrackedKeys returns how many keys currently hold state. It is an aggregate
// count and reveals nothing about any key; it exists so that eviction is
// testable and so that an operator sizing MaxKeys has something to size
// against.
func (l *Limiter) TrackedKeys() int {
	t := l.state
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.keys)
}

// live reports whether a window opened at start is still the current one at
// now.
//
// The comparison is on the absolute difference. A window that appears to open
// in the future is the result of the wall clock being stepped backwards; within
// one window that is treated as current, which counts the requests against the
// client, and beyond it the entry is discarded rather than being stranded live
// for as long as the step. §6.4 gives state one window, and a clock adjustment
// is not a reason to extend it.
func live(start, now time.Time, window time.Duration) bool {
	d := now.Sub(start)
	if d < 0 {
		d = -d
	}
	return d < window
}

// makeKey truncates addr to the key §6.4 mandates: IPv4 to /24, IPv6 to /64.
//
// The host bits are discarded here and nowhere else. Once this function
// returns, the untruncated address exists only in the caller's own variable and
// has never been stored.
//
// Unmap runs first. A client arriving over a dual-stack listener presents as
// ::ffff:a.b.c.d, and applying the IPv6 rule to that would key it by a /64 that
// every IPv4-mapped address shares — the whole IPv4 internet in one bucket,
// which is the wrong granularity in both directions at once.
func makeKey(addr netip.Addr, c Class) key {
	k := key{class: uint8(c)}

	a := addr.Unmap()
	switch {
	case a.Is4():
		v4 := a.As4()
		v4[3] = 0 // /24
		copy(k.net[:], v4[:])
		k.family = 4
	case a.Is6():
		v6 := a.As16()
		copy(k.net[:8], v6[:8]) // /64
		k.family = 6
	default:
		// Not a valid address. Allow refuses these before reaching here; the
		// zero family keeps them from colliding with a real network should
		// that ever change.
		k.family = 0
	}
	return k
}
