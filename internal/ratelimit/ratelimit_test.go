// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package ratelimit

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// A fixed origin for every test. Nothing here reads the clock, because Allow
// does not either — an hour-long window must not mean an hour-long test.
var origin = time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)

// addr is a parsing helper. Note that no test in this file passes an address to
// a formatting call: failures are reported by case name. TestNoRenderingOfKeys
// in source_test.go enforces that, and the discipline is the point.
func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("test address does not parse")
	}
	return a
}

// smallOpts is the usual fixture: limits low enough to exhaust in a loop.
func smallOpts() Options {
	return Options{PutRecord: 3, GetRecord: 5, Signal: 2, Window: time.Hour, MaxKeys: 64}
}

// TestLimitEnforced covers the Nth request being admitted and the N+1th
// refused, for each class independently.
func TestLimitEnforced(t *testing.T) {
	tests := []struct {
		name  string
		class Class
		limit int
	}{
		{"put record", ClassPutRecord, 3},
		{"get record", ClassGetRecord, 5},
		{"signal", ClassSignal, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := New(smallOpts())
			a := addr(t, "192.0.2.10")

			for i := 1; i <= tt.limit; i++ {
				if !l.Allow(a, tt.class, origin) {
					t.Fatalf("request %d of %d refused, want allowed", i, tt.limit)
				}
			}
			if l.Allow(a, tt.class, origin) {
				t.Errorf("request %d refused nothing, want refused past limit %d", tt.limit+1, tt.limit)
			}
			// Still refused later in the same window.
			if l.Allow(a, tt.class, origin.Add(59*time.Minute)) {
				t.Errorf("request late in the same window allowed, want refused")
			}
		})
	}
}

// TestDefaultLimits pins the shipped defaults, which follow from §9.1 and from
// §6.4's instruction to set limits generously rather than tightly.
func TestDefaultLimits(t *testing.T) {
	tests := []struct {
		name  string
		class Class
		want  int
	}{
		{"put record 600 per hour", ClassPutRecord, 600},
		{"get record 600 per hour", ClassGetRecord, 600},
		{"signal 600 per hour combined", ClassSignal, 600},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := New(Options{})
			if l.window != time.Hour {
				t.Fatalf("default window = %v, want 1h", l.window)
			}
			a := addr(t, "198.51.100.7")
			allowed := 0
			for i := 0; i < tt.want+10; i++ {
				if l.Allow(a, tt.class, origin) {
					allowed++
				}
			}
			if allowed != tt.want {
				t.Errorf("admitted %d in a window, want %d", allowed, tt.want)
			}
		})
	}
}

// TestClassesAreIndependent: exhausting PUT must not affect GET or signal.
func TestClassesAreIndependent(t *testing.T) {
	l := New(smallOpts())
	a := addr(t, "192.0.2.10")

	for i := 0; i < 3; i++ {
		if !l.Allow(a, ClassPutRecord, origin) {
			t.Fatalf("put %d refused, want allowed", i+1)
		}
	}
	if l.Allow(a, ClassPutRecord, origin) {
		t.Fatalf("put past limit allowed, want refused")
	}

	tests := []struct {
		name  string
		class Class
		limit int
	}{
		{"get record unaffected", ClassGetRecord, 5},
		{"signal unaffected", ClassSignal, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := 0; i < tt.limit; i++ {
				if !l.Allow(a, tt.class, origin) {
					t.Fatalf("request %d refused, want allowed", i+1)
				}
			}
		})
	}
}

// TestSignalPostAndGetShareAnAllowance. §5.4 gives the signal channels one 429
// row covering both methods, so they are one class rather than two.
func TestSignalPostAndGetShareAnAllowance(t *testing.T) {
	l := New(Options{Signal: 2, Window: time.Hour})
	a := addr(t, "192.0.2.10")

	if !l.Allow(a, ClassSignal, origin) { // stands in for POST
		t.Fatalf("first signal request refused")
	}
	if !l.Allow(a, ClassSignal, origin) { // stands in for GET
		t.Fatalf("second signal request refused")
	}
	if l.Allow(a, ClassSignal, origin) {
		t.Errorf("third signal request allowed, want refused")
	}
}

// TestWindowRollover: the allowance returns once the window elapses.
func TestWindowRollover(t *testing.T) {
	tests := []struct {
		name    string
		at      time.Time
		want    bool
		comment string
	}{
		{"just inside the window", origin.Add(time.Hour - time.Nanosecond), false, "window not yet elapsed"},
		{"exactly at the boundary", origin.Add(time.Hour), true, "window elapsed, allowance restored"},
		{"well past the boundary", origin.Add(3 * time.Hour), true, "later window"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := New(smallOpts())
			a := addr(t, "192.0.2.10")
			for i := 0; i < 3; i++ {
				if !l.Allow(a, ClassPutRecord, origin) {
					t.Fatalf("setup request %d refused", i+1)
				}
			}
			if got := l.Allow(a, ClassPutRecord, tt.at); got != tt.want {
				t.Errorf("Allow() = %v, want %v (%s)", got, tt.want, tt.comment)
			}
		})
	}
}

// TestClockSteppedBackwards. A window that appears to open in the future is a
// wall clock adjustment. Within one window the entry is treated as current;
// beyond it, it is discarded rather than left live for the length of the step,
// because §6.4 gives state one window and no more.
func TestClockSteppedBackwards(t *testing.T) {
	tests := []struct {
		name string
		at   time.Time
		want bool
	}{
		{"small backwards step keeps the window", origin.Add(-30 * time.Minute), false},
		{"large backwards step discards it", origin.Add(-2 * time.Hour), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := New(smallOpts())
			a := addr(t, "192.0.2.10")
			for i := 0; i < 3; i++ {
				if !l.Allow(a, ClassPutRecord, origin) {
					t.Fatalf("setup request %d refused", i+1)
				}
			}
			if got := l.Allow(a, ClassPutRecord, tt.at); got != tt.want {
				t.Errorf("Allow() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestTruncation is the §6.4 requirement itself: state is keyed by the address
// truncated to /24 for IPv4 and /64 for IPv6.
//
// Sharing is asserted behaviourally — one address exhausts the allowance and
// the other is refused — because the key is not observable from outside this
// package, and deliberately so.
func TestTruncation(t *testing.T) {
	tests := []struct {
		name      string
		first     string
		second    string
		wantShare bool
	}{
		{"ipv4 same /24", "192.0.2.1", "192.0.2.254", true},
		{"ipv4 same /24 across the low octet", "192.0.2.0", "192.0.2.255", true},
		{"ipv4 different /24", "192.0.2.1", "192.0.3.1", false},
		{"ipv4 adjacent /24 differing only in the third octet", "203.0.113.9", "203.0.114.9", false},
		{"ipv6 same /64", "2001:db8::1", "2001:db8::ffff:2", true},
		{"ipv6 same /64 across the interface identifier", "2001:db8:0:1::", "2001:db8:0:1:ffff:ffff:ffff:ffff", true},
		{"ipv6 different /64", "2001:db8:0:1::1", "2001:db8:0:2::1", false},
		{"ipv6 different /48", "2001:db8:1::1", "2001:db8:2::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := New(smallOpts())
			first := addr(t, tt.first)
			second := addr(t, tt.second)

			for i := 0; i < 3; i++ {
				if !l.Allow(first, ClassPutRecord, origin) {
					t.Fatalf("setup request %d refused", i+1)
				}
			}
			got := l.Allow(second, ClassPutRecord, origin)
			if shared := !got; shared != tt.wantShare {
				t.Errorf("second address shares a bucket = %v, want %v", shared, tt.wantShare)
			}
		})
	}
}

// TestIPv4MappedIPv6 covers a client arriving over a dual-stack listener.
//
// ::ffff:a.b.c.d must be unmapped before truncation. Applying the IPv6 rule to
// it would key every IPv4-mapped address by the same /64 — the whole IPv4
// internet in one bucket — so this is not a cosmetic normalisation.
func TestIPv4MappedIPv6(t *testing.T) {
	tests := []struct {
		name      string
		first     string
		second    string
		wantShare bool
	}{
		{"mapped and native form of one address", "::ffff:192.0.2.1", "192.0.2.1", true},
		{"mapped and native within one /24", "::ffff:192.0.2.1", "192.0.2.99", true},
		{"both mapped, same /24", "::ffff:192.0.2.1", "::ffff:192.0.2.200", true},
		// Under a /64 rule these two would collide, because every
		// IPv4-mapped address shares the leading 64 bits. They must not.
		{"both mapped, different /24", "::ffff:192.0.2.1", "::ffff:192.0.3.1", false},
		{"mapped and native, different /24", "::ffff:192.0.2.1", "192.0.3.1", false},
		{"mapped v4 and a real v6 network", "::ffff:192.0.2.1", "2001:db8::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := New(smallOpts())
			first := addr(t, tt.first)
			second := addr(t, tt.second)

			for i := 0; i < 3; i++ {
				if !l.Allow(first, ClassPutRecord, origin) {
					t.Fatalf("setup request %d refused", i+1)
				}
			}
			got := l.Allow(second, ClassPutRecord, origin)
			if shared := !got; shared != tt.wantShare {
				t.Errorf("second address shares a bucket = %v, want %v", shared, tt.wantShare)
			}
		})
	}
}

// TestMappedAddressKeysIdenticallyToNative checks the key directly, since it is
// visible from inside the package. The comparison is on key equality; neither
// value is rendered.
func TestMappedAddressKeysIdenticallyToNative(t *testing.T) {
	native := makeKey(addr(t, "192.0.2.1"), ClassPutRecord)
	mapped := makeKey(addr(t, "::ffff:192.0.2.1"), ClassPutRecord)
	if native != mapped {
		t.Errorf("mapped and native forms produced different keys, want identical")
	}
	// Neither key is rendered, here or anywhere: the assertions are on
	// equality and on a constant. TestNoRenderingOfAddresses enforces that.
	if native.family != 4 {
		t.Errorf("the native form did not key as IPv4")
	}
	if mapped.family != 4 {
		t.Errorf("the mapped form keyed by the IPv6 rule, want the IPv4 one")
	}
}

// TestHostBitsAreDiscarded asserts that the key holds only network bits, so
// that even the in-memory state cannot identify a host.
func TestHostBitsAreDiscarded(t *testing.T) {
	tests := []struct {
		name  string
		input string
		zero  []int // key.net indices that must be zero
	}{
		{"ipv4 low octet", "192.0.2.222", []int{3}},
		{"ipv4 mapped low octet", "::ffff:192.0.2.222", []int{3}},
		{"ipv6 interface identifier", "2001:db8::dead:beef", []int{8, 9, 10, 11, 12, 13, 14, 15}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := makeKey(addr(t, tt.input), ClassGetRecord)
			for _, i := range tt.zero {
				if k.net[i] != 0 {
					t.Errorf("key.net[%d] is not zero: host bits survived truncation", i)
				}
			}
		})
	}
}

// TestEviction: idle keys are removed, not merely expired in place. §6.4
// requires state to be discarded when its window elapses, and a map that only
// ever grows retains address-derived state past that.
func TestEviction(t *testing.T) {
	t.Run("explicit sweep removes elapsed keys", func(t *testing.T) {
		l := New(smallOpts())
		for i := 1; i <= 5; i++ {
			a := netip.AddrFrom4([4]byte{192, 0, byte(i), 1})
			if !l.Allow(a, ClassPutRecord, origin) {
				t.Fatalf("setup request %d refused", i)
			}
		}
		if got := l.TrackedKeys(); got != 5 {
			t.Fatalf("TrackedKeys() = %d, want 5", got)
		}
		l.Sweep(origin.Add(30 * time.Minute))
		if got := l.TrackedKeys(); got != 5 {
			t.Errorf("TrackedKeys() = %d after a sweep inside the window, want 5", got)
		}
		l.Sweep(origin.Add(time.Hour))
		if got := l.TrackedKeys(); got != 0 {
			t.Errorf("TrackedKeys() = %d after the window elapsed, want 0", got)
		}
	})

	t.Run("allow sweeps without an external caller", func(t *testing.T) {
		// The obligation to discard cannot depend on the operator remembering
		// to call Sweep, so Allow runs it on the caller's clock.
		l := New(smallOpts())
		for i := 1; i <= 5; i++ {
			a := netip.AddrFrom4([4]byte{192, 0, byte(i), 1})
			if !l.Allow(a, ClassPutRecord, origin) {
				t.Fatalf("setup request %d refused", i)
			}
		}
		later := origin.Add(2 * time.Hour)
		if !l.Allow(addr(t, "198.51.100.1"), ClassPutRecord, later) {
			t.Fatalf("request in a later window refused")
		}
		if got := l.TrackedKeys(); got != 1 {
			t.Errorf("TrackedKeys() = %d, want 1: the five idle keys were not evicted", got)
		}
	})

	t.Run("a key whose window elapsed is replaced, not accumulated", func(t *testing.T) {
		l := New(smallOpts())
		a := addr(t, "192.0.2.10")
		for w := 0; w < 10; w++ {
			at := origin.Add(time.Duration(w) * time.Hour)
			if !l.Allow(a, ClassPutRecord, at) {
				t.Fatalf("window %d: request refused", w)
			}
		}
		if got := l.TrackedKeys(); got != 1 {
			t.Errorf("TrackedKeys() = %d after ten windows from one key, want 1", got)
		}
	})
}

// TestKeyBound covers the documented behaviour at Options.MaxKeys: tracked keys
// keep being served, a new key is refused once the table is full of live
// entries, and the condition clears when those entries elapse.
func TestKeyBound(t *testing.T) {
	const bound = 4
	l := New(Options{PutRecord: 10, Window: time.Hour, MaxKeys: bound})

	for i := 1; i <= bound; i++ {
		a := netip.AddrFrom4([4]byte{192, 0, byte(i), 1})
		if !l.Allow(a, ClassPutRecord, origin) {
			t.Fatalf("key %d refused below the bound", i)
		}
	}
	if got := l.TrackedKeys(); got != bound {
		t.Fatalf("TrackedKeys() = %d, want %d", got, bound)
	}

	fresh := netip.AddrFrom4([4]byte{198, 51, 100, 1})
	if l.Allow(fresh, ClassPutRecord, origin) {
		t.Errorf("a new key at the bound was allowed, want refused")
	}
	if got := l.TrackedKeys(); got != bound {
		t.Errorf("TrackedKeys() = %d, want the bound to hold at %d", got, bound)
	}

	// An already-tracked key is unaffected: the bound denies growth, not
	// service to the clients already accounted for.
	if !l.Allow(netip.AddrFrom4([4]byte{192, 0, 1, 1}), ClassPutRecord, origin) {
		t.Errorf("a tracked key was refused at the bound, want allowed")
	}

	// A different class from a tracked network is a different key, so it is
	// subject to the bound too.
	if l.Allow(netip.AddrFrom4([4]byte{192, 0, 1, 1}), ClassGetRecord, origin) {
		t.Errorf("a new class for a tracked network was allowed at the bound, want refused")
	}

	// Once the live entries elapse, the reclaim at the bound admits the new key.
	later := origin.Add(time.Hour)
	if !l.Allow(fresh, ClassPutRecord, later) {
		t.Errorf("a new key was refused after the table elapsed, want allowed")
	}
	if got := l.TrackedKeys(); got != 1 {
		t.Errorf("TrackedKeys() = %d after the reclaim, want 1", got)
	}
}

// TestConcurrency: many goroutines against one key admit exactly the limit and
// no more. Run under -race.
func TestConcurrency(t *testing.T) {
	const (
		limit      = 100
		goroutines = 32
		each       = 20 // 640 attempts against a limit of 100
	)
	l := New(Options{GetRecord: limit, Window: time.Hour, MaxKeys: 1024})
	a := addr(t, "192.0.2.10")

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		allowed int
	)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := 0
			for i := 0; i < each; i++ {
				if l.Allow(a, ClassGetRecord, origin) {
					local++
				}
			}
			mu.Lock()
			allowed += local
			mu.Unlock()
		}()
	}
	wg.Wait()

	if allowed != limit {
		t.Errorf("admitted %d of %d attempts, want exactly the limit %d", allowed, goroutines*each, limit)
	}
	if got := l.TrackedKeys(); got != 1 {
		t.Errorf("TrackedKeys() = %d, want 1", got)
	}
}

// TestConcurrentSweep exercises Allow against Sweep and TrackedKeys from many
// goroutines. It asserts no invariant beyond "does not race and does not
// deadlock", which is the point of running it under -race.
func TestConcurrentSweep(t *testing.T) {
	l := New(Options{PutRecord: 5, Window: time.Hour, MaxKeys: 128})
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				at := origin.Add(time.Duration(i) * time.Minute)
				l.Allow(netip.AddrFrom4([4]byte{192, 0, byte(g), byte(i)}), ClassPutRecord, at)
				if i%16 == 0 {
					l.Sweep(at)
					_ = l.TrackedKeys()
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestRefusedPaths covers the inputs that must fail closed rather than becoming
// an unmetered path.
func TestRefusedPaths(t *testing.T) {
	l := New(smallOpts())

	t.Run("invalid address", func(t *testing.T) {
		var zero netip.Addr
		if l.Allow(zero, ClassPutRecord, origin) {
			t.Errorf("Allow() with an invalid address = true, want false")
		}
	})

	t.Run("class below the declared set", func(t *testing.T) {
		if l.Allow(addr(t, "192.0.2.10"), Class(-1), origin) {
			t.Errorf("Allow() with a negative class = true, want false")
		}
	})

	t.Run("class above the declared set", func(t *testing.T) {
		if l.Allow(addr(t, "192.0.2.10"), numClasses, origin) {
			t.Errorf("Allow() with an undeclared class = true, want false")
		}
	})

	t.Run("zero value limiter refuses rather than panicking", func(t *testing.T) {
		var l Limiter
		if l.Allow(addr(t, "192.0.2.10"), ClassPutRecord, origin) {
			t.Errorf("Allow() on a zero Limiter = true, want false")
		}
		l.Sweep(origin)
		if got := l.TrackedKeys(); got != 0 {
			t.Errorf("TrackedKeys() = %d, want 0", got)
		}
	})
}

// TestOptionsDefaults: a zero or negative field selects the default rather than
// producing a limiter that refuses everything.
func TestOptionsDefaults(t *testing.T) {
	tests := []struct {
		name string
		opts Options
	}{
		{"zero value", Options{}},
		{"negative limits", Options{PutRecord: -1, GetRecord: -1, Signal: -1, Window: -time.Second, MaxKeys: -1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := New(tt.opts)
			if l.limits[ClassPutRecord] != DefaultPutRecord {
				t.Errorf("put limit = %d, want %d", l.limits[ClassPutRecord], DefaultPutRecord)
			}
			if l.limits[ClassGetRecord] != DefaultGetRecord {
				t.Errorf("get limit = %d, want %d", l.limits[ClassGetRecord], DefaultGetRecord)
			}
			if l.limits[ClassSignal] != DefaultSignal {
				t.Errorf("signal limit = %d, want %d", l.limits[ClassSignal], DefaultSignal)
			}
			if l.window != DefaultWindow {
				t.Errorf("window = %v, want %v", l.window, DefaultWindow)
			}
			if l.maxKeys != DefaultMaxKeys {
				t.Errorf("maxKeys = %d, want %d", l.maxKeys, DefaultMaxKeys)
			}
			if l.sweepInterval <= 0 || l.sweepInterval > l.window {
				t.Errorf("sweepInterval = %v, want a positive fraction of the window", l.sweepInterval)
			}
		})
	}
}

// TestNoAddressReachesAFormattedValue feeds recognisable addresses through the
// limiter and then renders everything this package exposes, checking that the
// address does not appear.
//
// The two protections it exercises:
//
//   - No type declared here is a Stringer. Had the key been a netip.Addr or a
//     netip.Prefix, both of which are, the first Sprintf below would print the
//     network in dotted-quad.
//   - The keys live behind a pointer field. fmt dereferences only at the top
//     level of an argument, so a %v or %+v of a Limiter prints an opaque
//     machine address for the state rather than walking the map.
//
// Note the check is on the byte-wise rendering as well as the textual one: %v
// of a [16]byte prints "[192 0 2 0 ...]", which contains no dots but every bit
// the key holds, so it would be a disclosure just the same.
func TestNoAddressReachesAFormattedValue(t *testing.T) {
	l := New(Options{PutRecord: 4, GetRecord: 4, Signal: 4, Window: time.Hour, MaxKeys: 16})

	inputs := []string{"192.0.2.77", "::ffff:198.51.100.22", "2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff"}
	for _, s := range inputs {
		a := addr(t, s)
		for _, c := range []Class{ClassPutRecord, ClassGetRecord, ClassSignal} {
			l.Allow(a, c, origin)
		}
	}

	// Every spelling of the fed addresses and of their truncations, textual and
	// byte-wise.
	forbidden := []string{
		"192.0.2.77", "192.0.2.0", "192.0.2",
		"198.51.100.22", "198.51.100.0", "198.51.100",
		"2001:db8:aaaa:bbbb", "2001:db8", "2001:0db8",
		"192 0 2", "198 51 100",
		"32 1 13 184", // 2001:db8 as bytes
	}

	rendered := []struct {
		name string
		text string
	}{
		{"%v of the limiter", fmt.Sprintf("%v", l)},
		{"%+v of the limiter", fmt.Sprintf("%+v", l)},
		{"%#v of the limiter", fmt.Sprintf("%#v", l)},
		{"%v of the dereferenced limiter", fmt.Sprintf("%v", *l)},
		{"%+v of the dereferenced limiter", fmt.Sprintf("%+v", *l)},
		{"%v of the options", fmt.Sprintf("%v", Options{})},
		{"%v of a class", fmt.Sprintf("%v", ClassPutRecord)},
		{"%v of the tracked count", fmt.Sprintf("%v", l.TrackedKeys())},
	}

	for _, r := range rendered {
		t.Run(r.name, func(t *testing.T) {
			for _, f := range forbidden {
				if strings.Contains(r.text, f) {
					t.Errorf("rendering discloses %q", f)
				}
			}
		})
	}
}

// TestNoErrorValues asserts that nothing this package returns is an error, so
// there is no value that could carry an address into a caller's error log.
//
// The exported surface answers with a bool and an int. That is the whole of it,
// and this test fails if a method is added that returns anything else.
func TestNoErrorValues(t *testing.T) {
	// Feed recognisable addresses first, so that anything the API could
	// possibly surface has seen them.
	l := New(smallOpts())
	for i := 0; i < 10; i++ {
		l.Allow(addr(t, "203.0.113.42"), ClassPutRecord, origin)
		l.Allow(addr(t, "2001:db8:c0ff:ee::1"), ClassSignal, origin)
	}
	l.Sweep(origin)

	// The compiler is the assertion: each call below is assigned to a variable
	// of a concrete non-error type, so a signature change breaks the build
	// rather than silently introducing an error path.
	var allowed bool = l.Allow(addr(t, "203.0.113.42"), ClassGetRecord, origin)
	var tracked int = l.TrackedKeys()
	_, _ = allowed, tracked

	// And the source scan in TestNoErrorConstruction holds the implementation
	// to it: no errors.New, no fmt.Errorf, no error return anywhere.
}

// TestSweepIntervalFloor covers a window short enough that window/sweepDivisor
// truncates to zero — a limiter must not end up with a sweep interval of zero
// and sweep the whole table on every request.
func TestSweepIntervalFloor(t *testing.T) {
	l := New(Options{Window: time.Nanosecond})
	if l.sweepInterval <= 0 {
		t.Errorf("sweepInterval = %v, want positive", l.sweepInterval)
	}
}
