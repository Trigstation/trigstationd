// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestPrefixBitsMatchesTheSpecFormula pins bits = max(0, floor(log2(count/k))).
//
// The boundaries are the whole point. floor makes k a floor rather than a
// target, so the width may only increase when the count reaches a full multiple
// of a power of two — one record short must still give the narrower prefix. An
// implementation using round, which §5.3 explicitly rejects, differs from this
// at exactly those inputs and nowhere else, so a test that skipped them would
// pass on the wrong arithmetic.
func TestPrefixBitsMatchesTheSpecFormula(t *testing.T) {
	const k = anonymitySet // 50

	cases := []struct {
		count int64
		want  int
	}{
		{0, 0},   // an empty directory
		{1, 0},   // the state immediately after a first publish
		{49, 0},  // below k: the whole table is the anonymity set
		{50, 0},  // count/k == 1, log2 == 0
		{99, 0},  // one short of doubling
		{100, 1}, // count/k == 2
		{199, 1}, // one short again — round would give 2 here
		{200, 2},
		{399, 2},
		{400, 3},
		{100000, 10}, // §5.3's worked example: log2(100000/50) = 10.97, floor 10
	}
	for _, c := range cases {
		if got := prefixBits(c.count, k); got != c.want {
			t.Errorf("prefixBits(%d, %d) = %d, want %d", c.count, k, got, c.want)
		}
	}
}

// TestPrefixBitsNeverExceedsTheDirectoryCap is the §5.1 promise: a client
// following the advertised record_count is never rejected as over-precise.
//
// That holds only while the client's k stays at or above the normative k_min of
// 20. If somebody lowers anonymitySet below it, every lookup against a
// conforming directory starts returning 400, and it would present as the
// directory being broken rather than this constant being wrong.
func TestPrefixBitsNeverExceedsTheDirectoryCap(t *testing.T) {
	const kMin = 20 // fixed by §5.3, not an instance's choice

	for count := int64(0); count < 20000; count++ {
		client := prefixBits(count, anonymitySet)
		cap := prefixBits(count, kMin)
		if client > cap {
			t.Fatalf("record_count %d: client asked for %d bits, directory caps at %d",
				count, client, cap)
		}
	}
}

// TestPrefixHexWidthAndMasking covers §5.3's encoding rule: exactly
// ceil(bits/4) hex characters, with the trailing low bits of the final
// character zeroed.
func TestPrefixHexWidthAndMasking(t *testing.T) {
	// 0xa3f... — chosen so the masked bits are visible rather than incidentally
	// already zero.
	id, err := hex.DecodeString("a3ff00000000000000000000000000000000000000000000000000000000000f")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		bits int
		want string
	}{
		{0, ""},     // empty prefix: the whole table
		{1, "8"},    // 1010 -> keep the top bit, zero the low three
		{2, "8"},    // 10xx -> 1000
		{3, "a"},    // 101x -> 1010
		{4, "a"},    // exactly one character, nothing to mask
		{8, "a3"},   //
		{11, "a3e"}, // §5.3's example width: 1111 -> 1110, low bit zeroed
		{12, "a3f"}, // three characters, aligned
	}
	for _, c := range cases {
		got := prefixHex(id, c.bits)
		if got != c.want {
			t.Errorf("prefixHex(bits=%d) = %q, want %q", c.bits, got, c.want)
		}
		if wantLen := (c.bits + 3) / 4; len(got) != wantLen {
			t.Errorf("prefixHex(bits=%d) length %d, want ceil(%d/4) = %d",
				c.bits, len(got), c.bits, wantLen)
		}
	}
}

// TestPrefixHexTrailingBitsAreZero checks the masking property directly across
// every width, rather than only at the hand-written cases above.
func TestPrefixHexTrailingBitsAreZero(t *testing.T) {
	id, err := hex.DecodeString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	if err != nil {
		t.Fatal(err)
	}
	for bits := 1; bits <= 64; bits++ {
		got := prefixHex(id, bits)
		rem := len(got)*4 - bits
		if rem == 0 {
			continue
		}
		last := strings.IndexByte("0123456789abcdef", got[len(got)-1])
		if last < 0 {
			t.Fatalf("bits=%d: %q is not hex", bits, got)
		}
		if last&((1<<rem)-1) != 0 {
			t.Errorf("bits=%d: %q has %d significant trailing bits set, want zero",
				bits, got, rem)
		}
	}
}

// TestEndpointParsing covers the flag form, including the bracketed IPv6 case
// that a naive split on the last colon gets wrong.
func TestEndpointParsing(t *testing.T) {
	var l endpointList
	for _, s := range []string{
		"wan4:203.0.113.7:8920",
		"lan:192.168.1.10:8920",
		"wan6:[2001:db8::1]:8920",
		"dns:example.com:443",
	} {
		if err := l.Set(s); err != nil {
			t.Fatalf("Set(%q): %v", s, err)
		}
	}
	if len(l) != 4 {
		t.Fatalf("got %d endpoints, want 4", len(l))
	}
	if l[2].Host != "2001:db8::1" || l[2].Port != 8920 {
		t.Errorf("bracketed IPv6 parsed as host=%q port=%d", l[2].Host, l[2].Port)
	}
	if l[0].Type != "wan4" || l[0].Host != "203.0.113.7" {
		t.Errorf("first endpoint parsed as %+v", l[0])
	}

	for _, bad := range []string{"wan4:203.0.113.7", "nope:host:1", "wan4:host:0", "wan4:host:70000", "junk"} {
		var e endpointList
		if err := e.Set(bad); err == nil {
			t.Errorf("Set(%q) was accepted, want an error", bad)
		}
	}
}
