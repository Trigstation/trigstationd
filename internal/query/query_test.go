// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package query

import (
	"errors"
	"math"
	"strings"
	"testing"
)

// wideCap is a cap large enough not to interfere with tests that are about
// parsing rather than about the cap. Tests that are about the cap pass a real
// Cap(recordCount) instead.
const wideCap = 256

// TestPaddingBitsAreMaskedNotRejected is the case a strict implementation gets
// wrong on every ordinary query.
//
// prefix carries ceil(bits/4) hex characters, so unless bits is a multiple of
// four the final character has low bits that are not significant. §5.3 requires
// a directory to mask and ignore them and forbids rejecting the query because
// they are non-zero — and at the recommended bits of 10 for a 100,000-record
// instance, that is the normal path, not an edge case.
//
// The assertions are on the masked value, not merely on acceptance: an
// implementation that accepted the query and then compared the unmasked prefix
// would pass an acceptance-only test and return an empty result set for every
// client that left its padding bits set.
func TestPaddingBitsAreMaskedNotRejected(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		bits   uint
		want   uint32
	}{
		// bits = 10 is the recommended width at 100,000 records: three hex
		// characters, two bits spare. Every spelling of the low two bits must
		// select the same bucket.
		{"10 bits, padding zeroed as a client should", "a3c", 10, 0xa3c00000},
		{"10 bits, padding 01", "a3d", 10, 0xa3c00000},
		{"10 bits, padding 10", "a3e", 10, 0xa3c00000},
		{"10 bits, padding 11", "a3f", 10, 0xa3c00000},
		// The mask must not reach further than the padding: a different value
		// in the significant bits is a different bucket.
		{"10 bits, significant bits differ", "a30", 10, 0xa3000000},

		{"11 bits, one spare bit set", "a3f", 11, 0xa3e00000},
		{"9 bits, three spare bits set", "a3f", 9, 0xa3800000},
		{"12 bits, no spare bits", "a3f", 12, 0xa3f00000},

		{"1 bit set, remaining three spare", "f", 1, 0x80000000},
		{"1 bit clear, remaining three spare", "7", 1, 0x00000000},
		{"2 bits", "f", 2, 0xc0000000},
		{"3 bits", "f", 3, 0xe0000000},

		{"5 bits across a byte boundary", "ff", 5, 0xf8000000},
		{"6 bits across a byte boundary", "ff", 6, 0xfc000000},
		{"7 bits across a byte boundary", "ff", 7, 0xfe000000},

		{"31 bits, one spare bit", "ffffffff", 31, 0xfffffffe},
		// Beyond the width of the prefix column the spare bits fall outside the
		// word entirely, so the masking still has to happen in the byte form.
		{"33 bits, three spare bits", "1ffffffff", 33, 0x1fffffff},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := Parse(tt.prefix, true, itoa(tt.bits), true, wideCap)
			if err != nil {
				t.Fatalf("Parse() rejected a query with non-zero padding bits: %v", err)
			}
			if q.Prefix != tt.want {
				t.Errorf("Prefix = %#08x, want %#08x", q.Prefix, tt.want)
			}
			if q.Bits != tt.bits {
				t.Errorf("Bits = %d, want %d", q.Bits, tt.bits)
			}
		})
	}
}

// TestPaddingSpellingsAreIndistinguishable states the property behind the table
// above directly: for every bits that is not a multiple of four, all sixteen
// spellings of the final character that agree on the significant bits must
// produce the identical query.
func TestPaddingSpellingsAreIndistinguishable(t *testing.T) {
	const hexDigits = "0123456789abcdefABCDEF"

	for bits := uint(1); bits <= 32; bits++ {
		if bits%4 == 0 {
			continue
		}
		lead := strings.Repeat("a", int((bits+3)/4)-1)

		var first Query
		var firstSet bool
		for i := 0; i < len(hexDigits); i++ {
			q, err := Parse(lead+string(hexDigits[i]), true, itoa(bits), true, wideCap)
			if err != nil {
				t.Fatalf("bits=%d: Parse() = %v", bits, err)
			}
			// Group by the significant nibble bits only.
			v, _ := nibble(hexDigits[i])
			if v>>(4-bits%4) != 0 {
				continue
			}
			if !firstSet {
				first, firstSet = q, true
				continue
			}
			if q.Prefix != first.Prefix {
				t.Errorf("bits=%d: spelling %q gave %#08x, want %#08x", bits, hexDigits[i], q.Prefix, first.Prefix)
			}
		}
	}
}

// TestPrefixLength covers "prefix MUST contain exactly ceil(bits / 4) hex
// characters" in both directions.
func TestPrefixLength(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		bits   uint
		want   error
	}{
		{"10 bits, three characters", "a3f", 10, nil},
		{"10 bits, two characters is too short", "a3", 10, ReasonPrefixLength},
		{"10 bits, four characters is too long", "a3f0", 10, ReasonPrefixLength},
		{"10 bits, empty is too short", "", 10, ReasonPrefixLength},
		{"8 bits, two characters", "ab", 8, nil},
		{"8 bits, one character is too short", "a", 8, ReasonPrefixLength},
		{"8 bits, three characters is too long", "abc", 8, ReasonPrefixLength},
		{"1 bit, one character", "8", 1, nil},
		{"1 bit, two characters is too long", "80", 1, ReasonPrefixLength},
		{"0 bits, one character is too long", "0", 0, ReasonPrefixLength},
		{"4 bits, one character", "f", 4, nil},
		{"32 bits, eight characters", "ffffffff", 32, nil},
		{"32 bits, seven characters is too short", "fffffff", 32, ReasonPrefixLength},
		{"32 bits, nine characters is too long", "fffffffff", 32, ReasonPrefixLength},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.prefix, true, itoa(tt.bits), true, wideCap)
			if !errors.Is(err, tt.want) {
				t.Errorf("Parse() = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestHexIsCaseInsensitive covers §5.3's requirement that a directory accept
// both a3f and A3F. Mixed case is included because a client assembling a prefix
// from two sources can produce it, and nothing in the spec forbids it.
func TestHexIsCaseInsensitive(t *testing.T) {
	spellings := []string{"a3f", "A3F", "A3f", "a3F"}

	var want Query
	for i, s := range spellings {
		q, err := Parse(s, true, "12", true, wideCap)
		if err != nil {
			t.Fatalf("Parse(%q) = %v, want acceptance", s, err)
		}
		if i == 0 {
			want = q
			continue
		}
		if q.Prefix != want.Prefix || q.Bits != want.Bits {
			t.Errorf("Parse(%q) = {bits %d, prefix %#08x}, want {bits %d, prefix %#08x}",
				s, q.Bits, q.Prefix, want.Bits, want.Prefix)
		}
	}

	// The whole alphabet in both cases, at the full width of the prefix column.
	lower, err := Parse("abcdef01", true, "32", true, wideCap)
	if err != nil {
		t.Fatalf("Parse(lowercase) = %v", err)
	}
	upper, err := Parse("ABCDEF01", true, "32", true, wideCap)
	if err != nil {
		t.Fatalf("Parse(uppercase) = %v", err)
	}
	if lower.Prefix != upper.Prefix {
		t.Errorf("case changed the prefix: %#08x vs %#08x", lower.Prefix, upper.Prefix)
	}
	if lower.Prefix != 0xabcdef01 {
		t.Errorf("Prefix = %#08x, want 0xabcdef01", lower.Prefix)
	}
}

// TestNonHexRejected covers "MUST reject any character outside [0-9a-fA-F]".
//
// The final case is the one worth having: at bits = 1 only the top bit of the
// single character survives the mask, but the character is still validated. A
// parser that validated only the bits it kept would accept "g".
func TestNonHexRejected(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		bits   uint
	}{
		{"letter beyond f", "a3g", 12},
		{"uppercase letter beyond F", "a3G", 12},
		{"punctuation", "a3-", 12},
		{"space", "a3 ", 12},
		{"0x prefix", "0xa", 12},
		{"non-ASCII", "a3é", 12},
		{"null byte", "a3\x00", 12},
		{"invalid character in the padding position", "g", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.prefix, true, itoa(tt.bits), true, wideCap)
			if err == nil {
				t.Fatal("Parse() accepted a non-hex prefix")
			}
			// A multi-byte character fails the byte-length check first; both
			// reasons are 400, and the point of the test is the rejection.
			if !errors.Is(err, ReasonPrefixNotHex) && !errors.Is(err, ReasonPrefixLength) {
				t.Errorf("Parse() = %v, want a prefix rejection", err)
			}
		})
	}
}

// TestBitsParameter covers §5.3's "bits is REQUIRED. A directory MUST NOT infer
// it from the length of prefix", and the malformed forms of the value.
func TestBitsParameter(t *testing.T) {
	tests := []struct {
		name        string
		prefix      string
		bits        string
		bitsPresent bool
		want        error
	}{
		{"absent, with a prefix whose length would imply 12", "a3f", "", false, ReasonBitsMissing},
		{"present but empty", "a3f", "", true, ReasonBitsMalformed},
		{"non-numeric", "a3f", "twelve", true, ReasonBitsMalformed},
		{"hex", "a3f", "0xc", true, ReasonBitsMalformed},
		{"negative", "a3f", "-1", true, ReasonBitsMalformed},
		{"negative zero", "a3f", "-0", true, ReasonBitsMalformed},
		{"explicitly signed", "a3f", "+12", true, ReasonBitsMalformed},
		{"fractional", "a3f", "12.0", true, ReasonBitsMalformed},
		{"exponent", "a3f", "1e1", true, ReasonBitsMalformed},
		{"leading space", "a3f", " 12", true, ReasonBitsMalformed},
		{"trailing space", "a3f", "12 ", true, ReasonBitsMalformed},
		{"underscore separator", "a3f", "1_2", true, ReasonBitsMalformed},
		{"absurdly large", "a3f", "99999999999999999999999", true, ReasonBitsMalformed},
		{"beyond uint32", "a3f", "4294967296", true, ReasonBitsMalformed},
		{"large but representable", "a3f", "4294967295", true, ReasonBitsTooPrecise},
		{"well formed", "a3f", "12", true, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.prefix, true, tt.bits, tt.bitsPresent, wideCap)
			if !errors.Is(err, tt.want) {
				t.Errorf("Parse() = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestBitsBeyondLookupIDWidth covers the structural guard: a prefix wider than
// the 256-bit identifier it selects on cannot match anything, and accepting one
// would have this package size a buffer from a number the caller supplied.
//
// This is an implementation guard rather than a rule from §5.3, and it is
// unreachable through a cap computed by Cap — whose value cannot exceed 58 even
// at MaxInt64 records — so it can never differ from another implementation on a
// query a conforming client could send. maxBits here is deliberately larger than
// any real instance would use.
func TestBitsBeyondLookupIDWidth(t *testing.T) {
	const absurdCap = 1024

	if _, err := Parse(strings.Repeat("f", 64), true, "256", true, absurdCap); err != nil {
		t.Errorf("Parse() at exactly the width of a lookup_id = %v, want acceptance", err)
	}
	if _, err := Parse(strings.Repeat("f", 65), true, "257", true, absurdCap); !errors.Is(err, ReasonBitsTooPrecise) {
		t.Errorf("Parse() beyond the width of a lookup_id = %v, want ReasonBitsTooPrecise", err)
	}
}

// TestEmptyPrefixAtZeroBits covers "A directory MUST accept both ?prefix=&bits=0
// and ?bits=0 with prefix absent".
//
// This is the query every conforming client sends to a new instance, whose cap
// is 0 until it holds KMin records. If either spelling is rejected, or if either
// yields anything other than the full range, a new directory returns nothing to
// anybody and can never accumulate the records that would raise its cap.
func TestEmptyPrefixAtZeroBits(t *testing.T) {
	tests := []struct {
		name          string
		prefix        string
		prefixPresent bool
	}{
		{"?prefix=&bits=0", "", true},
		{"?bits=0 with prefix absent", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := Parse(tt.prefix, tt.prefixPresent, "0", true, Cap(0))
			if err != nil {
				t.Fatalf("Parse() = %v, want acceptance", err)
			}
			if q.Bits != 0 {
				t.Errorf("Bits = %d, want 0", q.Bits)
			}
			if q.Prefix != 0 {
				t.Errorf("Prefix = %#08x, want 0", q.Prefix)
			}
			lo, hi := q.Range()
			if lo != 0 || hi != 4294967295 {
				t.Errorf("Range() = (%d, %d), want (0, 4294967295) — the full column", lo, hi)
			}
			if q.NeedsPostFilter() {
				t.Error("NeedsPostFilter() = true at bits 0")
			}
		})
	}
}

// TestAbsentAndEmptyPrefixAgree pins the equivalence directly: the present flag
// exists to let a caller pass what it received, not to produce two behaviours.
func TestAbsentAndEmptyPrefixAgree(t *testing.T) {
	empty, errEmpty := Parse("", true, "0", true, 0)
	absent, errAbsent := Parse("", false, "0", true, 0)
	if errEmpty != nil || errAbsent != nil {
		t.Fatalf("errors = (%v, %v), want (nil, nil)", errEmpty, errAbsent)
	}
	if empty.Bits != absent.Bits || empty.Prefix != absent.Prefix {
		t.Error("an absent prefix and an empty prefix produced different queries at bits 0")
	}
}

// TestPrefixMissingWithNonZeroBits: an absent prefix is only meaningful at
// bits = 0.
func TestPrefixMissingWithNonZeroBits(t *testing.T) {
	if _, err := Parse("", false, "10", true, wideCap); !errors.Is(err, ReasonPrefixMissing) {
		t.Errorf("Parse() = %v, want ReasonPrefixMissing", err)
	}
}

// TestOverPreciseRejected covers "Directories MUST enforce a maximum bits and
// reject over-precise queries with 400".
//
// The record counts are chosen so the cap sits at a value the table can state by
// hand: Cap(100000) = 12, because 20 * 2^12 = 81920 <= 100000 < 163840.
func TestOverPreciseRejected(t *testing.T) {
	tests := []struct {
		name        string
		recordCount int64
		prefix      string
		bits        uint
		want        error
	}{
		{"at the cap", 100000, "a3f", 12, nil},
		{"one bit past the cap", 100000, "a3f0", 13, ReasonBitsTooPrecise},
		{"a full 32-bit prefix", 100000, "a3f0a3f0", 32, ReasonBitsTooPrecise},
		{"the recommended client width is well inside", 100000, "a3f", 10, nil},
		{"empty instance accepts only bits 0", 0, "", 0, nil},
		{"empty instance rejects one bit", 0, "8", 1, ReasonBitsTooPrecise},
		{"instance below k_min rejects one bit", 19, "8", 1, ReasonBitsTooPrecise},
		{"instance at k_min accepts only bits 0", 20, "8", 1, ReasonBitsTooPrecise},
		{"instance at twice k_min accepts one bit", 40, "8", 1, nil},
		{"instance at twice k_min rejects two bits", 40, "c", 2, ReasonBitsTooPrecise},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.prefix, true, itoa(tt.bits), true, Cap(tt.recordCount))
			if !errors.Is(err, tt.want) {
				t.Errorf("Parse() = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestCap works through DIRECTORY-SPEC.md §5.3's
// bits_max = max(0, floor(log2(record_count / 20))) by hand.
//
// The boundaries are the values where the expression changes: 20 * 2^b.
func TestCap(t *testing.T) {
	tests := []struct {
		recordCount int64
		want        uint
		why         string
	}{
		{0, 0, "undefined without the clamp: log2(0/20) has no value"},
		{1, 0, "negative without the clamp: log2(1/20) is about -4.3"},
		{19, 0, "negative without the clamp: log2(19/20) is about -0.07"},
		{20, 0, "log2(20/20) = 0"},
		{21, 0, "log2(21/20) is about 0.07, floor 0"},
		{39, 0, "log2(39/20) is about 0.96, floor 0"},
		{40, 1, "log2(40/20) = 1 exactly — the boundary math.Log2 would put at risk"},
		{41, 1, "log2(41/20) is about 1.04, floor 1"},
		{79, 1, "log2(79/20) is about 1.98, floor 1"},
		{80, 2, "log2(80/20) = 2 exactly"},
		{100000, 12, "20 * 2^12 = 81920 <= 100000 < 163840"},
		{81919, 11, "one below the 12-bit boundary"},
		{81920, 12, "exactly at the 12-bit boundary"},
		{-1, 0, "a negative count cannot occur, and must not produce a huge cap if it does"},
		{math.MaxInt64, 58, "20 * 2^58 <= MaxInt64 < 20 * 2^59"},
	}

	for _, tt := range tests {
		t.Run(itoa64(tt.recordCount), func(t *testing.T) {
			if got := Cap(tt.recordCount); got != tt.want {
				t.Errorf("Cap(%d) = %d, want %d (%s)", tt.recordCount, got, tt.want, tt.why)
			}
		})
	}
}

// TestCapClampAtColdStart asserts the two values the clamp exists for,
// separately from the table, because they are the cold-start failure rather than
// a boundary.
//
// Without max(0, …) the expression is negative below 20 records and undefined at
// zero. A directory that let that become a large unsigned value, or that treated
// it as an error, would reject the bits=0 query every conforming client sends to
// a new instance — and would then reject every lookup forever, because it could
// never accumulate records that nobody could find.
func TestCapClampAtColdStart(t *testing.T) {
	if got := Cap(0); got != 0 {
		t.Errorf("Cap(0) = %d, want 0", got)
	}
	if got := Cap(19); got != 0 {
		t.Errorf("Cap(19) = %d, want 0", got)
	}
	if _, err := Parse("", false, "0", true, Cap(0)); err != nil {
		t.Errorf("a new instance rejected ?bits=0: %v — it can now never be found", err)
	}
}

// TestConformingClientNeverExceedsCap asserts §5.1's claim rather than trusting
// it: "the server-side cap in §5.3 is computed against the true count, and a
// client following the advertised figure can never exceed it".
//
// The client's rule is bits = max(0, floor(log2(record_count / k))) with a
// RECOMMENDED k of 50; the directory's is the same expression with k_min = 20.
// The reference implementation below is deliberately a different algorithm from
// capFor's — a doubling loop rather than a bit length — so that the two are not
// the same mistake checked twice.
//
// The sweep includes the advertised count as well as the true one, since §5.1
// permits an instance to understate: a client sizing from a smaller figure must
// also land inside the cap computed from the true one.
func TestConformingClientNeverExceedsCap(t *testing.T) {
	const clientK = 50

	check := func(t *testing.T, trueCount int64) {
		t.Helper()
		capBits := Cap(trueCount)

		// Sized from the true count.
		if got := referenceBits(trueCount, clientK); got > capBits {
			t.Errorf("record_count %d: client bits %d exceeds cap %d", trueCount, got, capBits)
		}
		// Sized from any permitted understatement of it.
		for _, advertised := range []int64{trueCount, trueCount / 2, trueCount / 10, roundDownToTwoSigFigs(trueCount), 0} {
			if advertised > trueCount || advertised < 0 {
				continue
			}
			if got := referenceBits(advertised, clientK); got > capBits {
				t.Errorf("record_count %d advertised as %d: client bits %d exceeds cap %d",
					trueCount, advertised, got, capBits)
			}
		}
	}

	for n := int64(0); n <= 20000; n++ {
		check(t, n)
	}
	for b := uint(0); b < 58; b++ {
		for _, n := range []int64{
			20 << b, 20<<b - 1, 20<<b + 1,
			50 << b, 50<<b - 1, 50<<b + 1,
			1 << b,
		} {
			if n < 0 {
				continue
			}
			check(t, n)
		}
	}
	check(t, math.MaxInt64)

	// The property is only interesting if the client's rule is non-trivial at
	// these sizes, so assert the worked example from §5.3 as well: at 100,000
	// records and k = 50, log2(100000/50) = 10.97, so bits = 10.
	if got := referenceBits(100000, clientK); got != 10 {
		t.Errorf("reference client bits at 100000 records = %d, want 10 (§5.3's worked example)", got)
	}
	if got := Cap(100000); got != 12 {
		t.Errorf("Cap(100000) = %d, want 12", got)
	}
}

// referenceBits is max(0, floor(log2(recordCount/k))) computed by doubling,
// independently of capFor.
func referenceBits(recordCount, k int64) uint {
	if recordCount < k || k <= 0 {
		return 0
	}
	b := uint(0)
	// k * 2^(b+1) <= recordCount, written as a shift on recordCount so nothing
	// can overflow at the top of the range.
	for b < 62 && k <= recordCount>>(b+1) {
		b++
	}
	return b
}

// roundDownToTwoSigFigs is §5.1's RECOMMENDED understatement of record_count.
func roundDownToTwoSigFigs(n int64) int64 {
	if n < 100 {
		return n
	}
	scale := int64(1)
	for n/scale >= 100 {
		scale *= 10
	}
	return n / scale * scale
}

// TestRange covers the index bounds of §9's prefix column.
//
// The 0xFF cases are the ones that matter: the column holds the first 32 bits of
// a lookup_id as an integer and therefore reaches 4294967295. A directory that
// typed it as a signed 32-bit value loses every lookup_id whose first bit is set
// — half the keyspace, silently.
func TestRange(t *testing.T) {
	tests := []struct {
		name       string
		prefix     string
		bits       uint
		lo, hi     int64
		postFilter bool
	}{
		{"0 bits is the whole column", "", 0, 0, 4294967295, false},
		{"1 bit clear", "0", 1, 0, 2147483647, false},
		{"1 bit set spans the upper half", "8", 1, 2147483648, 4294967295, false},
		{"4 bits", "a", 4, 0xa0000000, 0xafffffff, false},
		{"4 bits at f", "f", 4, 0xf0000000, 0xffffffff, false},
		{"10 bits with padding set", "a3f", 10, 0xa3c00000, 0xa3ffffff, false},
		{"12 bits", "a3f", 12, 0xa3f00000, 0xa3ffffff, false},
		{"8 bits at ff spans above 2^31", "ff", 8, 4278190080, 4294967295, false},
		{"32 bits is a single value", "a3f0a3f0", 32, 0xa3f0a3f0, 0xa3f0a3f0, false},
		{"32 bits at ffffffff", "ffffffff", 32, 4294967295, 4294967295, false},
		{"33 bits needs a post-filter", "ffffffff8", 33, 4294967295, 4294967295, true},
		{"40 bits needs a post-filter", "ff00ff00ff", 40, 4278255360, 4278255360, true},
		{"256 bits needs a post-filter", strings.Repeat("f", 64), 256, 4294967295, 4294967295, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := Parse(tt.prefix, tt.prefix != "", itoa(tt.bits), true, wideCap)
			if err != nil {
				t.Fatalf("Parse() = %v", err)
			}
			lo, hi := q.Range()
			if lo != tt.lo || hi != tt.hi {
				t.Errorf("Range() = (%d, %d), want (%d, %d)", lo, hi, tt.lo, tt.hi)
			}
			if lo > hi {
				t.Error("Range() is inverted, so an index scan returns nothing")
			}
			if got := q.NeedsPostFilter(); got != tt.postFilter {
				t.Errorf("NeedsPostFilter() = %v, want %v", got, tt.postFilter)
			}
		})
	}
}

// TestRangeReachesAboveInt32 states the int64 requirement as its own property.
func TestRangeReachesAboveInt32(t *testing.T) {
	q, err := Parse("ff", true, "8", true, wideCap)
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	lo, hi := q.Range()
	if lo <= math.MaxInt32 {
		t.Errorf("lo = %d, want a value above %d — the upper half of the keyspace must be reachable", lo, math.MaxInt32)
	}
	if hi != 4294967295 {
		t.Errorf("hi = %d, want 4294967295", hi)
	}
}

// TestRangeCoversEveryPrefix is the completeness property behind Range: for any
// bits within the column's width, every possible first word either falls inside
// the range or has a different prefix. A bound that was off by one at either end
// would drop or over-return records.
func TestRangeCoversEveryPrefix(t *testing.T) {
	for bits := uint(0); bits <= 16; bits++ {
		hexLen := int((bits + 3) / 4)
		q, err := Parse(strings.Repeat("a", hexLen), hexLen > 0, itoa(bits), true, wideCap)
		if err != nil {
			t.Fatalf("bits=%d: Parse() = %v", bits, err)
		}
		lo, hi := q.Range()

		wantSpan := int64(1) << (32 - bits)
		if got := hi - lo + 1; got != wantSpan {
			t.Errorf("bits=%d: range spans %d values, want %d", bits, got, wantSpan)
		}
		if uint64(lo)&^(^uint64(0)<<(32-bits)) != 0 {
			t.Errorf("bits=%d: lo = %d has significant low bits set", bits, lo)
		}
	}
}

// TestMatches covers the post-filter a query wider than the prefix column needs.
func TestMatches(t *testing.T) {
	lookupID := []byte{0xa3, 0xf1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

	tests := []struct {
		name   string
		prefix string
		bits   uint
		id     []byte
		want   bool
	}{
		{"0 bits matches everything", "", 0, lookupID, true},
		{"10 bits with padding set", "a3f", 10, lookupID, true},
		{"12 bits exact", "a3f", 12, lookupID, true},
		{"12 bits wrong", "a3e", 12, lookupID, false},
		{"40 bits exact", "a3f1001122", 40, lookupID, true},
		{"40 bits wrong in the last byte", "a3f1001123", 40, lookupID, false},
		{"40 bits wrong in the low nibble of the last byte", "a3f1001127", 40, lookupID, false},
		{"36 bits ignores the low nibble of the last byte", "a3f100112", 36, lookupID, true},
		{"prefix longer than the identifier", strings.Repeat("a", 20), 80, lookupID[:4], false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q, err := Parse(tt.prefix, tt.prefix != "", itoa(tt.bits), true, wideCap)
			if err != nil {
				t.Fatalf("Parse() = %v", err)
			}
			if got := q.Matches(tt.id); got != tt.want {
				t.Errorf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestFullPrefixIsMasked asserts the byte form carries the same masking as the
// word form, since the post-filter compares against it.
func TestFullPrefixIsMasked(t *testing.T) {
	q, err := Parse("a3f", true, "10", true, wideCap)
	if err != nil {
		t.Fatalf("Parse() = %v", err)
	}
	if len(q.Full) != 2 {
		t.Fatalf("len(Full) = %d, want 2", len(q.Full))
	}
	if q.Full[0] != 0xa3 || q.Full[1] != 0xc0 {
		t.Errorf("Full = %#v, want [0xa3 0xc0]", q.Full)
	}
}

// TestEveryReasonIsMapped mirrors internal/reject: a reason added without a case
// in HTTPStatus would otherwise reach a client as a 500.
func TestEveryReasonIsMapped(t *testing.T) {
	for r := ReasonBitsMissing; r <= ReasonRepeatedParameter; r++ {
		if got := r.HTTPStatus(); got != 400 {
			t.Errorf("Reason(%d).HTTPStatus() = %d, want 400 — every §5.3 rejection is 400", int(r), got)
		}
		if r.Error() == "query: rejected" {
			t.Errorf("Reason(%d) has no message of its own", int(r))
		}
	}
}

// TestErrorsCarryNoQueryValues is the no-logging requirement asserted at the
// only place in this package that produces text.
//
// A lookup prefix is precisely the identifier that must never reach a log. An
// error that formatted the prefix or the bit count into its message would put it
// one fmt.Errorf away from an operator's terminal, however careful the caller
// was, so the property is enforced here rather than trusted downstream.
func TestErrorsCarryNoQueryValues(t *testing.T) {
	cases := []struct{ prefix, bits string }{
		{"a3f", "13"},
		{"deadbeef", "32"},
		{"a3g", "12"},
		{"a3f0", "10"},
		{"a3f", "twelve"},
		{"a3f", "-1"},
		{"a3f", "99999999999999999999999"},
	}

	for _, c := range cases {
		_, err := Parse(c.prefix, true, c.bits, true, Cap(100000))
		if err == nil {
			t.Fatalf("Parse(%q, %q) was accepted; the case is meant to be rejected", c.prefix, c.bits)
		}
		msg := err.Error()
		if strings.Contains(strings.ToLower(msg), strings.ToLower(c.prefix)) {
			t.Errorf("error message contains the prefix value: %q", msg)
		}
		if strings.Contains(msg, c.bits) {
			t.Errorf("error message contains the bits value: %q", msg)
		}
		for _, d := range "0123456789" {
			if strings.ContainsRune(msg, d) {
				t.Errorf("error message contains a digit and so may carry a query value: %q", msg)
				break
			}
		}
	}
}

// itoa avoids strconv in the test's own expectations, so a fault in the
// conversion the parser uses cannot be cancelled out by the same fault here.
func itoa(n uint) string {
	if n == 0 {
		return "0"
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

func itoa64(n int64) string {
	if n < 0 {
		return "-" + itoa64(-n)
	}
	return itoa(uint(n))
}

// TestBitsRejectsLeadingZeros covers §5.3's lexical rule: "one or more ASCII
// digits: no sign, no leading zeros, no whitespace".
//
// strconv.ParseUint accepts every one of these and reads "00" as 0 and "010"
// as 10, so the check has to be explicit. Two spellings of one bit count is the
// same defect the canonical-encoding rule closes for base64url — and it reached
// the wire, where ?prefix=&bits=00 was answered 200 rather than 400.
func TestBitsRejectsLeadingZeros(t *testing.T) {
	for _, s := range []string{"00", "000", "010", "0000000001"} {
		t.Run(s, func(t *testing.T) {
			if _, err := Parse("", true, s, true, 12); err == nil {
				t.Errorf("Parse accepted bits=%q; §5.3 forbids a leading zero", s)
			}
		})
	}

	// A single zero is the ordinary bits=0 query and must still be accepted.
	if _, err := Parse("", true, "0", true, 12); err != nil {
		t.Errorf("Parse rejected bits=0: %v", err)
	}
}

// TestBitsRejectsOtherNotations pins the rest of the lexical rule.
func TestBitsRejectsOtherNotations(t *testing.T) {
	for _, s := range []string{"+12", "-1", " 4", "4 ", "0x4", "4.0", "1e2", "", "four", "1_0"} {
		t.Run(s, func(t *testing.T) {
			if _, err := Parse("abc", true, s, true, 12); err == nil {
				t.Errorf("Parse accepted bits=%q", s)
			}
		})
	}
}
