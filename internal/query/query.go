// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

// Package query parses the prefix lookup of DIRECTORY-SPEC.md §5.3 and computes
// the bit-length cap a directory enforces against it.
//
// A lookup is a hex prefix plus an explicit bit length — ?prefix=a3f&bits=11 —
// and the directory returns every unexpired envelope whose lookup_id begins with
// those bits. It learns only that somebody asked about a bucket of between k and
// 2k servers, which is the whole of the privacy design in §8: the bucket is the
// anonymity set, and the cap here is what makes its breadth a protocol guarantee
// rather than a client courtesy.
//
// This package takes already-extracted strings rather than a request. It parses,
// masks and bounds; it does not serve, and it holds no state.
//
// # Two properties worth stating before reading the code
//
// **Padding bits are masked, never rejected.** prefix carries exactly
// ceil(bits/4) hex characters, so where bits is not a multiple of four the
// trailing low bits of the final character are not significant. A client SHOULD
// zero them and a directory MUST mask and ignore them — and MUST NOT reject the
// query because they are non-zero. This is the ordinary path, not an edge case:
// at 100,000 records the recommended bits is 10, which occupies three hex
// characters and leaves two bits spare. A directory strict about padding would
// fail on the normal query of a conforming client.
//
// **The cap is clamped at zero.** With k_min = 20 the cap is
// max(0, floor(log2(record_count / k_min))). The clamp is load-bearing rather
// than tidy: below 20 records the unclamped expression is negative and at zero
// records it is undefined, so a directory that omitted it would reject the
// bits=0 query every conforming client sends to a new instance — and would then
// reject every lookup it ever received, because it could never accumulate the
// records that nobody was able to find.
//
// # Integer maths, not floating point
//
// Both computations are exact integer arithmetic over math/bits. floor(log2(x))
// evaluated as math.Log2 invites a rounding error at precisely the powers of two
// where the boundary sits — the value that decides whether a query at the
// recommended width is accepted or rejected. Two directories disagreeing there
// is an interoperability failure that appears only at particular instance sizes.
package query

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"strconv"
)

// KMin is the anonymity floor the directory enforces, from the RECOMMENDED cap
// in DIRECTORY-SPEC.md §5.3. It is deliberately below the client's RECOMMENDED
// k of 50: the client aims for an anonymity set of at least 50, and the
// directory refuses anything that would drop it below 20. The gap is what lets a
// conforming client's own choice of bits never trip the cap.
const KMin = 20

// PrefixColumnBits is the width of the indexed prefix column in §9's schema:
// "the first 32 bits of lookup_id stored as an integer, for range scans". A
// query narrower than this is answered by the index alone; a query narrower than
// a lookup_id but wider than the column needs a post-filter (see Query.Range).
const PrefixColumnBits = 32

// LookupIDBits is the width of a lookup_id: SHA-256(wk_pub), 32 bytes.
//
// Rejecting a bits beyond it is an implementation guard, not a rule from §5.3 —
// a prefix longer than the identifier it selects on cannot match anything, and
// accepting one would have this package size a buffer from an attacker-supplied
// number. It is unreachable through Cap, whose value cannot exceed 58 even at a
// record count of MaxInt64, so no conforming query can reach it.
const LookupIDBits = 256

// Query is a validated, masked prefix lookup.
type Query struct {
	// Bits is the significant bit length of the prefix, at or below the cap it
	// was parsed against.
	Bits uint

	// Prefix is the first 32 bits of the prefix, masked to Bits and aligned to
	// the top of the word, so that it is directly comparable with the stored
	// prefix column. Where Bits is below 32 the remaining low bits are zero.
	Prefix uint32

	// Full is the whole masked prefix, ceil(Bits/8) bytes, aligned to the start
	// of lookup_id. It exists for the post-filter that a query wider than the
	// prefix column requires; see Range and Matches.
	Full []byte
}

// Cap returns the largest bits this directory will accept, per the RECOMMENDED
// bound in DIRECTORY-SPEC.md §5.3:
//
//	bits_max = max(0, floor(log2(record_count / k_min)))
//
// recordCount must be the **true** count, not the figure §5.1 permits an
// instance to understate in GET /v1/meta. That asymmetry is the point: because
// the advertised count may only ever be understated, a client sizing its prefix
// from the advertised figure always lands at or below the cap computed from the
// true one, and a conforming client can never be rejected as over-precise.
//
// A record count below KMin — including zero, and including a negative value
// that could only arise from a broken caller — yields 0, which accepts exactly
// the bits=0 query a client sends to an instance that small.
func Cap(recordCount int64) uint {
	return capFor(recordCount, KMin)
}

// capFor is Cap generalised over k, kept separate so the reasoning about the
// arithmetic sits in one place.
//
// floor(log2(recordCount/k)) is the largest b for which 2^b <= recordCount/k.
// Because 2^b is an integer, that is the same as the largest b for which
// 2^b <= floor(recordCount/k) — so integer division followed by a bit-length is
// exact, with none of the boundary risk of taking a logarithm in floating point.
func capFor(recordCount, k int64) uint {
	if k <= 0 || recordCount < k {
		return 0 // the max(0, …) clamp, and the undefined-at-zero case
	}
	return uint(bits.Len64(uint64(recordCount/k))) - 1
}

// Parse validates a prefix/bits query against maxBits and returns it masked.
//
// The two "present" flags distinguish an absent parameter from one supplied
// empty, which url.Values cannot express in the value alone. bitsPresent is what
// separates the required-parameter rejection from a malformed one; prefixPresent
// is what lets §5.3's "a directory MUST accept both ?prefix=&bits=0 and ?bits=0
// with prefix absent" be satisfied at this boundary rather than by asking every
// caller to normalise an absent parameter to the empty string first. Both
// spellings produce the identical Query.
//
// maxBits is the cap, normally Cap(trueRecordCount). It is a parameter rather
// than a package-level lookup because the cap moves with the record count and
// this package holds no state.
//
// The order the checks are applied in is not normative — §5.3 gives no
// evaluation order and binds every rejection here to 400, so the order cannot be
// observed on the wire. It is cheapest-first: an absurd bits is rejected before
// anything is sized from it.
func Parse(prefixParam string, prefixPresent bool, bitsParam string, bitsPresent bool, maxBits uint) (Query, error) {
	// bits is REQUIRED and MUST NOT be inferred from the length of prefix
	// (§5.3). Inference is the tempting shortcut and the one that breaks
	// interoperability silently: it makes "a3f" mean 12 bits everywhere, so a
	// client that meant 10 gets a narrower bucket and a smaller anonymity set
	// than it asked for, with nothing reporting an error.
	if !bitsPresent {
		return Query{}, ReasonBitsMissing
	}

	// §5.3 fixes the lexical form: one or more ASCII digits, no sign, no
	// leading zeros, no whitespace, no other notation.
	//
	// ParseUint covers most of that on its own — it rejects a sign, so "-1"
	// fails here rather than wrapping to something enormous, and a value too
	// large for 32 bits fails as out of range, so nothing downstream has to
	// defend against one. What it does not reject is a leading zero: it reads
	// "00" as 0 and "010" as 10. Two spellings of one value is the same defect
	// the canonical-encoding rule closes for base64url, so it is rejected here
	// rather than normalised.
	if bitsParam == "" || (len(bitsParam) > 1 && bitsParam[0] == '0') {
		return Query{}, ReasonBitsMalformed
	}
	n, err := strconv.ParseUint(bitsParam, 10, 32)
	if err != nil {
		return Query{}, ReasonBitsMalformed
	}
	nbits := uint(n)

	// The over-precise rejection of §5.3. A client asking for a 32-bit prefix
	// has defeated the privacy design entirely; this is where that stops being
	// a matter of client courtesy.
	if nbits > maxBits {
		return Query{}, ReasonBitsTooPrecise
	}
	if nbits > LookupIDBits {
		return Query{}, ReasonBitsTooPrecise
	}

	if !prefixPresent {
		if nbits > 0 {
			return Query{}, ReasonPrefixMissing
		}
		// Absent and empty are the same query at bits = 0. Normalise so the
		// length check below cannot be confused by a value a caller passed
		// alongside a false present flag.
		prefixParam = ""
	}

	// "prefix MUST contain exactly ceil(bits / 4) hex characters" (§5.3), in
	// both directions: too few is under-specified, too many carries bits the
	// client did not declare.
	//
	// The comparison is over bytes. Any input where a byte count and a character
	// count differ contains a byte outside the hex alphabet and would be
	// rejected regardless; only which of the two reasons it draws is affected,
	// and both are 400.
	if uint(len(prefixParam)) != (nbits+3)/4 {
		return Query{}, ReasonPrefixLength
	}

	// ceil(ceil(bits/4)/2) == ceil(bits/8), so every nibble below lands inside
	// full and no bounds check is needed in the loop.
	full := make([]byte, (nbits+7)/8)
	for i := 0; i < len(prefixParam); i++ {
		v, ok := nibble(prefixParam[i])
		if !ok {
			return Query{}, ReasonPrefixNotHex
		}
		if i%2 == 0 {
			full[i/2] |= v << 4
		} else {
			full[i/2] |= v
		}
	}

	// Every character is validated before masking, including one whose bits are
	// entirely discarded — "g" is not hex whether or not it survives the mask.
	return newQuery(full, nbits), nil
}

// FromBits builds a Query from an already-validated binary prefix.
//
// Parse is the wire path: it takes the hex text of a GET /v1/record query and
// enforces §5.3's syntax rules. FromBits is for callers that already hold the
// prefix as bytes and need the same masking and the same invariant between
// Bits, Prefix and Full — chiefly tests, and any future caller reconstructing a
// query from stored form.
//
// prefix must carry at least ceil(bits/8) bytes; anything beyond that is
// ignored. Low bits below the requested width are masked away rather than
// rejected, exactly as on the wire path, because §5.3 makes masking mandatory.
func FromBits(prefix []byte, bits uint) (Query, error) {
	if bits > LookupIDBits {
		return Query{}, ReasonBitsTooPrecise
	}
	need := (bits + 7) / 8
	if uint(len(prefix)) < need {
		return Query{}, ReasonPrefixLength
	}

	full := make([]byte, need)
	copy(full, prefix[:need])

	return newQuery(full, bits), nil
}

// newQuery masks the padding bits and derives the column word. It is the single
// place the invariant between Bits, Prefix and Full is established, so that no
// caller can produce a Query whose three fields disagree about the same prefix.
//
// full is retained, not copied: both callers have just allocated it.
func newQuery(full []byte, nbits uint) Query {
	if spare := uint(len(full))*8 - nbits; spare > 0 {
		full[len(full)-1] &^= byte(1)<<spare - 1
	}

	// The prefix column is 32 bits wide; a shorter prefix is zero-extended into
	// it, which is exactly what its masked low bits already are.
	var word [4]byte
	copy(word[:], full)

	return Query{
		Bits:   nbits,
		Prefix: binary.BigEndian.Uint32(word[:]),
		Full:   full,
	}
}

// nibble decodes one hex character. Both cases are accepted, per §5.3.
func nibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// Range returns the inclusive [lo, hi] bounds over the stored prefix column of
// §9's schema, for an index scan.
//
// The bounds are int64 because the column holds the first 32 bits of a
// lookup_id as an integer and therefore reaches 4294967295, which does not fit
// an int32. Half the keyspace — every lookup_id whose first bit is set — is
// unreachable if that is got wrong, and the failure is silent: those servers are
// simply never found.
//
// At Bits = 0 the range is the whole column, which is the correct answer for the
// query a client sends to a new instance, not an empty result.
//
// Above PrefixColumnBits the column cannot express the whole constraint. Range
// then returns the narrowest bounds it can — a single value, since the first 32
// bits are fully determined — and NeedsPostFilter reports true, meaning rows in
// range must still be checked against the full lookup_id with Matches. Parse
// does not reject such a query: how precise is too precise is the cap's
// decision, and the cap is a function of the record count.
func (q Query) Range() (lo, hi int64) {
	eb := q.Bits
	if eb > PrefixColumnBits {
		eb = PrefixColumnBits
	}
	span := uint64(1)<<(PrefixColumnBits-eb) - 1
	return int64(q.Prefix), int64(uint64(q.Prefix) | span)
}

// NeedsPostFilter reports whether a range scan over the prefix column is
// sufficient on its own. It is false for every query a directory of realistic
// size will accept, because the cap cannot exceed 32 below a record count of
// about 86 billion.
func (q Query) NeedsPostFilter() bool {
	return q.Bits > PrefixColumnBits
}

// Matches reports whether lookupID begins with the query's prefix. It is the
// post-filter NeedsPostFilter calls for, and is exact at any Bits.
func (q Query) Matches(lookupID []byte) bool {
	if uint(len(lookupID))*8 < q.Bits {
		return false
	}
	whole := q.Bits / 8
	if !bytes.Equal(q.Full[:whole], lookupID[:whole]) {
		return false
	}
	if rem := q.Bits % 8; rem != 0 {
		mask := byte(0xFF) << (8 - rem)
		if q.Full[whole]&mask != lookupID[whole]&mask {
			return false
		}
	}
	return true
}
