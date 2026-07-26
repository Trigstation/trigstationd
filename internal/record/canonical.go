// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package record

import "encoding/binary"

// Byte offsets of the envelope signing input, DIRECTORY-SPEC.md §4.1.
//
// FixedPrefixLen is the total width of every field that precedes ct. It is a
// constant, and the test suite asserts that it stays one — see the injectivity
// note on CanonicalEnvelope.
const (
	canonVLen         = 1
	canonExpiresAtLen = 8
	FixedPrefixLen    = canonVLen + LookupIDLen + WKPubLen + canonExpiresAtLen + NonceLen // 85
)

// CanonicalEnvelope builds the byte string that the envelope signature covers
// (DIRECTORY-SPEC.md §4.1):
//
//	sig = Ed25519(WK_priv, canonical(v, lookup_id, wk_pub, expires_at, nonce, ct))
//
// canonical() is the concatenation of the raw byte values in that order, with
// integers encoded per §0.1 — fixed-width unsigned big-endian, never decimal
// text. The widths are tabulated in §4.1:
//
//	v           1         uint8
//	lookup_id   32        raw bytes
//	wk_pub      32        raw bytes
//	expires_at  8         uint64 big-endian
//	nonce       12        raw bytes
//	ct          variable  raw bytes, to the end
//
// §4.4 distinguishes this signature from the payload's: this one is over raw
// concatenated field values because the directory must parse those fields
// anyway and all but the last are fixed-width. It is NOT over the JSON — key
// ordering and whitespace are not stable across implementations. The payload
// signature (§4.2) works the opposite way, over literal transmitted bytes with
// no canonicalisation at all. Do not unify them.
//
// # Injectivity is a normative constraint, not an accident
//
// §4.1 states it directly: bare concatenation is safe here ONLY because exactly
// one field is variable-length and it is last. With two adjacent variable-length
// fields an attacker able to influence one could shift bytes between them and
// produce a colliding signing input, making the signature forgeable.
//
// Therefore, per §4.1 and §10: any field added to this signing input MUST be
// fixed-width, and MUST be inserted BEFORE ct. Appending after ct, or inserting
// anything variable-length, breaks the security property rather than merely the
// wire format.
//
// TestCanonicalEnvelopeInjectivity encodes this. It asserts that everything
// before ct sums to exactly FixedPrefixLen regardless of ct, and that ct
// occupies the entire tail. A change that violates the rule fails that test
// rather than shipping.
func CanonicalEnvelope(v uint8, lookupID, wkPub []byte, expiresAt int64, nonce, ct []byte) []byte {
	out := make([]byte, 0, FixedPrefixLen+len(ct))
	out = append(out, v)
	out = append(out, lookupID...)
	out = append(out, wkPub...)
	out = binary.BigEndian.AppendUint64(out, uint64(expiresAt))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out
}
