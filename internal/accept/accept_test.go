// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package accept

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trigstation/trigstationd/internal/b64"
	"github.com/trigstation/trigstationd/internal/derive"
	"github.com/trigstation/trigstationd/internal/pow"
	"github.com/trigstation/trigstationd/internal/record"
	"github.com/trigstation/trigstationd/internal/reject"
)

// testNow is the directory's clock for every test that does not set its own. It
// is 86400 * 20295, the first second of an epoch, which is the instant
// DIRECTORY-SPEC.md §4.2 uses in its worked example.
const testNow = 1753488000

// testPoWBits keeps the fixtures fast. §6.1's default of 20 bits is roughly
// 100 ms per solve; the difficulty is a parameter precisely because an instance
// may advertise its own, so exercising the pipeline at 8 bits tests the same
// code path. TestCommittedVectorIsAccepted runs at the real default.
const testPoWBits = 8

// testSDir is a counting pattern, not a secret. Same convention as
// internal/vectors: visibly, structurally fake.
var testSDir = countingBytes(0x00, derive.SDirLen)

func countingBytes(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

// testLimits are the §4.3 defaults with the proof-of-work difficulty lowered.
func testLimits() Limits {
	l := DefaultLimits()
	l.PoWBits = testPoWBits
	return l
}

// fixture is a complete, valid envelope built with the same derive/record/pow
// helpers a real publisher would use, so that each test can corrupt exactly one
// thing and observe that the corruption alone is what fails.
type fixture struct {
	wkPub     ed25519.PublicKey
	lookupID  []byte
	nonce     []byte
	ct        []byte
	expiresAt int64
	env       record.Envelope
}

func newFixture(t *testing.T, expiresAt int64) *fixture {
	t.Helper()

	ep := derive.Epoch(expiresAt)
	wk, err := derive.WriteKey(testSDir, ep)
	if err != nil {
		t.Fatalf("derive.WriteKey: %v", err)
	}
	wkPub := wk.Public().(ed25519.PublicKey)
	lookupID := derive.LookupID(wkPub)

	recordKey, err := derive.RecordKey(testSDir, ep)
	if err != nil {
		t.Fatalf("derive.RecordKey: %v", err)
	}
	nonce := countingBytes(0xa0, record.NonceLen)

	// SealWithNonce is a test-only helper — a directory never encrypts anything
	// and the production path must never reach it. Using it here keeps the
	// ciphertext a real AES-256-GCM output rather than filler.
	ct, err := record.SealWithNonce(recordKey, nonce, []byte(`{"v":1,"ts":1753488000}`))
	if err != nil {
		t.Fatalf("record.SealWithNonce: %v", err)
	}

	powValue, err := pow.Solve(context.Background(), lookupID, expiresAt, testPoWBits)
	if err != nil {
		t.Fatalf("pow.Solve: %v", err)
	}
	sig := record.Sign(wk, record.Version, lookupID, wkPub, expiresAt, nonce, ct)

	return &fixture{
		wkPub:     wkPub,
		lookupID:  lookupID,
		nonce:     nonce,
		ct:        ct,
		expiresAt: expiresAt,
		env: record.Envelope{
			V:         record.Version,
			LookupID:  b64.Encode(lookupID),
			WKPub:     b64.Encode(wkPub),
			ExpiresAt: expiresAt,
			CT:        b64.Encode(ct),
			Nonce:     b64.Encode(nonce),
			PoW:       b64.Encode(powValue),
			Sig:       b64.Encode(sig),
		},
	}
}

// valid returns a fixture expiring an hour after testNow.
func valid(t *testing.T) *fixture {
	t.Helper()
	return newFixture(t, testNow+3600)
}

// body marshals the fixture's envelope as it would be transmitted.
func (f *fixture) body(t *testing.T) []byte {
	t.Helper()
	raw, err := json.Marshal(f.env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return raw
}

// bodyWith marshals the envelope with members added, replaced or — for a nil
// value — removed, so that a test can reach cases a typed struct cannot express.
func (f *fixture) bodyWith(t *testing.T, edits map[string]any) []byte {
	t.Helper()

	var m map[string]any
	if err := json.Unmarshal(f.body(t), &m); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	for k, v := range edits {
		if v == nil {
			delete(m, k)
			continue
		}
		m[k] = v
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal edited envelope: %v", err)
	}
	return raw
}

// badPoW returns an 8-byte counter that is guaranteed not to satisfy the
// difficulty. Picking a fixed value such as all-zero would satisfy an 8-bit
// challenge roughly once in 256 runs, which is exactly the kind of flake a
// security test must not have.
func badPoW(t *testing.T, lookupID []byte, expiresAt int64, bits int) []byte {
	t.Helper()
	var v [pow.Len]byte
	for i := uint64(0); i < 1024; i++ {
		binary.BigEndian.PutUint64(v[:], i)
		if !pow.Verify(lookupID, expiresAt, v[:], bits) {
			return bytes.Clone(v[:])
		}
	}
	t.Fatal("could not find a counter failing the difficulty")
	return nil
}

// mustDecode decodes a base64url field of a fixture, which is known good.
func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := b64.Decode(s)
	if err != nil {
		t.Fatalf("decode fixture field: %v", err)
	}
	return b
}

// flip returns b with one bit of byte i inverted.
func flip(b []byte, i int) []byte {
	out := bytes.Clone(b)
	out[i] ^= 0x01
	return out
}

// TestStatusTableRows walks DIRECTORY-SPEC.md §5.2's status table, one subtest
// per row this package can reach.
//
// Each row is a security property rather than an error case, so each is
// provoked individually: the envelope is valid except for the single thing the
// row names. The two rows not here are rate limiting's sibling condition in
// §6.4, which the transport owns, and the recency rule, which needs a storage
// read and belongs to the caller.
func TestStatusTableRows(t *testing.T) {
	tests := []struct {
		name        string
		body        func(t *testing.T, f *fixture) []byte
		now         int64
		rateLimited bool
		want        reject.RecordReason
	}{
		{
			name: "accepted and stored",
			body: func(t *testing.T, f *fixture) []byte { return f.body(t) },
			want: reject.RecordAccepted,
		},
		{
			name:        "rate limited",
			body:        func(t *testing.T, f *fixture) []byte { return f.body(t) },
			rateLimited: true,
			want:        reject.RecordRateLimited,
		},
		{
			name: "received body exceeds max_record_bytes",
			body: func(t *testing.T, f *fixture) []byte {
				// An unknown member would normally be ignored under §10. Size is
				// measured on the bytes as transmitted, before any parsing, so
				// it is rejected regardless.
				return f.bodyWith(t, map[string]any{
					"padding": strings.Repeat("x", record.MaxEnvelopeBytes),
				})
			},
			want: reject.RecordTooLarge,
		},
		{
			name: "malformed: not well-formed JSON",
			body: func(t *testing.T, f *fixture) []byte {
				return append(f.body(t)[:len(f.body(t))-1], ',')
			},
			want: reject.RecordMalformed,
		},
		{
			name: "malformed: body is not a JSON object",
			body: func(t *testing.T, f *fixture) []byte {
				return []byte(`["v",1]`)
			},
			want: reject.RecordMalformed,
		},
		{
			name: "malformed: empty body",
			body: func(t *testing.T, f *fixture) []byte { return nil },
			want: reject.RecordMalformed,
		},
		{
			name: "malformed: required member absent",
			body: func(t *testing.T, f *fixture) []byte {
				return f.bodyWith(t, map[string]any{"wk_pub": nil})
			},
			want: reject.RecordMalformed,
		},
		{
			name: "malformed: value is not valid base64url",
			body: func(t *testing.T, f *fixture) []byte {
				return f.bodyWith(t, map[string]any{"sig": "!!!!"})
			},
			want: reject.RecordMalformed,
		},
		{
			name: "malformed: fixed-width field decodes to the wrong length",
			body: func(t *testing.T, f *fixture) []byte {
				return f.bodyWith(t, map[string]any{"nonce": b64.Encode(make([]byte, 16))})
			},
			want: reject.RecordMalformed,
		},
		{
			name: "v is not 1",
			body: func(t *testing.T, f *fixture) []byte {
				return f.bodyWith(t, map[string]any{"v": 2})
			},
			want: reject.RecordBadVersion,
		},
		{
			name: "expires_at exceeds now + max_ttl",
			body: func(t *testing.T, f *fixture) []byte {
				return newFixture(t, testNow+record.MaxTTL+DefaultSkewGrace+1).body(t)
			},
			want: reject.RecordTTLTooLong,
		},
		{
			name: "lookup_id is not SHA-256(wk_pub)",
			body: func(t *testing.T, f *fixture) []byte {
				return f.bodyWith(t, map[string]any{
					"lookup_id": b64.Encode(flip(f.lookupID, 0)),
				})
			},
			want: reject.RecordLookupMismatch,
		},
		{
			name: "pow does not satisfy pow_bits",
			body: func(t *testing.T, f *fixture) []byte {
				return f.bodyWith(t, map[string]any{
					"pow": b64.Encode(badPoW(t, f.lookupID, f.expiresAt, testPoWBits)),
				})
			},
			want: reject.RecordPoWInsufficient,
		},
		{
			name: "sig does not verify under wk_pub",
			body: func(t *testing.T, f *fixture) []byte {
				sig, err := b64.Decode(f.env.Sig)
				if err != nil {
					t.Fatalf("decode sig: %v", err)
				}
				return f.bodyWith(t, map[string]any{"sig": b64.Encode(flip(sig, 0))})
			},
			want: reject.RecordSigInvalid,
		},
		{
			name: "expires_at is not strictly greater than the current time",
			body: func(t *testing.T, f *fixture) []byte {
				return newFixture(t, testNow-1).body(t)
			},
			want: reject.RecordExpired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := valid(t)
			now := tt.now
			if now == 0 {
				now = testNow
			}

			got, d := Check(tt.body(t, f), now, testLimits(), tt.rateLimited)
			if got != tt.want {
				t.Fatalf("Check = %d (status %d), want %d (status %d)",
					int(got), got.HTTPStatus(), int(tt.want), tt.want.HTTPStatus())
			}
			if tt.want == reject.RecordAccepted {
				if d == nil {
					t.Fatal("accepted but no decoded envelope returned")
				}
				return
			}
			if d != nil {
				t.Error("a rejection returned a decoded envelope; it must be nil")
			}
		})
	}
}

// TestValidEnvelopeIsAccepted checks the success case in full: the decoded
// envelope handed back must be the one that was sent, so the caller can apply
// the recency rule and index the record without parsing a second time.
func TestValidEnvelopeIsAccepted(t *testing.T) {
	f := valid(t)
	body := f.body(t)

	reason, d := Check(body, testNow, testLimits(), false)
	if reason != reject.RecordAccepted {
		t.Fatalf("Check = %d, want RecordAccepted", int(reason))
	}
	if d == nil {
		t.Fatal("no decoded envelope returned")
	}
	if d.V != record.Version {
		t.Errorf("decoded v = %d, want %d", d.V, record.Version)
	}
	if d.ExpiresAt != f.expiresAt {
		t.Errorf("decoded expires_at = %d, want %d", d.ExpiresAt, f.expiresAt)
	}
	if !bytes.Equal(d.LookupID, f.lookupID) {
		t.Error("decoded lookup_id does not match the fixture")
	}
	if !bytes.Equal(d.WKPub, f.wkPub) {
		t.Error("decoded wk_pub does not match the fixture")
	}
	if !bytes.Equal(d.CT, f.ct) {
		t.Error("decoded ct does not match the fixture")
	}
	if !bytes.Equal(d.Nonce, f.nonce) {
		t.Error("decoded nonce does not match the fixture")
	}

	// The bytes to store are the caller's own, unaltered (§5.2). Nothing here
	// may have touched them.
	if !bytes.Equal(body, f.body(t)) {
		t.Error("Check mutated the received body")
	}
}

// TestFirstFailingConditionWins is the test that proves the evaluation order is
// real rather than incidental.
//
// §5.2 requires the directory to return the code of the *first* condition that
// fails, so a request violating three conditions has exactly one correct
// answer. Asserting merely that such a request is rejected would pass against
// any order, and a publisher's retry logic — driven entirely by the code —
// would then diverge between directories.
func TestFirstFailingConditionWins(t *testing.T) {
	tests := []struct {
		name        string
		violations  string
		body        func(t *testing.T, f *fixture) []byte
		now         int64
		rateLimited bool
		want        reject.RecordReason
	}{
		{
			name:        "rate limited beats size and malformation",
			violations:  "rate limited, oversized, not JSON",
			rateLimited: true,
			body: func(t *testing.T, f *fixture) []byte {
				return []byte("{" + strings.Repeat("x", record.MaxEnvelopeBytes))
			},
			want: reject.RecordRateLimited,
		},
		{
			name:       "size beats malformation and version",
			violations: "oversized, not JSON, v absent",
			body: func(t *testing.T, f *fixture) []byte {
				return []byte("{\"v\":9," + strings.Repeat("x", record.MaxEnvelopeBytes))
			},
			want: reject.RecordTooLarge,
		},
		{
			name:       "malformation beats version, TTL and signature",
			violations: "sig not base64url, v = 2, expires_at beyond max_ttl",
			body: func(t *testing.T, f *fixture) []byte {
				return f.bodyWith(t, map[string]any{
					"sig":        "!!!!",
					"v":          2,
					"expires_at": testNow + record.MaxTTL + DefaultSkewGrace + 1,
				})
			},
			want: reject.RecordMalformed,
		},
		{
			name:       "version beats TTL and lookup_id",
			violations: "v = 0, expires_at beyond max_ttl, lookup_id mismatched",
			body: func(t *testing.T, f *fixture) []byte {
				return f.bodyWith(t, map[string]any{
					"v":          0,
					"expires_at": testNow + record.MaxTTL + DefaultSkewGrace + 1,
					"lookup_id":  b64.Encode(flip(f.lookupID, 0)),
				})
			},
			want: reject.RecordBadVersion,
		},
		{
			name:       "TTL beats lookup_id, pow and signature",
			violations: "expires_at beyond max_ttl, lookup_id mismatched, pow and sig therefore invalid",
			body: func(t *testing.T, f *fixture) []byte {
				return f.bodyWith(t, map[string]any{
					"expires_at": testNow + record.MaxTTL + DefaultSkewGrace + 1,
					"lookup_id":  b64.Encode(flip(f.lookupID, 0)),
				})
			},
			want: reject.RecordTTLTooLong,
		},
		{
			name:       "lookup_id beats pow and signature",
			violations: "lookup_id mismatched, pow invalid, sig invalid",
			body: func(t *testing.T, f *fixture) []byte {
				sig, err := b64.Decode(f.env.Sig)
				if err != nil {
					t.Fatalf("decode sig: %v", err)
				}
				return f.bodyWith(t, map[string]any{
					"lookup_id": b64.Encode(flip(f.lookupID, 0)),
					"pow":       b64.Encode(badPoW(t, f.lookupID, f.expiresAt, testPoWBits)),
					"sig":       b64.Encode(flip(sig, 0)),
				})
			},
			want: reject.RecordLookupMismatch,
		},
		{
			name:       "pow beats signature and expiry",
			violations: "pow invalid, sig invalid, expires_at in the past",
			body: func(t *testing.T, f *fixture) []byte {
				past := newFixture(t, testNow-1)
				sig, err := b64.Decode(past.env.Sig)
				if err != nil {
					t.Fatalf("decode sig: %v", err)
				}
				return past.bodyWith(t, map[string]any{
					"pow": b64.Encode(badPoW(t, past.lookupID, past.expiresAt, testPoWBits)),
					"sig": b64.Encode(flip(sig, 0)),
				})
			},
			want: reject.RecordPoWInsufficient,
		},
		{
			// The last two conditions this package evaluates, so only two can be
			// violated at once below the proof of work.
			name:       "signature beats expiry",
			violations: "sig invalid, expires_at in the past",
			body: func(t *testing.T, f *fixture) []byte {
				past := newFixture(t, testNow-1)
				sig, err := b64.Decode(past.env.Sig)
				if err != nil {
					t.Fatalf("decode sig: %v", err)
				}
				return past.bodyWith(t, map[string]any{"sig": b64.Encode(flip(sig, 0))})
			},
			want: reject.RecordSigInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := valid(t)
			now := tt.now
			if now == 0 {
				now = testNow
			}

			got, _ := Check(tt.body(t, f), now, testLimits(), tt.rateLimited)
			if got != tt.want {
				t.Fatalf("violations (%s): Check = %d (status %d), want %d (status %d)",
					tt.violations, int(got), got.HTTPStatus(), int(tt.want), tt.want.HTTPStatus())
			}
		})
	}
}

// TestTTLBoundaries pins the clock skew grace of DIRECTORY-SPEC.md §5.2 at both
// ends.
//
// The grace is not a fudge. expires_at is computed from the publisher's clock
// and evaluated against the directory's, and neither can observe the other's. A
// server configured to exactly max_ttl is rejected by every directory whose
// clock is behind, which presents as a directory that rejects every publish for
// no visible reason. Removing the grace passes a naive reading of the status
// table and breaks that publisher.
func TestTTLBoundaries(t *testing.T) {
	lim := testLimits()

	tests := []struct {
		name      string
		expiresAt int64
		want      reject.RecordReason
	}{
		{"exactly max_ttl", testNow + lim.MaxTTL, reject.RecordAccepted},
		{"one second inside the grace", testNow + lim.MaxTTL + lim.SkewGrace - 1, reject.RecordAccepted},
		{"exactly max_ttl plus the grace", testNow + lim.MaxTTL + lim.SkewGrace, reject.RecordAccepted},
		{"one second beyond the grace", testNow + lim.MaxTTL + lim.SkewGrace + 1, reject.RecordTTLTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, tt.expiresAt)
			got, _ := Check(f.body(t), testNow, lim, false)
			if got != tt.want {
				t.Errorf("expires_at = now + %d: Check = %d, want %d",
					tt.expiresAt-testNow, int(got), int(tt.want))
			}
		})
	}
}

// TestTTLGraceIsConfigurable asserts the grace is a limit and not a constant
// baked into the comparison. §5.2 states it as a SHOULD, so an instance may
// enforce the bound exactly; an instance that does must still accept exactly
// max_ttl.
func TestTTLGraceIsConfigurable(t *testing.T) {
	lim := testLimits()
	lim.SkewGrace = 0

	for _, tt := range []struct {
		name      string
		expiresAt int64
		want      reject.RecordReason
	}{
		{"exactly max_ttl", testNow + lim.MaxTTL, reject.RecordAccepted},
		{"one second beyond max_ttl", testNow + lim.MaxTTL + 1, reject.RecordTTLTooLong},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, tt.expiresAt)
			if got, _ := Check(f.body(t), testNow, lim, false); got != tt.want {
				t.Errorf("Check = %d, want %d", int(got), int(tt.want))
			}
		})
	}
}

// TestExpiryIsStrict covers the lower bound. §5.2 says "strictly greater than
// the directory's current time", and §5.2 also says a record whose expires_at
// has passed is absent for every purpose — so a record expiring exactly now is
// already absent and must not be storable.
func TestExpiryIsStrict(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt int64
		want      reject.RecordReason
	}{
		{"one second in the past", testNow - 1, reject.RecordExpired},
		{"exactly now", testNow, reject.RecordExpired},
		{"one second in the future", testNow + 1, reject.RecordAccepted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, tt.expiresAt)
			if got, _ := Check(f.body(t), testNow, testLimits(), false); got != tt.want {
				t.Errorf("Check = %d, want %d", int(got), int(tt.want))
			}
		})
	}
}

// TestSizeBoundary pins "exceeds" as strictly greater, measured on the bytes as
// transmitted.
func TestSizeBoundary(t *testing.T) {
	f := valid(t)
	body := f.body(t)

	lim := testLimits()
	lim.MaxRecordBytes = len(body)
	if got, _ := Check(body, testNow, lim, false); got != reject.RecordAccepted {
		t.Errorf("a body of exactly max_record_bytes: Check = %d, want RecordAccepted", int(got))
	}

	lim.MaxRecordBytes = len(body) - 1
	if got, _ := Check(body, testNow, lim, false); got != reject.RecordTooLarge {
		t.Errorf("a body one byte over: Check = %d, want RecordTooLarge", int(got))
	}
}

// TestBase64Spelling covers the §5.2 row for a value that is not valid unpadded
// base64url, in each of the ways a field can be spelled wrongly.
//
// §4.4 rejects padded and non-canonical input outright, and internal/b64
// enforces both, so this pipeline no longer carries its own check. The cases
// stay here regardless: they assert the behaviour at the boundary that actually
// faces the wire, which is where a regression in the decoder would matter, and
// they would fail if the rule were ever relaxed a layer down. See DECISIONS.md
// C-9 and C-10.
func TestBase64Spelling(t *testing.T) {
	tests := []struct {
		name   string
		member string
		value  func(f *fixture) string
	}{
		{
			name:   "lookup_id with padding",
			member: "lookup_id",
			value:  func(f *fixture) string { return b64.Encode(f.lookupID) + "=" },
		},
		{
			name:   "nonce with padding",
			member: "nonce",
			// 12 bytes is 16 base64 characters with no padding; a padded encoder
			// would not add any here, so the '=' is appended explicitly.
			value: func(f *fixture) string { return b64.Encode(f.nonce) + "==" },
		},
		{
			name:   "ct with padding",
			member: "ct",
			value:  func(f *fixture) string { return b64.Encode(f.ct) + "=" },
		},
		{
			name:   "standard alphabet rather than base64url",
			member: "sig",
			value:  func(f *fixture) string { return "+/8" + b64.Encode(make([]byte, 60)) },
		},
		{
			name:   "fixed-width field one byte too long",
			member: "wk_pub",
			value:  func(f *fixture) string { return b64.Encode(make([]byte, record.WKPubLen+1)) },
		},
		{
			name:   "fixed-width field one byte too short",
			member: "wk_pub",
			value:  func(f *fixture) string { return b64.Encode(make([]byte, record.WKPubLen-1)) },
		},
		{
			name:   "fixed-width field empty",
			member: "pow",
			value:  func(f *fixture) string { return "" },
		},
		{
			name:   "ct shorter than the AEAD tag",
			member: "ct",
			value:  func(f *fixture) string { return b64.Encode(make([]byte, record.TagLen-1)) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := valid(t)
			body := f.bodyWith(t, map[string]any{tt.member: tt.value(f)})
			if got, _ := Check(body, testNow, testLimits(), false); got != reject.RecordMalformed {
				t.Errorf("Check = %d (status %d), want RecordMalformed (400)", int(got), got.HTTPStatus())
			}
		})
	}
}

// TestRequiredMembers asserts that each of the eight §4.1 members is required,
// and that an explicit null is treated the same as an absent member.
//
// The expires_at row is the one that matters on the wire: left as a present
// zero it would clear the TTL bound and be rejected at the proof of work with
// 403, where §5.2 makes an absent required member 400.
func TestRequiredMembers(t *testing.T) {
	for _, member := range requiredMembers {
		t.Run("absent "+member, func(t *testing.T) {
			f := valid(t)
			body := f.bodyWith(t, map[string]any{member: nil})
			if got, _ := Check(body, testNow, testLimits(), false); got != reject.RecordMalformed {
				t.Errorf("Check = %d (status %d), want RecordMalformed (400)", int(got), got.HTTPStatus())
			}
		})

		t.Run("null "+member, func(t *testing.T) {
			f := valid(t)
			body := f.bodyWith(t, map[string]any{member: nil})

			// bodyWith deletes on nil, so the null form is spliced in directly.
			var m map[string]json.RawMessage
			if err := json.Unmarshal(f.body(t), &m); err != nil {
				t.Fatal(err)
			}
			m[member] = json.RawMessage("null")
			body, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}

			if got, _ := Check(body, testNow, testLimits(), false); got != reject.RecordMalformed {
				t.Errorf("Check = %d (status %d), want RecordMalformed (400)", int(got), got.HTTPStatus())
			}
		})
	}
}

// TestVersionIsRejectedNotIgnored is the §4.1 rule stated as a test: v pins the
// format, so it is not an unknown field and must not be ignored under the
// unknown-field rule of §10.
func TestVersionIsRejectedNotIgnored(t *testing.T) {
	for _, v := range []any{0, 2, 3, -1, 255} {
		t.Run(fmt.Sprintf("v = %v", v), func(t *testing.T) {
			f := valid(t)
			body := f.bodyWith(t, map[string]any{"v": v})
			if got, _ := Check(body, testNow, testLimits(), false); got != reject.RecordBadVersion {
				t.Errorf("Check = %d (status %d), want RecordBadVersion (400)", int(got), got.HTTPStatus())
			}
		})
	}
}

// TestUnknownMembersAreIgnored is required by §5 and §10: unknown members MUST
// be ignored, never rejected, or no additive change to v1 is ever deployable.
// A directory written today must accept an envelope carrying a member
// introduced tomorrow, and store and re-serve it verbatim.
func TestUnknownMembersAreIgnored(t *testing.T) {
	f := valid(t)
	body := f.bodyWith(t, map[string]any{
		"a_member_from_a_later_revision": "ignore me",
		"another":                        map[string]any{"nested": 1},
		"a_number":                       42,
	})

	got, d := Check(body, testNow, testLimits(), false)
	if got != reject.RecordAccepted {
		t.Fatalf("unknown members caused a rejection: Check = %d (status %d)", int(got), got.HTTPStatus())
	}
	if d == nil {
		t.Fatal("no decoded envelope returned")
	}
	if !bytes.Equal(d.LookupID, f.lookupID) {
		t.Error("decoded lookup_id does not match the fixture")
	}
}

// TestMalformedTypes covers members present with the right name and the wrong
// JSON type. All of these are 400 under §5.2 either as a malformed body or, for
// v, as a bad version; the reason constants differ but the status does not.
func TestMalformedTypes(t *testing.T) {
	tests := []struct {
		name  string
		edits map[string]any
	}{
		{"v as a string", map[string]any{"v": "1"}},
		{"expires_at as a string", map[string]any{"expires_at": "1753574400"}},
		{"expires_at as a fraction", map[string]any{"expires_at": 1753574400.5}},
		{"expires_at beyond int64", map[string]any{"expires_at": json.RawMessage("18446744073709551616")}},
		{"lookup_id as a number", map[string]any{"lookup_id": 1}},
		{"lookup_id as an object", map[string]any{"lookup_id": map[string]any{}}},
		{"sig as an array", map[string]any{"sig": []any{1, 2}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := valid(t)
			body := f.bodyWith(t, tt.edits)
			got, _ := Check(body, testNow, testLimits(), false)
			if got.HTTPStatus() != 400 {
				t.Errorf("Check = %d (status %d), want status 400", int(got), got.HTTPStatus())
			}
		})
	}
}

// TestCommittedVectorIsAccepted runs the envelope from testdata/vectors.json
// through the pipeline at the real §6.1 difficulty.
//
// The fixtures above are generated by this codebase, so on their own they would
// only prove the pipeline agrees with itself. The committed vector is the
// artefact independent implementations check against, and §9 requires it to be
// a deliverable rather than a by-product — so the acceptance path is grounded
// in it, using the file's literal bytes rather than a re-serialisation.
func TestCommittedVectorIsAccepted(t *testing.T) {
	body, expiresAt, lookupID := committedEnvelope(t)

	// An hour before the vector's expiry: inside max_ttl and not yet lapsed.
	now := expiresAt - 3600

	lim := DefaultLimits()
	if len(body) > lim.MaxRecordBytes {
		t.Fatalf("the committed envelope is %d bytes, over the §4.3 cap of %d", len(body), lim.MaxRecordBytes)
	}

	got, d := Check(body, now, lim, false)
	if got != reject.RecordAccepted {
		t.Fatalf("the committed vector was rejected: Check = %d (status %d)", int(got), got.HTTPStatus())
	}
	if d.ExpiresAt != expiresAt {
		t.Errorf("decoded expires_at = %d, want %d", d.ExpiresAt, expiresAt)
	}
	if b64.Encode(d.LookupID) != lookupID {
		t.Error("decoded lookup_id does not match the vector")
	}

	// The vector was solved at the default difficulty, so raising the bar must
	// reject it. §6.1 lets an instance raise pow_bits under load.
	lim.PoWBits = pow.DefaultBits + 4
	if got, _ := Check(body, now, lim, false); got != reject.RecordPoWInsufficient {
		t.Errorf("at a raised difficulty: Check = %d, want RecordPoWInsufficient", int(got))
	}

	// And past its own expiry it is no longer storable, whatever else holds.
	if got, _ := Check(body, expiresAt, DefaultLimits(), false); got != reject.RecordExpired {
		t.Errorf("at expires_at: Check = %d, want RecordExpired", int(got))
	}
}

// committedEnvelope returns the literal envelope bytes from
// testdata/vectors.json, together with the expiry and lookup_id the file
// declares for them.
func committedEnvelope(t *testing.T) (body []byte, expiresAt int64, lookupID string) {
	t.Helper()

	path := filepath.Join("..", "..", "testdata", "vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v (run: go run ./cmd/gen-vectors -o testdata/vectors.json)", err)
	}

	var file struct {
		Envelope struct {
			Envelope json.RawMessage `json:"envelope"`
		} `json:"envelope"`
		PoW struct {
			ExpiresAt int64  `json:"expires_at"`
			LookupID  string `json:"lookup_id"`
		} `json:"pow"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(file.Envelope.Envelope) == 0 {
		t.Fatal("vectors.json has no envelope.envelope member")
	}
	return file.Envelope.Envelope, file.PoW.ExpiresAt, file.PoW.LookupID
}

// TestNoIdentifierEscapes is a security property, not tidiness.
//
// This package sees every rejected envelope, which makes it the likeliest
// breach point in the codebase for the "no request logging" rule. Its rejection
// surface is deliberately a bare integer: there is no error value to carry a
// lookup_id, a wk_pub, a ciphertext or an address, and no place a value is
// formatted into a message.
//
// The test feeds envelopes carrying recognisable byte patterns through every
// rejection path and asserts the patterns appear in nothing the package
// returns.
func TestNoIdentifierEscapes(t *testing.T) {
	const marker = "MARKER-THIS-IDENTIFIER-MUST-NOT-ESCAPE"

	f := valid(t)
	expired := newFixture(t, testNow-1)
	markerB64 := b64.Encode([]byte(marker))

	bodies := [][]byte{
		[]byte(`{"` + marker + `":`),
		[]byte(`{"lookup_id":"` + marker + `"}`),
		f.bodyWith(t, map[string]any{"lookup_id": markerB64}),
		f.bodyWith(t, map[string]any{"wk_pub": markerB64}),
		f.bodyWith(t, map[string]any{"ct": markerB64}),
		f.bodyWith(t, map[string]any{"nonce": markerB64}),
		f.bodyWith(t, map[string]any{"pow": markerB64}),
		f.bodyWith(t, map[string]any{"sig": markerB64}),
		f.bodyWith(t, map[string]any{"padding": marker + strings.Repeat("x", record.MaxEnvelopeBytes)}),

		// The remaining rejection paths, each reached with an address-shaped
		// marker riding along in an unknown member. Everything past the parse
		// stage is covered here, so no branch of Check is exercised only by
		// envelopes without a recognisable pattern in them.
		f.bodyWith(t, map[string]any{
			"a_host": marker + ".example.net",
			"v":      2,
		}),
		f.bodyWith(t, map[string]any{
			"a_host":     marker + ".example.net",
			"expires_at": testNow + record.MaxTTL + DefaultSkewGrace + 1,
		}),
		f.bodyWith(t, map[string]any{
			"a_host":    marker + ".example.net",
			"lookup_id": b64.Encode(flip(f.lookupID, 0)),
		}),
		f.bodyWith(t, map[string]any{
			"a_host": marker + ".example.net",
			"pow":    b64.Encode(badPoW(t, f.lookupID, f.expiresAt, testPoWBits)),
		}),
		f.bodyWith(t, map[string]any{
			"a_host": marker + ".example.net",
			"sig":    b64.Encode(flip(mustDecode(t, f.env.Sig), 0)),
		}),
		expired.bodyWith(t, map[string]any{"a_host": marker + ".example.net"}),
	}

	// Every rejection reason this package can return must appear above, or the
	// guard has an untested branch.
	seen := make(map[reject.RecordReason]bool)

	for i, body := range bodies {
		for _, rateLimited := range []bool{false, true} {
			reason, d := Check(body, testNow, testLimits(), rateLimited)
			if d != nil {
				t.Fatalf("body %d: a marker envelope was accepted", i)
			}
			seen[reason] = true
			// Every rendering a caller could plausibly reach for.
			for _, s := range []string{
				fmt.Sprint(reason),
				fmt.Sprintf("%v|%#v|%d|%d", reason, reason, reason.HTTPStatus(), int(reason)),
			} {
				if strings.Contains(s, marker) || strings.Contains(s, markerB64) {
					t.Errorf("body %d: rejection surface leaked the offending value: %q", i, s)
				}
			}
		}
	}

	// RecordNotNewer is the caller's, so it is the one reason absent by design.
	for r := reject.RecordRateLimited; r < reject.RecordNotNewer; r++ {
		if !seen[r] {
			t.Errorf("rejection reason %d was never provoked by a marker envelope; that branch is unguarded", int(r))
		}
	}
}

// TestPackageProducesNoErrorStrings backs TestNoIdentifierEscapes with the
// stronger structural claim: there is no error value in this package at all, so
// there is nothing that could be formatted with an identifier in it later.
//
// If a future change needs to return an error, it must be added deliberately
// and this test updated deliberately — which is the point.
func TestPackageProducesNoErrorStrings(t *testing.T) {
	for _, name := range packageSources(t, false) {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, banned := range []string{"errors.New", "fmt.Errorf", "fmt.Sprintf", "fmt.Sprint"} {
			if bytes.Contains(src, []byte(banned)) {
				t.Errorf("%s uses %s; this package must not format values into strings", name, banned)
			}
		}
	}
}

// TestNoLoggingImports is the "no request logging" rule enforced mechanically.
//
// The requirement is that the code to log must not exist — not disabled, not
// behind a flag, not at debug level. A directory operator who cannot log is one
// who cannot be compelled to produce logs, and that property survives only if
// it is checked rather than remembered.
func TestNoLoggingImports(t *testing.T) {
	banned := map[string]bool{
		`"log"`:        true,
		`"log/slog"`:   true,
		`"log/syslog"`: true,
	}

	fset := token.NewFileSet()
	for _, name := range packageSources(t, true) {
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imp := range f.Imports {
			if banned[imp.Path.Value] {
				t.Errorf("%s imports %s; the code to log must not exist", name, imp.Path.Value)
			}
		}
	}
}

// packageSources lists this package's own .go files. Tests are included only
// when includeTests is set: the no-logging rule covers everything in the
// package, whereas the no-error-strings rule is about the production surface.
func packageSources(t *testing.T, includeTests bool) []string {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}

	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		if !includeTests && strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		t.Fatal("no source files found; the guard would pass vacuously")
	}
	return out
}
