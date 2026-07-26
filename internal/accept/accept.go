// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

// Package accept implements the envelope acceptance pipeline of
// DIRECTORY-SPEC.md §5.2.
//
// It is one pure function. Received bytes, a clock reading and the instance's
// limits go in; a reject.RecordReason comes out. There is no I/O, no storage,
// no network and no clock read — the caller passes now — so the whole of the
// publish decision that does not require a database is testable as a table.
//
// # What this package deliberately does not do
//
// Two of the eleven rows of the §5.2 status table are not implemented here.
//
// Rate limiting is passed in as a bool. It belongs to the transport, because it
// is the only part of the service that touches a client address at all, and
// §6.4 constrains how that address may be handled. Nothing in this package ever
// sees one.
//
// The recency rule (reject.RecordNotNewer) is the caller's, because it is the
// only condition requiring a storage read. Check stops at exactly the point
// where storage must be consulted: on reject.RecordAccepted the caller must
// still compare expires_at against any unexpired stored record under the same
// lookup_id before storing. That split is why RecordNotNewer is last in the
// §5.2 order — a rejected publish never touches the database.
//
// # The evaluation order is wire format
//
// §5.2 requires the conditions to be evaluated in the order of its table, and
// the directory to return the code of the *first* one that fails. A request
// violating three conditions therefore has exactly one correct answer, and a
// publisher's retry logic — driven entirely by the status code — depends on
// getting the same answer from every directory.
//
// Check walks reject.RecordReason in declaration order, which is that order.
// The sequence of conditions below is not stylistic and must not be tidied:
// lookup_id and pow are two SHA-256 computations and precede the Ed25519
// signature verification, which costs roughly two orders of magnitude more, so
// a flooding client is rejected on the cheap check.
//
// # Envelopes are not re-serialised
//
// Check returns the decoded envelope so the caller need not parse twice, but
// the bytes to store are the ones passed in. §5.2 requires a directory to
// retain the envelope as the byte sequence it received and reproduce those
// bytes unchanged in §5.3 responses; re-serialising from the fields parsed here
// would silently strip any member added under §10.
//
// # No identifiers escape
//
// This package sees every rejected envelope, so it is the likeliest place in
// the codebase to leak one. It therefore produces no error values at all: the
// only rejection surface is an integer reason. There is nothing here that
// formats a lookup_id, a wk_pub, a ciphertext or an address into a string, and
// TestNoIdentifierEscapes asserts it stays that way.
package accept

import (
	"bytes"
	"encoding/json"

	"github.com/trigstation/trigstationd/internal/pow"
	"github.com/trigstation/trigstationd/internal/record"
	"github.com/trigstation/trigstationd/internal/reject"
)

// DefaultSkewGrace is the clock skew allowance of DIRECTORY-SPEC.md §5.2, in
// seconds.
//
// expires_at is computed from the publisher's clock and evaluated against the
// directory's, and neither party can observe the other's. A server that
// requests exactly max_ttl is therefore rejected by any directory whose clock
// is behind its own, which presents as a directory that rejects every publish
// for no visible reason. §5.2 closes that from both ends: servers SHOULD leave
// 300 seconds of headroom, and directories SHOULD allow 300 seconds of grace
// above max_ttl. Both, not either.
//
// It is a grace on the upper bound only. The lower bound — expires_at strictly
// greater than now — has none, and must not acquire one: that check is what
// makes a lapsed record unstorable, and §5.2 relies on it to close the replay
// window that the recency rule would otherwise leave open once a stored record
// has itself expired.
const DefaultSkewGrace = 300

// Limits are the instance's advertised bounds, the ones GET /v1/meta publishes.
//
// They are parameters rather than constants because §6.1 lets an instance raise
// pow_bits under load and §5.1 lets it advertise its own max_record_bytes and
// max_ttl. Clients MUST read the advertised values rather than hardcoding them.
type Limits struct {
	// MaxRecordBytes is measured against the received body as transmitted,
	// before any parsing (§5.2). Default 4096 (§4.3).
	MaxRecordBytes int

	// MaxTTL is the maximum record lifetime in seconds. Default 48 hours (§4.3).
	MaxTTL int64

	// PoWBits is the proof-of-work difficulty (§6.1). Default 20.
	PoWBits int

	// SkewGrace is the allowance above MaxTTL, in seconds. See DefaultSkewGrace.
	SkewGrace int64
}

// DefaultLimits returns the limits DIRECTORY-SPEC.md §4.3 and §6.1 give as
// defaults. An operator may lower any of them; an instance advertises whatever
// it actually enforces.
func DefaultLimits() Limits {
	return Limits{
		MaxRecordBytes: record.MaxEnvelopeBytes,
		MaxTTL:         record.MaxTTL,
		PoWBits:        pow.DefaultBits,
		SkewGrace:      DefaultSkewGrace,
	}
}

// requiredMembers is the envelope schema of DIRECTORY-SPEC.md §4.1. Every one
// of the eight is needed to evaluate §5.2, so an envelope missing any of them
// is malformed rather than merely unusual.
//
// Presence is checked explicitly rather than inferred from the decoded value,
// because encoding/json cannot distinguish an absent member from a present zero
// and the two draw different codes. An absent expires_at left as zero would
// sail past the TTL bound and be rejected at the proof of work with 403, where
// §5.2 says an absent required member is 400.
var requiredMembers = [...]string{
	"v", "lookup_id", "wk_pub", "expires_at", "ct", "nonce", "pow", "sig",
}

// Check applies the DIRECTORY-SPEC.md §5.2 conditions, in their normative
// order, to a received PUT /v1/record body.
//
// rateLimited is the outcome of the transport's per-source limiter (§6.4),
// evaluated first so that a flood costs the directory as little as possible.
// now is the directory's current time in Unix seconds; it is a parameter so
// that this function is pure and its boundary behaviour is testable exactly.
//
// It returns reject.RecordAccepted and the decoded envelope when every
// condition it can evaluate without storage passes. The caller must then apply
// the last condition — the recency rule — and, on success, store the body bytes
// it passed in, verbatim.
//
// On any rejection the returned *record.Decoded is nil and the reason is the
// first condition that failed.
func Check(body []byte, now int64, lim Limits, rateLimited bool) (reject.RecordReason, *record.Decoded) {
	// 1. Rate limited. Before parsing, before measuring: the cheapest possible
	// rejection for the request pattern that most needs to be cheap.
	if rateLimited {
		return reject.RecordRateLimited, nil
	}

	// 2. Received body exceeds max_record_bytes, measured on the bytes as
	// transmitted, before any parsing (§5.2).
	if len(body) > lim.MaxRecordBytes {
		return reject.RecordTooLarge, nil
	}

	// 3. Malformed: not well-formed JSON, an absent required member, a value
	// that is not valid unpadded base64url, or a fixed-width field that decodes
	// to the wrong length.
	env, ok := parse(body)
	if !ok {
		return reject.RecordMalformed, nil
	}

	// record.Decode checks the version before the fields, whereas §5.2 orders
	// malformation ahead of a bad version. Decoding through a copy whose version
	// is the supported one applies the field checks alone, and the real version
	// is checked immediately after. The alternative — restating the §4.1 field
	// widths here — would leave two copies of the table, and a field added under
	// §10 would be checked in one and skipped in the other.
	probe := *env
	probe.V = record.Version
	d, err := probe.Decode()
	if err != nil {
		return reject.RecordMalformed, nil
	}

	// 4. v is not 1. §4.1 is explicit that this is a rejection and not an
	// application of the unknown-field rule: v pins the format, so it is not an
	// unknown field. Every other unrecognised member is ignored (§10), which is
	// what makes an additive change to v1 deployable at all.
	if env.V != record.Version {
		return reject.RecordBadVersion, nil
	}

	// 5. expires_at beyond the TTL bound, with the §5.2 skew grace applied.
	if d.ExpiresAt > now+lim.MaxTTL+lim.SkewGrace {
		return reject.RecordTTLTooLong, nil
	}

	// 6. lookup_id is not SHA-256(wk_pub). One SHA-256. This is what stops a
	// flooder writing under an identifier it did not derive.
	if d.VerifyLookupID() != nil {
		return reject.RecordLookupMismatch, nil
	}

	// 7. pow does not satisfy pow_bits (§6.1). One SHA-256. Deliberately before
	// the signature check: see the package comment.
	if !pow.Verify(d.LookupID, d.ExpiresAt, d.PoW, lim.PoWBits) {
		return reject.RecordPoWInsufficient, nil
	}

	// 8. sig does not verify under wk_pub. The signature *is* the authorisation
	// (§5.2); there is no header to check and no account to consult.
	if d.VerifySignature() != nil {
		return reject.RecordSigInvalid, nil
	}

	// 9. expires_at is not strictly greater than the directory's current time.
	// Strictly: a record expiring exactly now is already absent for every
	// purpose in this specification (§5.2).
	if d.ExpiresAt <= now {
		return reject.RecordExpired, nil
	}

	// 10 is the recency rule, and it is the caller's — it needs a storage read.
	return reject.RecordAccepted, d
}

// parse decodes the envelope's JSON layer: well-formedness, the presence of
// every required member, and the base64url spelling rule. It reports success or
// failure and nothing else, because everything it can detect is the same §5.2
// condition and the value that failed must not travel.
func parse(body []byte) (*record.Envelope, bool) {
	// A first pass over the raw members, because presence and absence are not
	// recoverable from the decoded struct. A body that is not a JSON object —
	// an array, a string, a bare number, empty — fails here.
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &members); err != nil {
		return nil, false
	}

	// §5.2: an envelope containing the same member name more than once is
	// malformed. A map cannot show this — unmarshalling collapses duplicates,
	// keeping whichever occurrence the decoder saw last — so the raw token
	// stream has to be walked separately.
	//
	// This is not pedantry about a malformed body. Parsers disagree about which
	// occurrence wins, and because the directory verifies a signature over the
	// fields it parsed and then stores the bytes verbatim (§5.2), a first-wins
	// directory and a last-wins client can end up disagreeing about an
	// expires_at that the directory never validated. It is a signature bypass
	// wearing a parser disagreement as a costume.
	if hasDuplicateMembers(body) {
		return nil, false
	}

	for _, name := range requiredMembers {
		raw, present := members[name]
		if !present || string(raw) == "null" {
			return nil, false
		}
	}

	// Unknown members are ignored, never rejected (§5, §10). encoding/json does
	// that by default; do not add DisallowUnknownFields.
	var env record.Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, false
	}

	return &env, true
}

// hasDuplicateMembers reports whether the top-level JSON object names any
// member more than once.
//
// Only the top level is examined. Every member of an envelope is a scalar
// (§4.1), so there is no nested object in a well-formed one, and a body that
// nests something where a scalar belongs fails the decode into record.Envelope
// regardless. Walking arbitrary depth would mean recursing over
// attacker-supplied structure for no gain.
//
// A body that is not an object, or is malformed, reports false: those are
// rejected by the surrounding decode, and this function's job is only to answer
// the duplicate question.
func hasDuplicateMembers(body []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(body))

	tok, err := dec.Token()
	if err != nil {
		return false
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return false
	}

	seen := make(map[string]struct{})
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		name, ok := tok.(string)
		if !ok {
			return false
		}
		if _, dup := seen[name]; dup {
			return true
		}
		seen[name] = struct{}{}

		// Skip the value. Decoding into json.RawMessage consumes exactly one
		// value whatever its shape, which advances the stream without this
		// having to track nesting itself.
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return false
		}
	}
	return false
}
