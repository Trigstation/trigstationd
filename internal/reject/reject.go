// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

// Package reject holds the normative mapping from rejection condition to HTTP
// status code, for both PUT /v1/record (DIRECTORY-SPEC.md §5.2) and the signal
// channels (§5.4).
//
// It exists as its own package for one reason: the mapping is wire format. A
// publisher's retry logic is driven entirely by the status code — 400 means the
// request is wrong and must not be retried, 409 means republish with a later
// expiry, 429 means back off — so two directories disagreeing about which code a
// condition draws is an interoperability failure, not a cosmetic difference. One
// table, in one place, that every handler must route through.
//
// The declaration order of the RecordReason constants is also normative: §5.2
// requires conditions to be evaluated in table order and the first failure to
// determine the code. Without a fixed order a request violating two conditions
// draws a different code from different directories. The order is cheapest-first
// as well, so the two SHA-256 checks precede the Ed25519 verification, which is
// roughly two orders of magnitude more expensive, and a flooding client is
// rejected on the cheap check.
//
// Codes are grouped by the publisher's remedy rather than by the internal
// category of the fault. That is why RecordExpired and RecordNotNewer share 409
// — the remedy for both is "republish with a later expiry", one branch in the
// publisher rather than two — while RecordTTLTooLong is 400 despite also
// concerning expires_at, because its remedy is different: reduce the configured
// TTL and re-solve the proof of work.
//
// Nothing in this package formats a value into a message. Response bodies carry
// no diagnostic detail (§5.2), and an error that named the lookup_id or address
// that caused it would be the identifier logging that must not exist.
package reject

import "net/http"

// RecordReason is the outcome of applying the DIRECTORY-SPEC.md §5.2 conditions
// to a publish. The zero value is RecordAccepted.
//
// The constants are declared in the order §5.2 requires them to be evaluated.
// Do not reorder them, and add new ones only at the position the spec gives the
// condition — a new constant appended for convenience silently changes the
// evaluation order every caller relies on.
type RecordReason int

const (
	// RecordAccepted is the success case: 204, no body.
	RecordAccepted RecordReason = iota

	// RecordRateLimited is checked first, before any parsing, so that a flood
	// costs the directory as little as possible.
	RecordRateLimited

	// RecordTooLarge is measured against the received body as transmitted,
	// before any parsing (§5.2).
	RecordTooLarge

	// RecordMalformed covers a body that is not well-formed JSON, an absent
	// required member, a value that is not valid unpadded base64url, and a
	// fixed-width field that decodes to the wrong length.
	RecordMalformed

	// RecordBadVersion is v != 1. Per §4.1 this is rejected rather than being
	// ignored under the unknown-field rule: v pins the format, so it is not an
	// unknown field.
	RecordBadVersion

	// RecordTTLTooLong is expires_at beyond now + max_ttl, after the skew grace
	// of §5.2 has been applied.
	RecordTTLTooLong

	// RecordLookupMismatch is lookup_id != SHA-256(wk_pub). One SHA-256.
	RecordLookupMismatch

	// RecordPoWInsufficient is a proof of work that does not meet pow_bits. One
	// SHA-256, so it precedes the signature check.
	RecordPoWInsufficient

	// RecordSigInvalid is a signature that does not verify under wk_pub. The
	// most expensive check, so it goes last of the cryptographic three.
	RecordSigInvalid

	// RecordExpired is expires_at not strictly greater than the directory's
	// current time.
	RecordExpired

	// RecordNotNewer is the recency rule: expires_at not strictly greater than
	// that of an unexpired stored record under the same lookup_id. Last,
	// because it is the only condition requiring a storage read.
	RecordNotNewer
)

// HTTPStatus returns the status code DIRECTORY-SPEC.md §5.2 binds to the reason.
func (r RecordReason) HTTPStatus() int {
	switch r {
	case RecordAccepted:
		return http.StatusNoContent // 204
	case RecordRateLimited:
		return http.StatusTooManyRequests // 429
	case RecordTooLarge:
		return http.StatusRequestEntityTooLarge // 413
	case RecordMalformed, RecordBadVersion, RecordTTLTooLong:
		return http.StatusBadRequest // 400
	case RecordLookupMismatch, RecordPoWInsufficient, RecordSigInvalid:
		return http.StatusForbidden // 403
	case RecordExpired, RecordNotNewer:
		return http.StatusConflict // 409
	}
	// Unreachable for any declared reason. Returning 500 rather than panicking
	// keeps a future unmapped constant from taking the process down, and
	// TestEveryRecordReasonIsMapped fails the build before it can ship.
	return http.StatusInternalServerError
}

// SignalReason is the outcome of a signal channel operation
// (DIRECTORY-SPEC.md §5.4).
//
// # The declaration order is the evaluation order, as it is for RecordReason
//
// An earlier version of this comment claimed the §5.4 conditions were disjoint,
// so that no order was needed. That was wrong, and wrong in the direction that
// matters: at least three pairs can apply to one request — rate limited with
// "signal": false, rate limited with an over-size body, and a malformed
// channel_id with "signal": false. §5.4 now fixes an order and this package
// encodes it, so a caller walking the conditions in constant order gets the
// right answer without having to remember the rule.
//
// **The ordering principle differs from §5.2's, deliberately.** §5.2 is
// cheapest-first, so an expensive Ed25519 verification is never reached by a
// request a SHA-256 would have rejected. §5.4 is by **durability**: when several
// conditions hold, answer with the one that tells the client the most about what
// to do next. Static instance configuration, then load shedding, then request
// validity, then stored state.
//
// So SignalDisabled precedes SignalRateLimited. An instance advertising
// "signal": false will never serve this client, whereas a rate limit lapses
// within the hour, and PAIRING-SPEC.md §6.3 makes polling the normal path — so
// answering 429 on a permanently disabled instance would invite an indefinite
// retry loop against something that can never work. Note that 404 is reachable
// only on an instance that genuinely advertises "signal": false; it cannot be
// returned to a client of a working one, under this order or any other.
type SignalReason int

const (
	// SignalStored is a successful POST: 204.
	SignalStored SignalReason = iota

	// SignalDelivered is a successful GET carrying a blob: 200, sent as
	// application/octet-stream. A directory forbidden to interpret the body
	// must not claim a type for it.
	SignalDelivered

	// SignalEmpty is a GET whose long-poll window elapsed with no blob: 204,
	// deliberately not 404.
	//
	// The client's correct response to 204 is to poll again; to 404, to try a
	// different directory. Conflating them means a client either hammers an
	// instance that will never answer or abandons one that would have, and
	// PAIRING-SPEC.md §6.3 makes polling the normal path rather than an edge
	// case.
	SignalEmpty

	// The rejections below are in §5.4's normative evaluation order. Do not
	// reorder them, and add a new one at the position §5.4 gives the condition
	// rather than appending it for convenience.

	// SignalDisabled is an instance advertising "signal": false — the only
	// signal outcome that is 404, and first because it is the most durable
	// answer available. Nothing this instance is asked will change it.
	SignalDisabled

	// SignalRateLimited is 429. Second, so that a flooding client is shed
	// before the directory parses anything on its behalf.
	SignalRateLimited

	// SignalBadChannel is a channel_id that is not exactly 32 bytes of unpadded,
	// canonically encoded base64url.
	SignalBadChannel

	// SignalTooLarge is a body beyond the §4.3 signal channel payload limit.
	SignalTooLarge

	// SignalConflict is the first-write-wins rejection: a POST to a channel
	// already holding an unexpired blob. Overwrite semantics would let anyone
	// who guessed a channel identifier replace a legitimate blob and turn the
	// rendezvous into an injection point; failing closed reduces that to a
	// denial of service the participants detect immediately.
	//
	// Last, because it is the only condition requiring a look at stored state.
	SignalConflict
)

// HTTPStatus returns the status code DIRECTORY-SPEC.md §5.4 binds to the reason.
func (r SignalReason) HTTPStatus() int {
	switch r {
	case SignalStored, SignalEmpty:
		return http.StatusNoContent // 204
	case SignalDelivered:
		return http.StatusOK // 200
	case SignalBadChannel:
		return http.StatusBadRequest // 400
	case SignalTooLarge:
		return http.StatusRequestEntityTooLarge // 413
	case SignalConflict:
		return http.StatusConflict // 409
	case SignalRateLimited:
		return http.StatusTooManyRequests // 429
	case SignalDisabled:
		return http.StatusNotFound // 404
	}
	// See the note on RecordReason.HTTPStatus.
	return http.StatusInternalServerError
}
