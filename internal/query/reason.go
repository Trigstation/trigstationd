// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package query

import "net/http"

// Reason is why a prefix lookup was rejected (DIRECTORY-SPEC.md §5.3).
//
// §5.3 binds every rejection in this table to 400, so unlike the §5.2 table in
// internal/reject the declaration order carries no normative weight and the
// choice between two reasons can never change what a client sees on the wire.
// The distinctions exist so the parser's behaviour can be pinned by a test, not
// so a client can be told which one it tripped: response bodies carry no
// diagnostic detail.
//
// Reason satisfies error, so Parse can return one directly and a caller can
// recover it with errors.As before asking for its status code.
//
// # Why these messages carry no values
//
// A lookup prefix is exactly the identifier the no-logging requirement exists to
// protect — a directory that recorded which buckets were asked about would be
// keeping the one piece of information §5.3's blinding is designed to withhold.
// Every message below is therefore a constant naming the failure mode, and
// nothing in this package formats a prefix, a bit count or any other query
// parameter into an error. Nothing anywhere else can leak what it was never
// given.
type Reason int

// The reasons. Zero is deliberately not a valid Reason: a Reason is only ever
// produced alongside a rejection, and the zero value of an error-typed variable
// should not silently mean "bits parameter is required".
const (
	// ReasonBitsMissing is a query with no bits parameter at all. §5.3 makes
	// bits REQUIRED and forbids inferring it from the length of prefix, because
	// inferring it would make a3f mean 12 bits on one directory and whatever the
	// client intended on another.
	ReasonBitsMissing Reason = iota + 1

	// ReasonBitsMalformed is a bits parameter that is not a plain non-negative
	// decimal integer: empty, signed, fractional, out of range, or containing
	// anything other than digits.
	ReasonBitsMalformed

	// ReasonBitsTooPrecise is the over-precise query §5.3 requires a directory
	// to reject. The bound is a function of the true record count, so the same
	// query may be accepted by a larger instance and rejected by a smaller one.
	ReasonBitsTooPrecise

	// ReasonPrefixMissing is an absent prefix parameter where bits is non-zero.
	// An absent prefix is only meaningful at bits = 0, where §5.3 requires both
	// ?prefix=&bits=0 and a bare ?bits=0 to be accepted.
	ReasonPrefixMissing

	// ReasonPrefixLength is a prefix whose length is not exactly ceil(bits / 4)
	// hex characters, in either direction.
	ReasonPrefixLength

	// ReasonPrefixNotHex is a character outside [0-9a-fA-F]. Case is not a
	// fault: §5.3 requires both a3f and A3F to be accepted.
	ReasonPrefixNotHex
)

// Error implements error.
func (r Reason) Error() string {
	switch r {
	case ReasonBitsMissing:
		return "query: bits parameter is required"
	case ReasonBitsMalformed:
		return "query: bits parameter is not a non-negative integer"
	case ReasonBitsTooPrecise:
		return "query: prefix is more precise than this instance permits"
	case ReasonPrefixMissing:
		return "query: prefix parameter is required when bits is non-zero"
	case ReasonPrefixLength:
		return "query: prefix length does not match bits"
	case ReasonPrefixNotHex:
		return "query: prefix contains a character outside the hex alphabet"
	}
	return "query: rejected"
}

// HTTPStatus returns the status code DIRECTORY-SPEC.md §5.3 binds to the reason.
// Every one of them is 400; the switch is written out in full so that a reason
// added without a case here fails TestEveryReasonIsMapped rather than reaching a
// client as a 500.
func (r Reason) HTTPStatus() int {
	switch r {
	case ReasonBitsMissing,
		ReasonBitsMalformed,
		ReasonBitsTooPrecise,
		ReasonPrefixMissing,
		ReasonPrefixLength,
		ReasonPrefixNotHex:
		return http.StatusBadRequest // 400
	}
	// Unreachable for any declared reason. See the note in internal/reject.
	return http.StatusInternalServerError
}
