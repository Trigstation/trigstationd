// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package reject

import (
	"net/http"
	"testing"
)

// TestRecordStatusTable transcribes DIRECTORY-SPEC.md §5.2's status table.
//
// The expected values are taken from the specification, not from the
// implementation. If this test is ever updated to match a code change rather
// than a spec change, the mapping has stopped being wire format.
func TestRecordStatusTable(t *testing.T) {
	tests := []struct {
		name   string
		reason RecordReason
		want   int
	}{
		{"accepted and stored", RecordAccepted, 204},
		{"rate limited", RecordRateLimited, 429},
		{"body exceeds max_record_bytes", RecordTooLarge, 413},
		{"malformed body", RecordMalformed, 400},
		{"v is not 1", RecordBadVersion, 400},
		{"expires_at exceeds now + max_ttl", RecordTTLTooLong, 400},
		{"lookup_id is not SHA-256(wk_pub)", RecordLookupMismatch, 403},
		{"pow does not satisfy pow_bits", RecordPoWInsufficient, 403},
		{"sig does not verify under wk_pub", RecordSigInvalid, 403},
		{"expires_at not after current time", RecordExpired, 409},
		{"expires_at not after stored record", RecordNotNewer, 409},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.reason.HTTPStatus(); got != tt.want {
				t.Errorf("HTTPStatus() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestSignalStatusTable transcribes DIRECTORY-SPEC.md §5.4's status table.
func TestSignalStatusTable(t *testing.T) {
	tests := []struct {
		name   string
		reason SignalReason
		want   int
	}{
		{"POST stored", SignalStored, 204},
		{"GET delivered a blob", SignalDelivered, 200},
		{"GET long-poll elapsed empty", SignalEmpty, 204},
		{"channel_id malformed", SignalBadChannel, 400},
		{"body exceeds payload limit", SignalTooLarge, 413},
		{"channel already holds a blob", SignalConflict, 409},
		{"rate limited", SignalRateLimited, 429},
		{"instance advertises signal false", SignalDisabled, 404},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.reason.HTTPStatus(); got != tt.want {
				t.Errorf("HTTPStatus() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestEvaluationOrderIsSpecOrder pins the declaration order of RecordReason to
// the order §5.2 requires the conditions to be evaluated in.
//
// §5.2 requires the directory to return the code of the *first* condition that
// fails, so a request violating several conditions has one correct answer. A
// caller that walks the conditions in constant order gets that for free — which
// is why the order is a property worth testing rather than a comment.
func TestEvaluationOrderIsSpecOrder(t *testing.T) {
	want := []RecordReason{
		RecordAccepted,
		RecordRateLimited,
		RecordTooLarge,
		RecordMalformed,
		RecordBadVersion,
		RecordTTLTooLong,
		RecordLookupMismatch,
		RecordPoWInsufficient,
		RecordSigInvalid,
		RecordExpired,
		RecordNotNewer,
	}

	for i, r := range want {
		if int(r) != i {
			t.Errorf("%d: reason has value %d, want %d — the evaluation order has been changed", i, int(r), i)
		}
	}
}

// TestCheapChecksPrecedeSignatureVerification asserts the ordering property
// §5.2 gives as its rationale: the two SHA-256 checks come before the Ed25519
// verification, so a flooding client is rejected on the cheap check.
func TestCheapChecksPrecedeSignatureVerification(t *testing.T) {
	if !(RecordLookupMismatch < RecordSigInvalid) {
		t.Error("lookup_id check must precede the signature check")
	}
	if !(RecordPoWInsufficient < RecordSigInvalid) {
		t.Error("proof-of-work check must precede the signature check")
	}
}

// TestStorageReadIsLast asserts the recency rule is evaluated after every check
// that needs no storage access, so a rejected publish never touches the
// database.
func TestStorageReadIsLast(t *testing.T) {
	for _, r := range []RecordReason{
		RecordRateLimited, RecordTooLarge, RecordMalformed, RecordBadVersion,
		RecordTTLTooLong, RecordLookupMismatch, RecordPoWInsufficient,
		RecordSigInvalid, RecordExpired,
	} {
		if !(r < RecordNotNewer) {
			t.Errorf("reason %d must be evaluated before the recency rule", int(r))
		}
	}
}

// TestEveryRecordReasonIsMapped fails if a constant is added without a case in
// HTTPStatus, which would otherwise surface as a 500 in production.
func TestEveryRecordReasonIsMapped(t *testing.T) {
	for r := RecordAccepted; r <= RecordNotNewer; r++ {
		if got := r.HTTPStatus(); got == http.StatusInternalServerError {
			t.Errorf("RecordReason(%d) has no mapping", int(r))
		}
	}
}

// TestEverySignalReasonIsMapped is the SignalReason equivalent.
func TestEverySignalReasonIsMapped(t *testing.T) {
	for r := SignalStored; r <= SignalDisabled; r++ {
		if got := r.HTTPStatus(); got == http.StatusInternalServerError {
			t.Errorf("SignalReason(%d) has no mapping", int(r))
		}
	}
}

// TestTimeoutIsNotNotFound is the distinction ruling C turns on, asserted
// directly rather than left implicit in the table above.
//
// A client receiving 204 polls again; one receiving 404 tries a different
// directory. If these ever collapse to the same code, device pairing either
// hammers an instance that will never answer or abandons one that would have.
func TestTimeoutIsNotNotFound(t *testing.T) {
	if SignalEmpty.HTTPStatus() == SignalDisabled.HTTPStatus() {
		t.Fatal("a long-poll timeout and an instance without signal support must be distinguishable")
	}
	if SignalEmpty.HTTPStatus() != http.StatusNoContent {
		t.Errorf("long-poll timeout = %d, want 204", SignalEmpty.HTTPStatus())
	}
	if SignalDisabled.HTTPStatus() != http.StatusNotFound {
		t.Errorf("signal disabled = %d, want 404", SignalDisabled.HTTPStatus())
	}
}

// TestSharedCodesShareARemedy asserts the grouping principle from D-11: codes
// are grouped by the publisher's remedy, not by the category of the fault.
//
// A stale expires_at and a violated recency rule are different faults with the
// same remedy — republish with a later expiry — so they share 409. An over-long
// TTL also concerns expires_at but has a different remedy, so it must not.
func TestSharedCodesShareARemedy(t *testing.T) {
	if RecordExpired.HTTPStatus() != RecordNotNewer.HTTPStatus() {
		t.Error("a stale expires_at and a violated recency rule share a remedy and must share a code")
	}
	if RecordTTLTooLong.HTTPStatus() == RecordNotNewer.HTTPStatus() {
		t.Error("an over-long TTL has a different remedy from the recency rule and must not share its code")
	}
}

// TestSignalEvaluationOrderIsSpecOrder pins the declaration order of the
// SignalReason rejections to §5.4's normative order.
//
// This exists because the previous version of this package asserted the §5.4
// conditions were disjoint and therefore needed no order. They are not: rate
// limiting co-occurs with "signal": false and with an over-size body, and a
// malformed channel_id co-occurs with "signal": false. A comment claiming
// otherwise is worse than no comment, because it discourages exactly the check
// this test performs.
func TestSignalEvaluationOrderIsSpecOrder(t *testing.T) {
	want := []SignalReason{
		SignalDisabled,    // 1. static instance configuration
		SignalRateLimited, // 2. load shedding
		SignalBadChannel,  // 3. request validity
		SignalTooLarge,    // 4. request validity
		SignalConflict,    // 5. stored state
	}

	for i := 1; i < len(want); i++ {
		if !(want[i-1] < want[i]) {
			t.Errorf("§5.4 requires %d to be evaluated before %d; the declaration order says otherwise",
				int(want[i-1]), int(want[i]))
		}
	}
}

// TestDurableAnswersPrecedeTransientOnes states the §5.4 ordering principle
// directly, so that a future reorder has to argue with the reason rather than
// only with the sequence.
//
// §5.2 orders by cost. §5.4 orders by durability: when several conditions hold,
// the client is told the one that says the most about what to do next. An
// instance advertising "signal": false will never serve this client; a rate
// limit lapses within the hour. Answering 429 to a client of a permanently
// disabled instance invites an indefinite retry loop, and PAIRING-SPEC.md §6.3
// makes polling the normal path rather than a corner.
func TestDurableAnswersPrecedeTransientOnes(t *testing.T) {
	if !(SignalDisabled < SignalRateLimited) {
		t.Error("a permanently disabled instance must be reported before a transient rate limit")
	}
	if !(SignalRateLimited < SignalBadChannel) {
		t.Error("a flooding client must be shed before the directory parses its channel_id")
	}
	if !(SignalConflict > SignalTooLarge) {
		t.Error("the only condition needing stored state must be evaluated last")
	}
}
