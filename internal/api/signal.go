// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package api

import (
	"net/http"

	"github.com/trigstation/trigstationd/internal/ratelimit"
	"github.com/trigstation/trigstationd/internal/reject"
	"github.com/trigstation/trigstationd/internal/signal"
)

// handlePostSignal serves the POST half of DIRECTORY-SPEC.md §5.4.
//
// First-write-wins, the channel-id syntax and the payload limit all belong to
// internal/signal. What is decided here is the two conditions the store cannot
// see: whether this instance brokers signal channels at all, and whether the
// source has exhausted its §6.2 allowance.
func (s *Server) handlePostSignal(w http.ResponseWriter, r *http.Request) {
	if s.signal == nil {
		w.WriteHeader(reject.SignalDisabled.HTTPStatus())
		return
	}

	now := s.now()
	if !s.allow(r, ratelimit.ClassSignal, now) {
		w.WriteHeader(reject.SignalRateLimited.HTTPStatus())
		return
	}

	// One byte over the §4.3 payload limit, so that the store's own size check
	// decides the outcome without the directory buffering an oversized blob.
	blob, ok := readLimited(r, signal.MaxBlobBytes+1)
	if !ok {
		// A body that could not be read is not a blob this directory can
		// deliver. §5.4 has no row for it; the channel-id row is the only 400
		// in the table and this is not that, so a truncated upload is treated
		// as the store treats anything it cannot accept for delivery.
		w.WriteHeader(reject.SignalRateLimited.HTTPStatus())
		return
	}

	w.WriteHeader(s.signal.Post(r.PathValue("channel_id"), blob, now).HTTPStatus())
}

// handleGetSignal serves the GET half of DIRECTORY-SPEC.md §5.4.
//
// # The long-poll ends when the client goes away
//
// r.Context() is cancelled when the client disconnects, and it is passed
// straight to the store, so a departed reader releases its waiter immediately
// rather than holding one for the rest of the 30-second window. PAIRING-SPEC.md
// §6.3 has both devices polling as its normal path, so waiters are the common
// case and leaking one per abandoned request would be a real cost.
//
// The same context is what makes Server.Drain work: a shutdown releases every
// waiter through the store, and each returns the 204 §5.4 already requires
// clients to tolerate.
//
// # 204, never 404
//
// A poll that finds nothing is 204. 404 is reserved for an instance advertising
// "signal": false, and the distinction is not pedantic — a client's correct
// response to 204 is to poll again, and to 404 is to try a different directory.
// Conflating them means a client either hammers an instance that will never
// answer or abandons one that would have. internal/reject holds both mappings,
// so neither code appears here.
func (s *Server) handleGetSignal(w http.ResponseWriter, r *http.Request) {
	if s.signal == nil {
		w.WriteHeader(reject.SignalDisabled.HTTPStatus())
		return
	}

	now := s.now()
	if !s.allow(r, ratelimit.ClassSignal, now) {
		w.WriteHeader(reject.SignalRateLimited.HTTPStatus())
		return
	}

	blob, reason := s.signal.Get(r.Context(), r.PathValue("channel_id"), now)
	if reason == reject.SignalDelivered {
		// application/octet-stream, because the directory MUST NOT interpret
		// the body and so must not claim a type for it. Blobs are usually
		// ciphertext, but PAIRING-SPEC.md §6.3 legitimately posts a bare
		// ephemeral public key.
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(reason.HTTPStatus())
		w.Write(blob)
		return
	}

	w.WriteHeader(reason.HTTPStatus())
}
