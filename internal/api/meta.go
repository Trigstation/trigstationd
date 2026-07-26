// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package api

import (
	"encoding/json"
	"net/http"
)

// meta is the GET /v1/meta response of DIRECTORY-SPEC.md §5.1.
//
// All seven members are REQUIRED and every one is emitted unconditionally.
// There are no omitempty tags here and there must not be: a client cannot size
// its prefix without record_count, cannot size its envelope without
// max_record_bytes and cannot solve a proof of work without pow_bits, so an
// instance that omitted any of them is not usable by a conforming client. An
// omitempty on signal would silently drop the member on an instance with signal
// channels off, which is exactly the instance a client most needs to be told
// about.
type meta struct {
	V              int    `json:"v"`
	RecordCount    int64  `json:"record_count"`
	MaxTTL         int64  `json:"max_ttl"`
	MaxRecordBytes int    `json:"max_record_bytes"`
	PoWBits        int    `json:"pow_bits"`
	Signal         bool   `json:"signal"`
	SourceURL      string `json:"source_url"`
}

// handleMeta serves DIRECTORY-SPEC.md §5.1.
//
// It is not rate limited. §6.2 gives per-source limits to PUT /v1/record, GET
// /v1/record and the signal channels, and internal/ratelimit has a class for
// each of those three and no fourth. Meta reads one COUNT and returns under two
// hundred bytes, and it is the response a client needs before it can form any
// other request, so limiting it would mostly serve to lock a client out of the
// instance it was trying to learn how to talk to.
func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	now := s.now()

	count, err := s.store.Count(r.Context(), now.Unix())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	body, err := json.Marshal(meta{
		V:              1,
		RecordCount:    understate(count),
		MaxTTL:         s.limits.MaxTTL,
		MaxRecordBytes: s.limits.MaxRecordBytes,
		PoWBits:        s.limits.PoWBits,
		Signal:         s.signal != nil,
		SourceURL:      s.sourceURL,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// understate rounds a record count down to two significant figures, the
// RECOMMENDED reduction in DIRECTORY-SPEC.md §5.1: 104,233 becomes 100,000.
//
// # The direction is the whole point
//
// §5.1 permits record_count to be reduced so that an instance need not disclose
// its exact scale, and forbids it from ever exceeding the true count. That
// asymmetry is not cosmetic. A client picks its prefix length from this figure,
// so an overstated count yields a narrower prefix and a result set smaller than
// the k it asked for, silently weakening the anonymity guarantee of §8 for a
// client that followed the spec exactly. Understating is always safe: it yields
// a broader prefix and a larger response.
//
// The true count still feeds the server-side cap in §5.3 — see handleGetRecord
// — which is what makes §5.1's promise hold that a client following the
// advertised figure can never be rejected as over-precise.
//
// Rounding down is deterministic and stateless, and bounds the resulting
// response inflation at roughly ten per cent. Counts below 100 are returned
// unchanged: they already carry only two significant figures, and an instance
// that small has nothing to conceal about its scale that the near-total result
// set of any query would not disclose anyway.
func understate(n int64) int64 {
	if n < 100 {
		return n
	}
	scale := int64(1)
	for n/scale >= 100 {
		scale *= 10
	}
	return (n / scale) * scale
}
