// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package api

import (
	"bytes"
	"errors"
	"net/http"
	"net/url"

	"github.com/trigstation/trigstationd/internal/accept"
	"github.com/trigstation/trigstationd/internal/query"
	"github.com/trigstation/trigstationd/internal/ratelimit"
	"github.com/trigstation/trigstationd/internal/reject"
	"github.com/trigstation/trigstationd/internal/store"
)

// handlePutRecord serves DIRECTORY-SPEC.md §5.2.
//
// The whole of the acceptance decision belongs to other packages.
// internal/accept applies ten of the eleven rows of the §5.2 table in their
// normative order; internal/store applies the eleventh, the recency rule, which
// is the only one needing a read. This function reads a body under a limit,
// passes it to each in turn, and asks internal/reject for the code. It contains
// no status literal and no condition of its own.
//
// # Content-Type is not consulted
//
// §5.2 requires that a directory MUST NOT reject a publish on the basis of its
// Content-Type: the vendor type, application/json, an unrecognised value and an
// absent header are all acceptable. The body is validated in full either way, so
// rejecting on the header gains nothing and costs interoperability with
// constrained clients — notably browsers, for which a non-standard content type
// forces a CORS preflight. Nothing below reads the header, which is the most
// durable way to satisfy that.
//
// # The response body
//
// There is none, for any outcome. §5.2 is explicit that response bodies carry no
// diagnostic detail and the code is the whole answer. That is not only about
// terseness: the only detail worth writing would name the envelope that failed,
// and an error message is an output stream like any other.
func (s *Server) handlePutRecord(w http.ResponseWriter, r *http.Request) {
	now := s.now()

	// Row one of the §5.2 evaluation order, and it is first for a reason: a
	// flood must cost the directory as little as possible, so the limit is
	// applied before the body is read, let alone parsed or measured.
	//
	// accept.Check is not called for this row. It would answer correctly with a
	// nil body, but reaching it means having read a body the order says should
	// never have been read.
	if !s.allow(r, ratelimit.ClassPutRecord, now) {
		w.WriteHeader(reject.RecordRateLimited.HTTPStatus())
		return
	}

	// One byte over the limit, so that accept.Check's "len(body) >
	// MaxRecordBytes" is decided on the bytes as transmitted without the
	// directory ever buffering an oversized body.
	body, ok := readLimited(r, s.limits.MaxRecordBytes+1)
	if !ok {
		// A body that could not be read in full is not a well-formed envelope,
		// which §5.2 binds to 400. In practice this is a client that
		// disconnected, and nothing will read the response.
		w.WriteHeader(reject.RecordMalformed.HTTPStatus())
		return
	}

	reason, decoded := accept.Check(body, now.Unix(), s.limits, false)
	if reason == reject.RecordAccepted {
		var err error
		reason, err = s.store.Put(r.Context(), store.Record{
			LookupID:  decoded.LookupID,
			WKPub:     decoded.WKPub,
			ExpiresAt: decoded.ExpiresAt,

			// Verbatim: the bytes as received, never a re-serialisation of the
			// fields just parsed out of them. §5.2 requires the directory to
			// reproduce these exact bytes in §5.3, which is what lets an
			// envelope carrying a member added under §10 pass through a
			// directory written before that member existed.
			Envelope: body,
		}, now.Unix())
		if err != nil {
			// On an error the returned reason carries no meaning and must not
			// be acted on. A storage fault is the directory's failure, not the
			// publisher's, and none of the §5.2 codes describes it.
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(reason.HTTPStatus())
}

// handleGetRecord serves DIRECTORY-SPEC.md §5.3.
//
// # Envelopes are reproduced, not re-encoded
//
// The response is assembled around the stored bytes rather than marshalled from
// a struct. That is not an optimisation and the ordinary approach does not work:
// encoding/json compacts and HTML-escapes the output of a json.Marshaler, so
// even json.RawMessage inside a marshalled wrapper would come back with its
// whitespace removed and any '<', '>' or '&' rewritten as escapes. Both are
// invisible in a test that only checks the fields it knows about, and both break
// §5.2's requirement that the returned bytes are the received bytes.
//
// The consequence is §10's additive-change policy in practice: an envelope may
// carry a member introduced after this directory was written, and a directory
// that rebuilt the JSON from the fields it happened to know would strip it
// silently. A server and client both running a later revision could then not use
// an older directory as a transport, and nothing would report an error.
func (s *Server) handleGetRecord(w http.ResponseWriter, r *http.Request) {
	now := s.now()

	if !s.allow(r, ratelimit.ClassGetRecord, now) {
		w.WriteHeader(reject.RecordRateLimited.HTTPStatus())
		return
	}

	values := r.URL.Query()
	if repeated(values, "prefix") || repeated(values, "bits") {
		w.WriteHeader(query.ReasonRepeatedParameter.HTTPStatus())
		return
	}

	// The cap is computed against the TRUE count, not the figure §5.1 permits
	// GET /v1/meta to understate. Because the advertised count may only ever be
	// understated, a client sizing its prefix from it always lands at or below
	// this cap — which is what makes §5.1's promise unconditional that a
	// conforming client can never be rejected as over-precise.
	count, err := s.store.Count(r.Context(), now.Unix())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	prefix, prefixPresent := single(values, "prefix")
	bits, bitsPresent := single(values, "bits")

	q, err := query.Parse(prefix, prefixPresent, bits, bitsPresent, query.Cap(count))
	if err != nil {
		var reason query.Reason
		if errors.As(err, &reason) {
			w.WriteHeader(reason.HTTPStatus())
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	envelopes, err := s.store.ByPrefix(r.Context(), q, now.Unix())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Buffered rather than streamed, so that Content-Length is set and a
	// storage error part way through cannot leave a truncated body behind a 200.
	// §5.3 bounds a response at roughly 2k envelopes, so this is tens of
	// kilobytes at the recommended prefix width.
	var buf bytes.Buffer
	buf.WriteString(`{"records":[`)
	for i, envelope := range envelopes {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(envelope)
	}
	buf.WriteString(`]}`)

	w.Header().Set("Content-Type", "application/json")
	w.Write(buf.Bytes())
}

// repeated reports whether a query parameter was supplied more than once.
//
// url.Values hides this: Get returns the first occurrence and says nothing about
// the rest, so a directory using it resolves the ambiguity §5.3 requires it to
// reject. The length of the slice is the only place the repetition survives.
func repeated(values url.Values, name string) bool {
	return len(values[name]) > 1
}

// single returns a query parameter and whether it was present at all.
//
// The distinction matters at exactly one point in §5.3, which requires both
// ?prefix=&bits=0 and a bare ?bits=0 to be accepted, and requires a missing bits
// to be rejected rather than inferred. url.Values.Get cannot express it: an
// absent parameter and one supplied empty both come back as "".
func single(values url.Values, name string) (string, bool) {
	v, present := values[name]
	if !present || len(v) == 0 {
		return "", false
	}
	return v[0], true
}
