// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/trigstation/trigstationd/internal/b64"
	"github.com/trigstation/trigstationd/internal/ratelimit"
	"github.com/trigstation/trigstationd/internal/record"
)

// TestPutRecordStatusTable walks every row of the §5.2 status table end to end.
//
// The table is normative and the evaluation order with it: a request violating
// two conditions has exactly one correct answer, because a publisher's retry
// logic is driven entirely by the code. 400 means the request is wrong and must
// not be retried, 403 means the material is wrong, 409 means republish with a
// later expiry, 429 means back off. Each row is therefore a separate case rather
// than a group assertion that a rejection happened.
func TestPutRecordStatusTable(t *testing.T) {
	now := testNow.Unix()

	// A fixture whose only fault is the one named. Each mutation is applied to
	// an otherwise valid envelope so that the row under test is genuinely the
	// first condition to fail.
	cases := []struct {
		name string
		want int

		// opts, when non-zero, replaces the default instance configuration.
		opts *options

		// before runs against the harness first, so that a row needing prior
		// state — the recency rule — can create it.
		before func(t *testing.T, h *harness)

		// body returns the bytes to publish.
		body func(t *testing.T) []byte
	}{
		{
			name: "accepted and stored",
			want: http.StatusNoContent,
			body: func(t *testing.T) []byte {
				return body(t, newPublisher(1).envelope(t, now+3600, testPoWBits))
			},
		},
		{
			name: "rate limited",
			want: http.StatusTooManyRequests,
			opts: &options{rate: ratelimit.Options{PutRecord: 1}},
			before: func(t *testing.T, h *harness) {
				h.status(http.MethodPut, "/v1/record", body(t, newPublisher(2).envelope(t, now+3600, testPoWBits)))
			},
			body: func(t *testing.T) []byte {
				return body(t, newPublisher(3).envelope(t, now+3600, testPoWBits))
			},
		},
		{
			name: "received body exceeds max_record_bytes",
			want: http.StatusRequestEntityTooLarge,
			body: func(t *testing.T) []byte {
				// Measured on the bytes as transmitted, before any parsing, so
				// this need not be a plausible envelope.
				return bytes.Repeat([]byte("x"), record.MaxEnvelopeBytes+1)
			},
		},
		{
			name: "body is not well-formed JSON",
			want: http.StatusBadRequest,
			body: func(t *testing.T) []byte { return []byte(`{"v":1,`) },
		},
		{
			name: "body is not a JSON object",
			want: http.StatusBadRequest,
			body: func(t *testing.T) []byte { return []byte(`[1,2,3]`) },
		},
		{
			name: "a required member is absent",
			want: http.StatusBadRequest,
			body: func(t *testing.T) []byte {
				env := newPublisher(4).envelope(t, now+3600, testPoWBits)
				return withoutMember(t, env, "nonce")
			},
		},
		{
			name: "a required member is explicitly null",
			want: http.StatusBadRequest,
			body: func(t *testing.T) []byte {
				env := newPublisher(5).envelope(t, now+3600, testPoWBits)
				return withMember(t, env, "expires_at", "null")
			},
		},
		{
			name: "a value is not valid unpadded base64url",
			want: http.StatusBadRequest,
			body: func(t *testing.T) []byte {
				env := newPublisher(6).envelope(t, now+3600, testPoWBits)
				env.Nonce = "not!base64url"
				return body(t, env)
			},
		},
		{
			name: "a value carries base64url padding",
			want: http.StatusBadRequest,
			body: func(t *testing.T) []byte {
				env := newPublisher(7).envelope(t, now+3600, testPoWBits)
				env.PoW += "="
				return body(t, env)
			},
		},
		{
			name: "a fixed-width field decodes to the wrong length",
			want: http.StatusBadRequest,
			body: func(t *testing.T) []byte {
				env := newPublisher(8).envelope(t, now+3600, testPoWBits)
				env.Nonce = b64.Encode([]byte{1, 2, 3})
				return body(t, env)
			},
		},
		{
			name: "v is not 1",
			want: http.StatusBadRequest,
			body: func(t *testing.T) []byte {
				env := newPublisher(9).envelope(t, now+3600, testPoWBits)
				env.V = 2
				return body(t, env)
			},
		},
		{
			name: "expires_at exceeds now plus max_ttl",
			want: http.StatusBadRequest,
			body: func(t *testing.T) []byte {
				// Beyond max_ttl and beyond the 300-second skew grace §5.2
				// requires a directory to allow above it.
				return body(t, newPublisher(10).envelope(t, now+record.MaxTTL+3600, testPoWBits))
			},
		},
		{
			name: "lookup_id is not SHA-256(wk_pub)",
			want: http.StatusForbidden,
			body: func(t *testing.T) []byte {
				env := newPublisher(11).envelope(t, now+3600, testPoWBits)
				other := newPublisher(12)
				env.LookupID = b64.Encode(other.lookupID)
				return body(t, env)
			},
		},
		{
			name: "pow does not satisfy pow_bits",
			want: http.StatusForbidden,
			body: func(t *testing.T) []byte {
				// pow is not covered by the envelope signature, so replacing it
				// leaves every earlier condition satisfied and this the first to
				// fail. A run of eight zero bytes is astronomically unlikely to
				// clear even eight bits.
				env := newPublisher(13).envelope(t, now+3600, testPoWBits)
				env.PoW = b64.Encode(make([]byte, record.PoWLen))
				return body(t, env)
			},
		},
		{
			name: "sig does not verify under wk_pub",
			want: http.StatusForbidden,
			body: func(t *testing.T) []byte {
				env := newPublisher(14).envelope(t, now+3600, testPoWBits)
				sig, err := b64.Decode(env.Sig)
				if err != nil {
					t.Fatalf("decoding a fixture signature: %v", err)
				}
				sig[0] ^= 0xff
				env.Sig = b64.Encode(sig)
				return body(t, env)
			},
		},
		{
			name: "expires_at is not strictly greater than the current time",
			want: http.StatusConflict,
			body: func(t *testing.T) []byte {
				// Equality, not the past: §5.2 makes a record live if and only
				// if expires_at is strictly greater than the directory's clock,
				// so this is the boundary case rather than a stale one.
				return body(t, newPublisher(15).envelope(t, now, testPoWBits))
			},
		},
		{
			name: "expires_at is not strictly greater than the stored record",
			want: http.StatusConflict,
			before: func(t *testing.T, h *harness) {
				env := newPublisher(16).envelope(t, now+3600, testPoWBits)
				if got := h.status(http.MethodPut, "/v1/record", body(t, env)); got != http.StatusNoContent {
					t.Fatalf("seeding the recency rule = %d, want 204", got)
				}
			},
			body: func(t *testing.T) []byte {
				// The same expiry replayed. Within an epoch the write key is
				// stable so the captured envelope still verifies, and without
				// strict monotonicity the replay would roll the published
				// address back until the next republish.
				return body(t, newPublisher(16).envelope(t, now+3600, testPoWBits))
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := options{}
			if c.opts != nil {
				opts = *c.opts
			}
			h := newHarness(t, opts)

			if c.before != nil {
				c.before(t, h)
			}

			resp, read := h.do(http.MethodPut, "/v1/record", c.body(t), nil)
			if resp.StatusCode != c.want {
				t.Errorf("PUT /v1/record = %d, want %d", resp.StatusCode, c.want)
			}
			if len(read) != 0 {
				t.Errorf("the response carries a body of %d bytes: §5.2 says the code is the whole answer", len(read))
			}
		})
	}
}

// TestPutRecordIgnoresContentType is §5.2's "a directory MUST NOT reject a
// request on the basis of its Content-Type".
//
// The four cases must behave identically, not merely all succeed: a directory
// that accepted the vendor type and rejected an absent header would pass a test
// that only checked the happy path. Browsers matter here — a non-standard
// content type forces a CORS preflight, so a constrained client has a real
// reason to send something else or nothing at all.
func TestPutRecordIgnoresContentType(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		set         bool
	}{
		{"vendor type", "application/vnd.trigstation.record+json", true},
		{"application/json", "application/json", true},
		{"unrecognised", "text/plain; charset=utf-8", true},
		{"absent", "", false},
	}

	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, options{})
			env := newPublisher(byte(40+i)).envelope(t, testNow.Unix()+3600, testPoWBits)

			header := http.Header{}
			if c.set {
				header.Set("Content-Type", c.contentType)
			} else {
				// net/http fills in a content type when one is not set, so it
				// has to be removed explicitly to test an absent header.
				header["Content-Type"] = nil
			}

			resp, _ := h.do(http.MethodPut, "/v1/record", body(t, env), header)
			if resp.StatusCode != http.StatusNoContent {
				t.Errorf("PUT with Content-Type %q = %d, want 204", c.contentType, resp.StatusCode)
			}
		})
	}
}

// TestStoredEnvelopeIsReproducedByteForByte is the single most important
// assertion in this package.
//
// §5.2 requires a directory to retain the envelope as the byte sequence it
// received and reproduce those bytes unchanged in §5.3. A re-serialising
// implementation looks completely correct: every field a test knows to check
// comes back right, and the only thing lost is the member the directory had
// never heard of. That is precisely what §10's additive-change policy depends
// on — a server and a client both running a later revision must be able to use
// an older directory as a transport — and losing it reports no error anywhere.
//
// The fixture is deliberately awkward in three separate ways: an unknown member,
// a key order no encoder would produce, and whitespace no encoder would emit.
// Each defeats a different plausible shortcut.
func TestStoredEnvelopeIsReproducedByteForByte(t *testing.T) {
	h := newHarness(t, options{})
	p := newPublisher(60)
	expiresAt := testNow.Unix() + 3600
	env := p.envelope(t, expiresAt, testPoWBits)

	// Hand-assembled rather than marshalled. encoding/json emits struct fields
	// in declaration order with no spare whitespace, so a marshalled fixture
	// could not distinguish a directory that stored the bytes from one that
	// re-encoded them.
	sent := []byte("{\n" +
		`  "sig": "` + env.Sig + "\",\n" +
		`  "unknown_member_from_a_later_revision": {"nested": [1, 2, 3]},` + "\n" +
		`  "expires_at":` + strconv.FormatInt(env.ExpiresAt, 10) + ",\n" +
		`  "wk_pub"   : "` + env.WKPub + "\",\n" +
		`  "v": 1,` + "\n" +
		`  "nonce":"` + env.Nonce + "\",\n" +
		`  "pow": "` + env.PoW + "\",\n" +
		`  "ct":  "` + env.CT + "\",\n" +
		`  "lookup_id": "` + env.LookupID + "\"\n" +
		"}")

	if got := h.status(http.MethodPut, "/v1/record", sent); got != http.StatusNoContent {
		t.Fatalf("publishing the awkward envelope = %d, want 204", got)
	}

	resp, read := h.do(http.MethodGet, "/v1/record?bits=0", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/record = %d, want 200", resp.StatusCode)
	}

	// The strongest form of the assertion: the exact byte sequence appears in
	// the response, before anything has had a chance to normalise it.
	if !bytes.Contains(read, sent) {
		t.Fatalf("the response does not contain the envelope as sent.\nsent: %s\ngot:  %s", sent, read)
	}

	var out struct {
		Records []json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal(read, &out); err != nil {
		t.Fatalf("decoding the lookup response: %v", err)
	}
	if len(out.Records) != 1 {
		t.Fatalf("the lookup returned %d records, want 1", len(out.Records))
	}
	if !bytes.Equal(out.Records[0], sent) {
		t.Errorf("the returned envelope is not the envelope as sent.\nsent: %s\ngot:  %s", sent, out.Records[0])
	}

	// Stated separately because it is the property that actually breaks: the
	// unknown member must survive a directory that has never heard of it.
	var members map[string]json.RawMessage
	if err := json.Unmarshal(out.Records[0], &members); err != nil {
		t.Fatalf("the returned envelope is not a JSON object: %v", err)
	}
	if _, ok := members["unknown_member_from_a_later_revision"]; !ok {
		t.Error("the unknown member was stripped: §10's additive-change policy depends on it surviving")
	}
}

// TestEmptyResultIsAnEmptyArray checks the literal bytes, because the two
// plausible wrong answers both decode without complaint.
//
// A nil slice marshals to null, which a client ranging over it treats as an
// error rather than as an empty result; and 404 tells a client to try a
// different directory when the correct behaviour is to accept that this bucket
// is empty. §5.3 requires 200 with an empty array.
func TestEmptyResultIsAnEmptyArray(t *testing.T) {
	h := newHarness(t, options{})

	resp, read := h.do(http.MethodGet, "/v1/record?bits=0", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/record on an empty instance = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if string(read) != `{"records":[]}` {
		t.Errorf("the response body is %q, want %q", read, `{"records":[]}`)
	}
}

// TestGetRecordRejectsRepeatedParameters is §5.3's "a repeated parameter is
// 400".
//
// url.Values hides the repetition: Get returns the first occurrence silently, so
// a directory built on it resolves an ambiguity the specification requires it to
// reject. Two directories reading the same query differently is the failure, and
// no honest client emits one.
func TestGetRecordRejectsRepeatedParameters(t *testing.T) {
	h := newHarness(t, options{})

	cases := []struct {
		name  string
		query string
		want  int
	}{
		{"bits twice", "?prefix=&bits=0&bits=0", http.StatusBadRequest},
		{"bits twice with different values", "?prefix=&bits=1&bits=2", http.StatusBadRequest},
		{"prefix twice", "?prefix=&prefix=&bits=0", http.StatusBadRequest},
		{"both twice", "?prefix=&prefix=&bits=0&bits=0", http.StatusBadRequest},
		{"neither repeated", "?prefix=&bits=0", http.StatusOK},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := h.status(http.MethodGet, "/v1/record"+c.query, nil); got != c.want {
				t.Errorf("GET /v1/record%s = %d, want %d", c.query, got, c.want)
			}
		})
	}
}

// TestGetRecordQuerySyntax covers the §5.3 parameter rules at the boundary the
// HTTP layer owns: which parameter is present, and in what spelling.
//
// The maths is internal/query's and is tested there. What is tested here is that
// the transport reports presence faithfully — an absent prefix and one supplied
// empty are different inputs to the parser, and url.Values renders both as "".
func TestGetRecordQuerySyntax(t *testing.T) {
	h := newHarness(t, options{})

	cases := []struct {
		name  string
		query string
		want  int
	}{
		{"bits absent", "", http.StatusBadRequest},
		{"bits absent with a prefix", "?prefix=a3f", http.StatusBadRequest},
		{"bits zero with an empty prefix", "?prefix=&bits=0", http.StatusOK},
		{"bits zero with prefix absent", "?bits=0", http.StatusOK},
		{"bits zero with a prefix", "?prefix=a&bits=0", http.StatusBadRequest},
		{"bits not a number", "?prefix=a3f&bits=twelve", http.StatusBadRequest},
		{"bits negative", "?prefix=a3f&bits=-1", http.StatusBadRequest},
		{"bits beyond the cap on an empty instance", "?prefix=a&bits=4", http.StatusBadRequest},
		{"bits beyond a lookup_id", "?prefix=a&bits=257", http.StatusBadRequest},
		{"prefix is not hex", "?prefix=g&bits=4", http.StatusBadRequest},
		{"prefix is the wrong length", "?prefix=a3f0&bits=10", http.StatusBadRequest},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := h.status(http.MethodGet, "/v1/record"+c.query, nil); got != c.want {
				t.Errorf("GET /v1/record%s = %d, want %d", c.query, got, c.want)
			}
		})
	}
}

// TestGetRecordFindsByPrefix checks that the transport hands internal/query and
// internal/store a query they agree on, including the case §5.3 calls the
// ordinary one: a bits that is not a multiple of four, whose trailing bits a
// directory MUST mask rather than reject.
func TestGetRecordFindsByPrefix(t *testing.T) {
	h := newHarness(t, options{})
	expiresAt := testNow.Unix() + 3600

	// Enough records that the cap admits a few bits of prefix.
	const n = 64
	published := map[string][]byte{}
	for i := 0; i < n; i++ {
		p := newPublisher(byte(i))
		env := p.envelope(t, expiresAt, testPoWBits)
		raw := body(t, env)
		if got := h.status(http.MethodPut, "/v1/record", raw); got != http.StatusNoContent {
			t.Fatalf("publishing fixture %d = %d, want 204", i, got)
		}
		published[env.LookupID] = raw
	}

	// bits=0 returns everything.
	all := lookup(t, h, "?bits=0")
	if len(all) != n {
		t.Fatalf("bits=0 returned %d records, want %d", len(all), n)
	}

	// A one-bit query returns a strict subset, and the union of the two halves
	// is the whole table. Trailing bits of the hex character are non-zero in one
	// of the two spellings, which §5.3 requires to be masked rather than
	// rejected.
	low := lookup(t, h, "?prefix=0&bits=1")
	high := lookup(t, h, "?prefix=f&bits=1")
	if len(low)+len(high) != n {
		t.Errorf("the two halves of a one-bit query hold %d+%d records, want %d", len(low), len(high), n)
	}
	for _, envelope := range append(append([][]byte{}, low...), high...) {
		if !containsBytes(all, envelope) {
			t.Error("a record returned by a narrower query was absent from bits=0")
		}
	}
}

// TestVectorRoundTrip publishes the envelope from the committed test vectors and
// reads it back.
//
// §9 makes the vectors a deliverable: independent implementations verify against
// them rather than against this codebase. Grounding the HTTP layer in the same
// file means the wire behaviour is anchored to the shared artefact and not only
// to fixtures this package invented — including the shipped proof-of-work
// difficulty of 20 bits, which no fixture here solves.
func TestVectorRoundTrip(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors.json"))
	if err != nil {
		t.Fatalf("reading the test vectors: %v", err)
	}

	var file struct {
		Envelope struct {
			Envelope json.RawMessage `json:"envelope"`
		} `json:"envelope"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decoding the test vectors: %v", err)
	}

	// The bytes as they are committed, indentation and all. Publishing these
	// rather than a re-encoding is deliberate: the pretty-printed form is a
	// second, free check that whitespace survives storage.
	sent := []byte(file.Envelope.Envelope)

	var env record.Envelope
	if err := json.Unmarshal(sent, &env); err != nil {
		t.Fatalf("decoding the vector envelope: %v", err)
	}

	// The vector's expires_at is fixed, so the clock is placed under it rather
	// than the other way around.
	h := newHarness(t, options{
		powBits: 20,
		now:     time.Unix(env.ExpiresAt-3600, 0).UTC(),
	})

	if got := h.status(http.MethodPut, "/v1/record", sent); got != http.StatusNoContent {
		t.Fatalf("publishing the vector envelope = %d, want 204", got)
	}

	found := lookup(t, h, "?bits=0")
	if len(found) != 1 {
		t.Fatalf("the lookup returned %d records, want 1", len(found))
	}
	if !bytes.Equal(found[0], sent) {
		t.Error("the vector envelope did not survive a publish and lookup byte for byte")
	}
}

// lookup issues a GET /v1/record and returns the raw envelopes.
func lookup(t *testing.T, h *harness, query string) [][]byte {
	t.Helper()

	resp, read := h.do(http.MethodGet, "/v1/record"+query, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/record%s = %d, want 200", query, resp.StatusCode)
	}

	var out struct {
		Records []json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal(read, &out); err != nil {
		t.Fatalf("decoding a lookup response: %v", err)
	}

	envelopes := make([][]byte, len(out.Records))
	for i, r := range out.Records {
		envelopes[i] = []byte(r)
	}
	return envelopes
}

func containsBytes(haystack [][]byte, needle []byte) bool {
	for _, h := range haystack {
		if bytes.Equal(h, needle) {
			return true
		}
	}
	return false
}

// withoutMember re-encodes an envelope with one member removed.
func withoutMember(t *testing.T, e record.Envelope, name string) []byte {
	t.Helper()

	var members map[string]json.RawMessage
	if err := json.Unmarshal(body(t, e), &members); err != nil {
		t.Fatalf("decoding an envelope fixture: %v", err)
	}
	delete(members, name)

	out, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("re-encoding an envelope fixture: %v", err)
	}
	return out
}

// withMember re-encodes an envelope with one member replaced by a raw JSON
// value, so that a case can supply something the struct cannot hold.
func withMember(t *testing.T, e record.Envelope, name, value string) []byte {
	t.Helper()

	var members map[string]json.RawMessage
	if err := json.Unmarshal(body(t, e), &members); err != nil {
		t.Fatalf("decoding an envelope fixture: %v", err)
	}
	members[name] = json.RawMessage(value)

	out, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("re-encoding an envelope fixture: %v", err)
	}
	return out
}
