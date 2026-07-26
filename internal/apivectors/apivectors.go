// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

// Package apivectors generates and describes testdata/api-vectors.json.
//
// DIRECTORY-SPEC.md §9 requires two shipped vector sets. The derivation
// vectors of internal/vectors cover §3.3, §4.1, §4.2 and §6.1 — the
// cryptography. These cover the API: "the status tables of §5.2 and §5.4, the
// evaluation order §5.2 mandates, and the verbatim-storage requirement — each
// fixture giving a method, path, query, headers and body against an expected
// status and body, so that an implementation in any language can drive them
// from its own harness".
//
// # What makes this file usable by somebody who does not read Go
//
// Every fixture is transport-shaped. A method, a path, a raw query string, a
// header map, a request body, an expected status, an expected body and the
// headers the response must and must not carry. Nothing in a fixture names a Go
// type, a route pattern or a framework, and nothing depends on the order the
// fixtures are driven in.
//
// Three things make that last claim true, and each is a requirement rather
// than a convenience:
//
//   - **The clock is fixed.** Expiry is time-dependent, so the file carries an
//     explicit `now` in Unix seconds and every expectation is evaluated against
//     it. Without that the fixtures would expire, and a second implementation
//     could not tell a conformance failure from a stale file.
//
//   - **The initial state is declared.** The recency rule of §5.2 and the
//     first-write-wins rule of §5.4 both depend on what is already stored, so
//     the file carries the records and the signal channels an instance must
//     hold before a fixture runs.
//
//   - **State is reset between fixtures.** Some fixtures store a record or
//     consume a blob. Rather than ordering them so that the mutations happen
//     to land harmlessly, every fixture is driven against a freshly
//     constructed instance in the declared initial state. Each fixture also
//     reports whether it mutates state, so a harness that cannot reset can see
//     which ones it must run last.
//
// # Generation is deterministic
//
// Running the generator twice produces byte-identical output. Nothing here
// reads the clock or draws from a CSPRNG: key material comes from counting
// seeds hashed with a domain string, nonces and ciphertexts are derived from
// the public key, and the proof-of-work search counts from zero.
//
// # The proof-of-work difficulty is 8, not the default 20
//
// §6.1 makes pow_bits an instance parameter that a directory advertises and MAY
// raise under load, so 8 is a conforming instance rather than a deviation. It
// is chosen because these vectors need roughly sixty solved proofs and the
// self-check regenerates them on every test run. Verification costs one SHA-256
// at any difficulty, so nothing about the directory's work is being skipped —
// only the publisher's. The shipped default of 20 is exercised by the
// derivation vectors, whose single proof was solved once and committed.
package apivectors

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Path is the committed location of the vector file, relative to the module
// root. Tests resolve it relative to their own package directory.
const Path = "testdata/api-vectors.json"

// File is the top-level structure of testdata/api-vectors.json.
//
// Field order is marshalling order. The underscore-prefixed members are meant
// to be read first by a human opening the file.
type File struct {
	Comment     string   `json:"_comment"`
	Warning     []string `json:"_warning"`
	Spec        string   `json:"spec"`
	GeneratedBy string   `json:"generated_by"`

	// Now is the directory's clock, in seconds since the Unix epoch, for every
	// fixture in the file. See the package comment.
	Now int64 `json:"now"`

	Encoding Encoding `json:"encoding"`
	Harness  Harness  `json:"harness"`

	Instances    []Instance   `json:"instances"`
	InitialState InitialState `json:"initial_state"`

	ResponseInvariants ResponseInvariants `json:"response_invariants"`

	Coverage []CoverageRow `json:"coverage"`
	Fixtures []Fixture     `json:"fixtures"`
}

// Encoding documents how a value in this file becomes bytes on the wire. It is
// prose rather than a schema because the audience is an implementer writing a
// harness in another language, who needs to know what to do before they need to
// validate anything.
type Encoding struct {
	Note          string       `json:"_note"`
	BinaryValues  string       `json:"binary_values"`
	Bodies        string       `json:"bodies"`
	BodyEncodings []NamedNote  `json:"body_encodings"`
	Comparisons   []NamedNote  `json:"comparisons"`
	Headers       string       `json:"headers"`
	Query         string       `json:"query"`
	Conditions    []NamedNote  `json:"conditions"`
	Tables        []TableOrder `json:"evaluation_order"`
}

// NamedNote is a name and the rule behind it.
type NamedNote struct {
	Name string `json:"name"`
	Note string `json:"note"`
}

// TableOrder records whether a status table's evaluation order is normative,
// and what that order is. §5.2's order is wire format: a request violating two
// conditions has exactly one correct answer, and a publisher's retry logic is
// driven entirely by the code.
type TableOrder struct {
	Table      string   `json:"table"`
	Normative  bool     `json:"order_is_normative"`
	Note       string   `json:"note"`
	Conditions []string `json:"conditions_in_order"`
}

// Harness states what a driver must do around each fixture.
type Harness struct {
	Note                 []string `json:"_note"`
	ResetBetweenFixtures bool     `json:"reset_between_fixtures"`
	OrderIndependent     bool     `json:"order_independent"`
}

// Instance is one configuration a fixture may be driven against. Every fixture
// names one.
type Instance struct {
	Name string   `json:"name"`
	Note []string `json:"note"`

	// The §5.1 advertised bounds, and the §5.2 clock-skew grace.
	MaxTTL         int64 `json:"max_ttl"`
	MaxRecordBytes int   `json:"max_record_bytes"`
	PoWBits        int   `json:"pow_bits"`
	SkewGrace      int64 `json:"skew_grace"`

	// Signal reports whether this instance brokers signal channels, which is
	// the "signal" member of GET /v1/meta and the difference between a 404 and
	// every other outcome in the §5.4 table.
	Signal bool `json:"signal"`

	// Draining is the "instance at capacity, or shutting down" state of §5.4.
	Draining bool `json:"draining"`

	MaxSignalBlobBytes      int   `json:"max_signal_blob_bytes"`
	SignalTTL               int64 `json:"signal_ttl"`
	SignalPollWindowMaximum int64 `json:"signal_poll_window_maximum"`

	KMin      int    `json:"k_min"`
	SourceURL string `json:"source_url"`

	RateLimits RateLimits `json:"rate_limits"`

	LoadInitialRecords  bool `json:"load_initial_records"`
	LoadInitialChannels bool `json:"load_initial_channels"`
}

// RateLimits are the §6.2 per-class allowances, counted per source per window.
type RateLimits struct {
	PutRecord     int   `json:"put_record"`
	GetRecord     int   `json:"get_record"`
	Signal        int   `json:"signal"`
	WindowSeconds int64 `json:"window_seconds"`
}

// InitialState is what an instance holds before a fixture runs.
type InitialState struct {
	Note           []string         `json:"_note"`
	Records        []InitialRecord  `json:"records"`
	SignalChannels []InitialChannel `json:"signal_channels"`
}

// InitialRecord is one pre-loaded record, given as the exact bytes a publisher
// sent.
//
// Loading it by issuing the PUT is deliberate: it means the initial state is
// reachable through the API rather than through a private storage interface,
// so a harness needs nothing beyond an HTTP client. A directory that loads its
// state some other way MUST store these bytes verbatim, because §5.2 requires
// the bytes returned by §5.3 to be the bytes received.
type InitialRecord struct {
	ID       string `json:"id"`
	Note     string `json:"note"`
	LookupID string `json:"lookup_id"`

	// LoadedAt is the clock reading the load PUT must be evaluated against. It
	// equals `now` for every record here; it is stated rather than assumed so
	// that a fixture file with a staggered load has somewhere to say so.
	LoadedAt  int64 `json:"loaded_at"`
	ExpiresAt int64 `json:"expires_at"`

	LoadExpectStatus int  `json:"load_expect_status"`
	Envelope         Body `json:"envelope"`
}

// InitialChannel is one pre-loaded signal channel.
type InitialChannel struct {
	ID        string `json:"id"`
	Note      string `json:"note"`
	ChannelID string `json:"channel_id"`

	// PostedAt is the clock reading the loading POST must be evaluated
	// against. One channel here is loaded in the past so that its blob has
	// expired at `now`, which is what distinguishes §5.4's "already holds an
	// unexpired blob" from "holds a blob".
	PostedAt  int64 `json:"posted_at"`
	ExpiresAt int64 `json:"expires_at"`
	Held      bool  `json:"held_at_now"`

	LoadExpectStatus int  `json:"load_expect_status"`
	Blob             Body `json:"blob"`
}

// ResponseInvariants are the things §5.5 requires of every /v1/ response,
// asserted on every fixture rather than restated on each.
type ResponseInvariants struct {
	Note          []string          `json:"_note"`
	AppliesTo     string            `json:"applies_to"`
	Headers       map[string]string `json:"headers"`
	HeadersAbsent []string          `json:"headers_absent"`
}

// CoverageRow is one row of a normative table and the fixtures that exercise
// it. The self-check fails if a row has no fixture, or if a fixture belongs to
// no row.
type CoverageRow struct {
	Table    string   `json:"table"`
	Row      string   `json:"row"`
	Status   int      `json:"status"`
	Fixtures []string `json:"fixtures"`
}

// Fixture is one request and everything expected of the response.
type Fixture struct {
	ID   string   `json:"id"`
	Spec string   `json:"spec"`
	Row  string   `json:"row"`
	Note []string `json:"note"`

	// Instance names the configuration in Instances this fixture is driven
	// against.
	Instance string `json:"instance"`

	// Conditions are the conditions of the fixture's status table that this
	// request violates, listed in that table's evaluation order. It is empty
	// for a request that violates none.
	Conditions []string `json:"violates"`

	// ExpectFirst is the condition whose code the response must carry: the
	// first violated condition in the table's order, or the success row's name
	// when nothing is violated.
	ExpectFirst string `json:"expect_first"`

	// OrderIsNormative is true only for §5.2, whose evaluation order is wire
	// format. Elsewhere the conditions are disjoint or all draw the same code.
	OrderIsNormative bool `json:"order_is_normative"`

	// Discriminating is false where two violated conditions draw the same code,
	// so the fixture cannot detect an implementation that evaluated them in the
	// wrong order. Such a fixture is kept because §5.2's cheapest-first
	// reasoning rests on the pair, and stated so that nobody mistakes it for a
	// test of the order.
	Discriminating bool `json:"discriminating"`

	// MutatesState reports whether a conforming response leaves the instance
	// different from how it started.
	MutatesState bool `json:"mutates_state"`

	PriorRequests []PriorRequest `json:"prior_requests"`
	Request       Request        `json:"request"`
	Expect        Expect         `json:"expect"`
}

// PriorRequest is a request that must be issued, against the same instance,
// before the fixture's own. It exists for the rate-limit rows, whose
// precondition is "this source's allowance for this class is already spent" —
// a state no single request can express.
type PriorRequest struct {
	Note         string  `json:"note"`
	Repeat       int     `json:"repeat"`
	ExpectStatus int     `json:"expect_status"`
	Request      Request `json:"request"`
}

// Request is a request in transport terms and nothing else.
type Request struct {
	Method string `json:"method"`
	Path   string `json:"path"`

	// Query is the raw query string, without the leading '?'. It is raw rather
	// than a map because §5.3 requires a repeated parameter to be rejected
	// rather than resolved, and a map cannot express one.
	Query string `json:"query"`

	// Headers are sent as given. Names are case-insensitive per RFC 9110.
	Headers map[string]string `json:"headers"`

	Body Body `json:"body"`
}

// Body is a request or response body, with its encoding stated on the value
// rather than inferred from the field it sits in.
type Body struct {
	// Encoding is one of "empty", "utf8", "base64url" or "repeated_byte". See
	// Encoding.BodyEncodings in the generated file.
	Encoding string `json:"encoding"`

	Value string `json:"value,omitempty"`

	// Byte and Length carry a "repeated_byte" body. An absent Byte means zero.
	Byte   int `json:"byte,omitempty"`
	Length int `json:"length,omitempty"`
}

// Expect is everything asserted about the response.
type Expect struct {
	Status int  `json:"status"`
	Body   Body `json:"body"`

	// Comparison is how Body is compared against what arrived: "empty",
	// "exact_bytes", "json_object" or "records_array". See
	// Encoding.Comparisons.
	Comparison string `json:"comparison"`

	// Headers must be present with exactly these values.
	Headers map[string]string `json:"headers"`

	// HeaderTokens name headers whose value is a comma-separated list that
	// must contain every listed token. Order and spacing are not significant,
	// and the header may carry more.
	HeaderTokens map[string][]string `json:"header_tokens"`

	// HeadersAbsent must not appear at all.
	HeadersAbsent []string `json:"headers_absent"`
}

// Body encodings. These names are part of the file format.
const (
	BodyEmpty        = "empty"
	BodyUTF8         = "utf8"
	BodyBase64URL    = "base64url"
	BodyRepeatedByte = "repeated_byte"
)

// Comparison modes. These names are part of the file format.
const (
	CompareEmpty        = "empty"
	CompareExactBytes   = "exact_bytes"
	CompareJSONObject   = "json_object"
	CompareRecordsArray = "records_array"
)

// Instance names. These are part of the file format.
const (
	InstanceDefault            = "default"
	InstanceSignalDisabled     = "signal-disabled"
	InstanceDraining           = "draining"
	InstanceLimitsOfOne        = "limits-of-one"
	InstanceDisabledAndLimited = "signal-disabled-limits-of-one"
)

// Marshal renders the vector file exactly as it is committed: two-space
// indent, HTML escaping off, and a trailing newline.
//
// Escaping off is load-bearing here rather than cosmetic. One pre-loaded record
// carries '<', '>' and '&' in a string value, and the whole point of that
// record is that those bytes reach a client unchanged. A file that escaped them
// would record the wrong expectation and the fixture that catches
// re-serialisation would be testing nothing.
func Marshal(f *File) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(f); err != nil {
		return nil, fmt.Errorf("apivectors: marshal: %w", err)
	}
	return buf.Bytes(), nil
}

// Bytes materialises a body into the bytes that go on the wire.
//
// It is exported because a harness in this repository and a reader working out
// what "repeated_byte" means need the same answer, and because the self-check
// must send exactly what an independent harness would send.
func (b Body) Bytes() ([]byte, error) {
	switch b.Encoding {
	case BodyEmpty, "":
		return nil, nil
	case BodyUTF8:
		return []byte(b.Value), nil
	case BodyBase64URL:
		raw, err := decodeBase64URL(b.Value)
		if err != nil {
			return nil, fmt.Errorf("apivectors: body: %w", err)
		}
		return raw, nil
	case BodyRepeatedByte:
		if b.Byte < 0 || b.Byte > 255 {
			return nil, fmt.Errorf("apivectors: body: repeated byte out of range")
		}
		if b.Length < 0 {
			return nil, fmt.Errorf("apivectors: body: negative length")
		}
		out := make([]byte, b.Length)
		for i := range out {
			out[i] = byte(b.Byte)
		}
		return out, nil
	}
	return nil, fmt.Errorf("apivectors: body: unknown encoding %q", b.Encoding)
}
