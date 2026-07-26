// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package apivectors

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"

	"github.com/trigstation/trigstationd/internal/b64"
	"github.com/trigstation/trigstationd/internal/query"
	"github.com/trigstation/trigstationd/internal/record"
	"github.com/trigstation/trigstationd/internal/signal"
)

// Condition names. These strings are part of the file format: a harness maps
// them onto its own rejection reasons, and the self-check maps them onto
// internal/reject to prove the expected status is the one the normative table
// binds to the condition.
//
// The §5.2 names are declared in the evaluation order §5.2 mandates.
const (
	condAccepted        = "accepted"
	condRateLimited     = "rate_limited"
	condTooLarge        = "too_large"
	condMalformed       = "malformed"
	condBadVersion      = "bad_version"
	condTTLTooLong      = "ttl_too_long"
	condLookupMismatch  = "lookup_mismatch"
	condPoWInsufficient = "pow_insufficient"
	condSigInvalid      = "sig_invalid"
	condExpired         = "expired"
	condNotNewer        = "not_newer"
)

// §5.4 condition names. The conditions of that table are disjoint, so their
// order carries no meaning.
const (
	condStored      = "stored"
	condDelivered   = "delivered"
	condEmpty       = "empty"
	condBadChannel  = "bad_channel"
	condConflict    = "conflict"
	condSignalLarge = "signal_too_large"
	condDisabled    = "signal_disabled"
)

// recordConditionOrder is the §5.2 table, in order. It is published in the
// file so that an implementer can compare their own ordering against it
// without reading this source.
var recordConditionOrder = []string{
	condRateLimited,
	condTooLarge,
	condMalformed,
	condBadVersion,
	condTTLTooLong,
	condLookupMismatch,
	condPoWInsufficient,
	condSigInvalid,
	condExpired,
	condNotNewer,
}

// coverageRows is every row of every normative table in §5, declared up front.
//
// The self-check fails if a row here has no fixture, and fails if a fixture
// belongs to no row. Coverage is therefore a property of the artefact rather
// than a claim in a report.
var coverageRows = []struct {
	key    string
	table  string
	row    string
	status int
}{
	{"5.1/meta", "§5.1", "GET /v1/meta returns all seven REQUIRED members, source_url non-empty", 200},
	{"5.1/signal-false", "§5.1", "An instance that does not broker signal channels advertises \"signal\": false", 200},

	{"5.2/accepted", "§5.2", "Accepted and stored", 204},
	{"5.2/rate-limited", "§5.2", "Rate limited", 429},
	{"5.2/too-large", "§5.2", "Received body exceeds max_record_bytes", 413},
	{"5.2/malformed", "§5.2", "Body is not well-formed JSON, a required member is absent, a value is not valid unpadded base64url, or a fixed-width field decodes to the wrong length", 400},
	{"5.2/bad-version", "§5.2", "v is not 1", 400},
	{"5.2/ttl-too-long", "§5.2", "expires_at exceeds now + max_ttl", 400},
	{"5.2/lookup-mismatch", "§5.2", "lookup_id is not SHA-256(wk_pub)", 403},
	{"5.2/pow", "§5.2", "pow does not satisfy pow_bits", 403},
	{"5.2/sig", "§5.2", "sig does not verify under wk_pub", 403},
	{"5.2/expired", "§5.2", "expires_at is not strictly greater than the directory's current time", 409},
	{"5.2/not-newer", "§5.2", "expires_at is not strictly greater than that of an unexpired stored record under the same lookup_id", 409},
	{"5.2/order", "§5.2", "The conditions MUST be evaluated in the order of that table, and the directory MUST return the code of the first condition that fails", 0},
	{"5.2/content-type", "§5.2", "A directory MUST NOT reject a request on the basis of its Content-Type", 204},
	{"5.2/verbatim", "§5.2", "Envelopes are stored and returned verbatim; the returned bytes are the received bytes", 200},

	{"5.3/match", "§5.3", "Returns every non-expired envelope whose lookup_id begins with the given bit prefix", 200},
	{"5.3/empty-result", "§5.3", "A directory with no matching records returns 200 with an empty records array, never 404", 200},
	{"5.3/mask-padding-bits", "§5.3", "Where bits is not a multiple of four a directory MUST mask and ignore the trailing bits, and MUST NOT reject the query because they are non-zero", 200},
	{"5.3/uppercase", "§5.3", "prefix is hex, case-insensitive: both a3f and A3F MUST be accepted", 200},
	{"5.3/bits-zero", "§5.3", "A directory MUST accept both ?prefix=&bits=0 and ?bits=0 with prefix absent", 200},
	{"5.3/over-precise", "§5.3", "Directories MUST enforce a maximum bits and reject over-precise queries with 400", 400},
	{"5.3/bits-required", "§5.3", "bits is REQUIRED; a directory MUST NOT infer it from the length of prefix", 400},
	{"5.3/bits-lexical", "§5.3", "bits is one or more ASCII digits: no sign, no leading zeros, no whitespace, no other notation", 400},
	{"5.3/bits-max-256", "§5.3", "bits MUST NOT exceed 256, the width of a lookup_id", 400},
	{"5.3/prefix-hex", "§5.3", "A directory MUST reject any character outside [0-9a-fA-F] with 400", 400},
	{"5.3/prefix-length", "§5.3", "prefix MUST contain exactly ceil(bits / 4) hex characters", 400},
	{"5.3/repeated-parameter", "§5.3", "A query supplying prefix or bits more than once MUST be rejected rather than resolved", 400},
	{"5.3/content-type", "§5.3", "GET /v1/record responds with Content-Type: application/json", 200},
	{"5.3/rate-limited", "§5.3", "Rate limited. §6.2 requires a per-source limit on GET as well as PUT, and §6.4 counts it as its own class; §5.3 states no code for it, and 429 is what §5.2 and §5.4 bind rate limiting to", 429},

	{"5.4/post-stored", "§5.4", "POST — Stored", 204},
	{"5.4/post-bad-channel", "§5.4", "POST — channel_id is not exactly 32 bytes of unpadded base64url", 400},
	{"5.4/post-too-large", "§5.4", "POST — body exceeds the §4.3 signal channel payload limit", 413},
	{"5.4/post-conflict", "§5.4", "POST — channel already holds an unexpired blob", 409},
	{"5.4/get-delivered", "§5.4", "GET — blob present, or one arrived within the long-poll window", 200},
	{"5.4/get-empty", "§5.4", "GET — long-poll window elapsed with no blob", 204},
	{"5.4/get-bad-channel", "§5.4", "GET — channel_id is not exactly 32 bytes of unpadded base64url", 400},
	{"5.4/rate-limited", "§5.4", "either — rate limited", 429},
	{"5.4/draining", "§5.4", "either — instance at capacity, or shutting down", 429},
	{"5.4/disabled", "§5.4", "either — instance advertises \"signal\": false", 404},
	{"5.4/octet-stream", "§5.4", "A 200 response carries Content-Type: application/octet-stream", 200},

	{"5.5/preflight", "§5.5", "OPTIONS preflight for PUT /v1/record and POST /v1/signal/{channel_id}", 204},
	{"5.5/allow-origin", "§5.5", "Access-Control-Allow-Origin: * on every /v1/ response. Asserted on every fixture in this file through response_invariants, not only on the ones listed here", 0},
	{"5.5/no-credentials", "§5.5", "Access-Control-Allow-Credentials MUST NOT be sent. Asserted on every fixture in this file through response_invariants, not only on the ones listed here", 0},
}

// generator carries the material every fixture is built from.
type generator struct {
	ctx context.Context

	// next is the next publisher seed index to draw from, so that no two
	// fixtures ever share an identifier by accident.
	next uint32

	initial  []storedRecord
	channels []InitialChannel

	// recency is the pre-loaded record the §5.2 recency fixtures republish
	// under, and recencyExpires is the expiry they are measured against.
	recency        *publisher
	recencyExpires int64

	// freeChannel, heldChannel and expiredChannel are the three pre-loaded
	// channel identifiers, by role.
	heldChannel    string
	expiredChannel string
	freeChannel    string
	sizeChannel    string
	heldBlob       []byte

	fixtures []Fixture
	coverage map[string][]string
}

// fixtureCase is the input to add. It exists so that each fixture below reads
// as a table row rather than as a struct literal with eleven zero values in it.
type fixtureCase struct {
	id       string
	spec     string
	row      string
	note     []string
	instance string

	conditions []string
	first      string
	ordered    bool
	blunt      bool // two violated conditions draw the same code
	mutates    bool

	prior   []PriorRequest
	request Request
	expect  Expect

	rows []string
}

func (g *generator) add(c fixtureCase) {
	instance := c.instance
	if instance == "" {
		instance = InstanceDefault
	}
	conditions := c.conditions
	if conditions == nil {
		conditions = []string{}
	}
	prior := c.prior
	if prior == nil {
		prior = []PriorRequest{}
	}

	g.fixtures = append(g.fixtures, Fixture{
		ID:               c.id,
		Spec:             c.spec,
		Row:              c.row,
		Note:             c.note,
		Instance:         instance,
		Conditions:       conditions,
		ExpectFirst:      c.first,
		OrderIsNormative: c.ordered,
		Discriminating:   !c.blunt,
		MutatesState:     c.mutates,
		PriorRequests:    prior,
		Request:          c.request,
		Expect:           c.expect,
	})

	for _, row := range c.rows {
		g.coverage[row] = append(g.coverage[row], c.id)
	}
}

// Request constructors. Each one is a transport shape and nothing more.

func putRecord(body string, headers map[string]string) Request {
	if headers == nil {
		headers = map[string]string{}
	}
	return Request{
		Method:  "PUT",
		Path:    "/v1/record",
		Query:   "",
		Headers: headers,
		Body:    Body{Encoding: BodyUTF8, Value: body},
	}
}

// vendorMediaType is the record media type of DIRECTORY-SPEC.md §0. §5.2 makes
// it advisory in both directions: a publisher SHOULD send it and a directory
// MUST NOT reject a request on the basis of its Content-Type.
const vendorMediaType = "application/vnd.trigstation.record+json"

func vendorType() map[string]string {
	return map[string]string{"Content-Type": vendorMediaType}
}

func getRecord(rawQuery string) Request {
	return Request{
		Method:  "GET",
		Path:    "/v1/record",
		Query:   rawQuery,
		Headers: map[string]string{},
		Body:    Body{Encoding: BodyEmpty},
	}
}

func postSignal(channelID string, body Body) Request {
	return Request{
		Method:  "POST",
		Path:    "/v1/signal/" + channelID,
		Query:   "",
		Headers: map[string]string{},
		Body:    body,
	}
}

func getSignal(channelID string) Request {
	return Request{
		Method:  "GET",
		Path:    "/v1/signal/" + channelID,
		Query:   "",
		Headers: map[string]string{},
		Body:    Body{Encoding: BodyEmpty},
	}
}

// Expectation constructors.

func expectStatus(status int) Expect {
	return Expect{
		Status:        status,
		Body:          Body{Encoding: BodyEmpty},
		Comparison:    CompareEmpty,
		Headers:       map[string]string{},
		HeaderTokens:  map[string][]string{},
		HeadersAbsent: []string{},
	}
}

func expectRecords(body string) Expect {
	e := expectStatus(200)
	e.Body = Body{Encoding: BodyUTF8, Value: body}
	e.Comparison = CompareRecordsArray
	e.Headers = map[string]string{"Content-Type": "application/json"}
	return e
}

func expectMeta(body string) Expect {
	e := expectStatus(200)
	e.Body = Body{Encoding: BodyUTF8, Value: body}
	e.Comparison = CompareJSONObject
	e.Headers = map[string]string{"Content-Type": "application/json"}
	return e
}

func expectBlob(blob []byte) Expect {
	e := expectStatus(200)
	e.Body = Body{Encoding: BodyBase64URL, Value: b64.Encode(blob)}
	e.Comparison = CompareExactBytes
	e.Headers = map[string]string{"Content-Type": "application/octet-stream"}
	return e
}

// buildInitialState creates the pre-loaded records and signal channels.
func (g *generator) buildInitialState() error {
	pubs, next := highPublishers(0, InitialRecordCount)
	g.next = next

	// The second publisher carries the adversarially formatted envelope and
	// the third is the recency target. Both are ordinary members of the table
	// otherwise, so that neither is reachable by a query that would not also
	// reach the rest.
	for i, p := range pubs {
		env, err := p.envelope(g.ctx, RecordExpiresAt)
		if err != nil {
			return err
		}

		rec := storedRecord{
			id:        fmt.Sprintf("record-%02d", i),
			publisher: p,
			expiresAt: RecordExpiresAt,
			body:      render(envelopeMembers(env)),
			note:      "An ordinary record. Its identifier begins with a 1 bit, like every record in this table.",
		}

		switch i {
		case 1:
			rec.id = "record-adversarial-formatting"
			rec.body = adversarialEnvelope(env)
			rec.note = "Stored with formatting a re-serialising directory would destroy: " +
				"non-minimal whitespace, member order differing from the §4.1 example, an unknown nested " +
				"member, and a string value containing '<', '>' and '&'. §5.2 requires the bytes returned " +
				"by §5.3 to be the bytes received, so every response containing this record is byte-exact " +
				"or the directory is re-encoding."
		case 2:
			rec.id = "record-recency-target"
			rec.note = "The record the §5.2 recency fixtures republish under. Its expires_at is the floor " +
				"a later publish must strictly exceed."
			g.recency = p
			g.recencyExpires = RecordExpiresAt
		}

		g.initial = append(g.initial, rec)
	}

	sortStored(g.initial)

	// Signal channels. The blob carries a NUL, a 0xff and the three characters
	// a JSON encoder is most likely to rewrite, because §5.4 forbids the
	// directory to interpret the body at all and a directory that treated a
	// blob as text would corrupt exactly these.
	g.heldBlob = append([]byte{0x00, 0x01, 0xff, 0xfe}, []byte("<offer> & \"answer\"")...)
	g.heldBlob = append(g.heldBlob, 0x00)

	g.heldChannel = channelID(1)
	g.expiredChannel = channelID(2)
	g.freeChannel = channelID(3)
	g.sizeChannel = channelID(4)

	g.channels = []InitialChannel{
		{
			ID: "channel-held",
			Note: "Holds an unexpired blob at now. This is the channel §5.4's first-write-wins rule " +
				"applies to, and the one a GET delivers.",
			ChannelID:        g.heldChannel,
			PostedAt:         Now,
			ExpiresAt:        Now + SignalTTL,
			Held:             true,
			LoadExpectStatus: 204,
			Blob:             Body{Encoding: BodyBase64URL, Value: b64.Encode(g.heldBlob)},
		},
		{
			ID: "channel-expired",
			Note: "Loaded far enough in the past that its blob has expired at now. §5.4 rejects a " +
				"second write only where the channel holds an *unexpired* blob, so a POST here is stored. " +
				"Load it with the instance's clock reading posted_at, then return the clock to now.",
			ChannelID:        g.expiredChannel,
			PostedAt:         Now - SignalTTL - 100,
			ExpiresAt:        Now - 100,
			Held:             false,
			LoadExpectStatus: 204,
			Blob:             Body{Encoding: BodyUTF8, Value: "a blob that has outlived its TTL"},
		},
	}

	return nil
}

// adversarialEnvelope renders an envelope in a form that is valid JSON, valid
// under §4.1, and destroyed by a directory that re-serialises what it stored.
//
// Four properties, each chosen for a different fault:
//
//   - Non-minimal whitespace, which every compacting encoder removes.
//   - Member order differing from the §4.1 example, which any directory
//     rebuilding the object from a struct silently normalises.
//   - An unknown nested member, which §10's additive-change policy requires a
//     directory to carry through and which a struct-based rebuild drops. This
//     is the case that makes an older directory usable as a transport by a
//     server and client both running a later revision.
//   - A string containing '<', '>' and '&', which Go's encoding/json escapes
//     when re-marshalling a raw value, and which several other languages
//     escape too. §5.2 names this fault directly.
//
// It is the fixture most likely to be left out, because an implementation with
// the fault passes every test that compares parsed structures rather than bytes.
func adversarialEnvelope(e record.Envelope) string {
	var b strings.Builder
	b.WriteString("{\n")
	b.WriteString("  \"sig\":  " + jsonString(e.Sig) + ",\n")
	b.WriteString("\n")
	b.WriteString("  \"expires_at\" :   " + strconv.FormatInt(e.ExpiresAt, 10) + ",\n")
	b.WriteString("  \"wk_pub\"\t: " + jsonString(e.WKPub) + ",\n")
	b.WriteString("  \"_extension\": {\n")
	b.WriteString("      \"introduced_after_this_directory_was_written\": true,\n")
	b.WriteString("      \"html\": \"a <b> tag & an > angle\",\n")
	b.WriteString("      \"nested\": { \"deep\": [ 1, 2, 3 ] }\n")
	b.WriteString("  },\n")
	b.WriteString("  \"lookup_id\": " + jsonString(e.LookupID) + ",\n")
	b.WriteString("  \"nonce\":" + jsonString(e.Nonce) + ",\n")
	b.WriteString("  \"pow\"   : " + jsonString(e.PoW) + ",\n")
	b.WriteString("  \"ct\": " + jsonString(e.CT) + ",\n")
	b.WriteString("  \"v\": 1\n")
	b.WriteString("}")
	return b.String()
}

// buildMetaFixtures covers DIRECTORY-SPEC.md §5.1.
func (g *generator) buildMetaFixtures() {
	body := func(signalOn bool) string {
		return fmt.Sprintf(
			`{"v":1,"record_count":%d,"max_ttl":%d,"max_record_bytes":%d,"pow_bits":%d,"signal":%t,"source_url":%s}`,
			len(g.initial), MaxTTL, MaxRecordBytes, PoWBits, signalOn, jsonString(SourceURL))
	}

	g.add(fixtureCase{
		id:   "meta-200-all-seven-members",
		spec: "§5.1",
		row:  "All seven members are REQUIRED",
		note: []string{
			"record_count is the true count of unexpired records here because §5.1's RECOMMENDED " +
				"reduction — round down to two significant figures — leaves a count below 100 unchanged.",
			"§5.1 permits record_count to be understated and forbids it from ever exceeding the true " +
				"count, so a harness whose instance rounds differently should assert record_count <= 40 " +
				"rather than equality.",
			"source_url MUST point at the source of the running instance. Configure the instance with " +
				"the value declared under instances[] to compare exactly; only its non-emptiness is normative.",
		},
		first:   condAccepted,
		request: Request{Method: "GET", Path: "/v1/meta", Query: "", Headers: map[string]string{}, Body: Body{Encoding: BodyEmpty}},
		expect:  expectMeta(body(true)),
		rows:    []string{"5.1/meta"},
	})

	g.add(fixtureCase{
		id:       "meta-200-signal-disabled",
		spec:     "§5.1",
		row:      "An instance that does not broker signal channels advertises \"signal\": false",
		instance: InstanceSignalDisabled,
		note: []string{
			"The member is emitted, not omitted. An instance with signal channels off is exactly the " +
				"instance a client most needs to be told about, and a client that saw no member would " +
				"discover the answer as a 404 it is entitled to read as \"try another directory\".",
		},
		first:   condAccepted,
		request: Request{Method: "GET", Path: "/v1/meta", Query: "", Headers: map[string]string{}, Body: Body{Encoding: BodyEmpty}},
		expect:  expectMeta(body(false)),
		rows:    []string{"5.1/signal-false"},
	})
}

// buildRecordFixtures covers DIRECTORY-SPEC.md §5.2: every row of the status
// table in isolation, then the evaluation order.
func (g *generator) buildRecordFixtures() error {
	// A publisher that is not in the initial state, so that its publish is a
	// first write rather than a replacement.
	fresh, next := highPublishers(g.next, 1)
	g.next = next
	accepted, err := fresh[0].envelope(g.ctx, RecordExpiresAt)
	if err != nil {
		return err
	}
	acceptedBody := render(envelopeMembers(accepted))

	g.add(fixtureCase{
		id:   "record-put-204-accepted",
		spec: "§5.2",
		row:  "Accepted and stored",
		note: []string{
			"Every condition passes: the body is inside max_record_bytes, v is 1, expires_at is in the " +
				"future and inside max_ttl, lookup_id is SHA-256(wk_pub), the proof of work meets pow_bits, " +
				"the signature verifies under wk_pub, and no record is stored under this lookup_id.",
			"There is no response body for any §5.2 outcome. The code is the whole answer.",
		},
		first:   condAccepted,
		mutates: true,
		request: putRecord(acceptedBody, vendorType()),
		expect:  expectStatus(204),
		rows:    []string{"5.2/accepted"},
	})

	// §5.2: a directory MUST NOT reject a publish on the basis of its
	// Content-Type. Four spellings, one outcome.
	contentTypes := []struct {
		id      string
		note    string
		headers map[string]string
	}{
		{"record-put-204-content-type-vendor", "The RECOMMENDED type. A browser publishing with it is forced into a CORS preflight, which is why §5.5 requires one.", vendorType()},
		{"record-put-204-content-type-json", "application/json is acceptable.", map[string]string{"Content-Type": "application/json"}},
		{"record-put-204-content-type-unrecognised", "An unrecognised type is acceptable.", map[string]string{"Content-Type": "text/plain;charset=utf-8"}},
		{"record-put-204-content-type-absent", "An absent header is acceptable. The body is validated in full either way.", map[string]string{}},
	}
	for _, c := range contentTypes {
		g.add(fixtureCase{
			id:   c.id,
			spec: "§5.2",
			row:  "A directory MUST NOT reject a request on the basis of its Content-Type",
			note: []string{
				c.note,
				"Rejecting on the header gains nothing, because the body is validated in full regardless, " +
					"and costs interoperability with constrained clients.",
			},
			first:   condAccepted,
			mutates: true,
			request: putRecord(acceptedBody, c.headers),
			expect:  expectStatus(204),
			rows:    []string{"5.2/content-type"},
		})
	}

	// Rate limited. The precondition is a state, not a request, so it is
	// expressed as an instance whose allowance is one and a prior request that
	// spends it.
	g.add(fixtureCase{
		id:       "record-put-429-rate-limited",
		spec:     "§5.2",
		row:      "Rate limited",
		instance: InstanceLimitsOfOne,
		note: []string{
			"Rate limiting is the first row of the §5.2 order, and it is first so that a flood costs the " +
				"directory as little as possible: the limit is applied before the body is read, let alone " +
				"parsed or measured.",
			"A fixture cannot express \"already rate limited\" in one request. It is expressed here as an " +
				"instance whose per-class allowance is 1 and a prior request of the same class that spends " +
				"it. The prior request is deliberately one that changes no state.",
			"§6.4 counts PUT /v1/record, GET /v1/record and signal channel access independently, so " +
				"spending this allowance must not affect the other two.",
		},
		conditions: []string{condRateLimited},
		first:      condRateLimited,
		ordered:    true,
		prior: []PriorRequest{{
			Note:         "Spends this source's single PUT allowance. Its own outcome is 400 and it stores nothing.",
			Repeat:       1,
			ExpectStatus: 400,
			Request:      putRecord("{}", vendorType()),
		}},
		request: putRecord(acceptedBody, vendorType()),
		expect:  expectStatus(429),
		rows:    []string{"5.2/rate-limited"},
	})

	// Size. Both sides of the boundary, because max_record_bytes is measured
	// against the received body as transmitted, before any parsing.
	sizePubs, next := highPublishers(g.next, 1)
	g.next = next
	sizeEnv, err := sizePubs[0].envelope(g.ctx, RecordExpiresAt)
	if err != nil {
		return err
	}
	atLimit, err := padTo(envelopeMembers(sizeEnv), MaxRecordBytes)
	if err != nil {
		return err
	}
	overLimit, err := padTo(envelopeMembers(sizeEnv), MaxRecordBytes+1)
	if err != nil {
		return err
	}

	g.add(fixtureCase{
		id:   "record-put-204-at-size-limit",
		spec: "§5.2",
		row:  "Accepted and stored",
		note: []string{
			fmt.Sprintf("The body is exactly max_record_bytes (%d) as transmitted. The limit is a maximum, "+
				"not a bound to stay under.", MaxRecordBytes),
			"The padding is an unknown member, which §10 requires a directory to ignore rather than reject.",
		},
		first:   condAccepted,
		mutates: true,
		request: putRecord(atLimit, vendorType()),
		expect:  expectStatus(204),
		rows:    []string{"5.2/accepted"},
	})

	g.add(fixtureCase{
		id:   "record-put-413-over-size-limit",
		spec: "§5.2",
		row:  "Received body exceeds max_record_bytes",
		note: []string{
			fmt.Sprintf("The body is max_record_bytes + 1 (%d) as transmitted. One byte is the whole "+
				"difference between this fixture and the one before it.", MaxRecordBytes+1),
			"Measured before any parsing, so a directory never has to buffer an oversized body to answer.",
		},
		conditions: []string{condTooLarge},
		first:      condTooLarge,
		ordered:    true,
		request:    putRecord(overLimit, vendorType()),
		expect:     expectStatus(413),
		rows:       []string{"5.2/too-large"},
	})

	// Malformed, one fixture per sub-condition of the row.
	malPubs, next := highPublishers(g.next, 1)
	g.next = next
	malEnv, err := malPubs[0].envelope(g.ctx, RecordExpiresAt)
	if err != nil {
		return err
	}
	mm := envelopeMembers(malEnv)

	paddedLookup, err := padded(malEnv.LookupID)
	if err != nil {
		return err
	}
	nonCanonicalLookup, err := nonCanonical(malEnv.LookupID)
	if err != nil {
		return err
	}
	shortNonce := b64.Encode(malPubs[0].nonce[:record.NonceLen-1])

	malformed := []struct {
		id   string
		note []string
		body string
	}{
		{
			"record-put-400-not-json",
			[]string{"The body is not JSON at all."},
			"this is not an envelope",
		},
		{
			"record-put-400-empty-body",
			[]string{"An empty body is not a well-formed envelope. It is worth stating because an empty " +
				"body is what a client library produces when a serialisation step silently fails."},
			"",
		},
		{
			"record-put-400-not-an-object",
			[]string{"Well-formed JSON, but not an object. An envelope is an object (§4.1)."},
			"[1,2,3]",
		},
		{
			"record-put-400-required-member-absent",
			[]string{"pow is absent. Every one of the eight members of §4.1 is needed to evaluate §5.2, so " +
				"an envelope missing any of them is malformed rather than merely unusual."},
			render(remove(mm, "pow")),
		},
		{
			"record-put-400-explicit-null",
			[]string{"pow is present with the value null. §5.2: an explicit null is not a value — a required " +
				"member present with the value null MUST be treated exactly as an absent member."},
			render(set(mm, "pow", "null")),
		},
		{
			"record-put-400-padded-base64url",
			[]string{"lookup_id is the padded spelling of the same 32 bytes. §4.4 requires padded input to " +
				"be rejected as malformed rather than stripped, because a directory stores and returns " +
				"envelopes verbatim: anything it tolerates it hands unchanged to every client that queries. " +
				"Tolerance here does not contain a malformed encoding, it distributes one.",
				"Java's Base64.getUrlEncoder and Python's urlsafe_b64encode pad by default, so this is among " +
					"the first things an implementer on those platforms gets wrong."},
			render(set(mm, "lookup_id", jsonString(paddedLookup))),
		},
		{
			"record-put-400-non-canonical-base64url",
			[]string{"lookup_id decodes to the right 32 bytes but its final character carries non-zero " +
				"unused bits. A 32-byte value occupies 43 characters carrying 258 bits, so without §4.4's " +
				"canonical-encoding rule there are four spellings of every such value — all of which verify, " +
				"and all of which would be served."},
			render(set(mm, "lookup_id", jsonString(nonCanonicalLookup))),
		},
		{
			"record-put-400-wrong-decoded-length",
			[]string{"nonce decodes to 11 bytes where §4.1 fixes 12. A fixed-width field that decodes to the " +
				"wrong length is malformed, not merely unusual: the signing input of §4.1 is a bare " +
				"concatenation, and its injectivity depends on every field before ct having its declared width."},
			render(set(mm, "nonce", jsonString(shortNonce))),
		},
		{
			"record-put-400-duplicate-member",
			[]string{"expires_at appears twice. §5.2 requires this to be rejected rather than resolved: " +
				"parsers disagree about which occurrence wins — Go takes the last, many others the first — " +
				"and because a directory verifies a signature over the fields it parsed and then stores the " +
				"bytes verbatim, a first-wins directory and a last-wins client can end up disagreeing about " +
				"an expires_at the directory never validated.",
				"That is a signature bypass wearing a parser disagreement as a costume."},
			render(append(append([]member(nil), mm...), member{"expires_at", strconv.FormatInt(Now+60, 10)})),
		},
	}

	for _, m := range malformed {
		g.add(fixtureCase{
			id:         m.id,
			spec:       "§5.2",
			row:        "Body is not well-formed JSON, a required member is absent, a value is not valid unpadded base64url, or a fixed-width field decodes to the wrong length",
			note:       m.note,
			conditions: []string{condMalformed},
			first:      condMalformed,
			ordered:    true,
			request:    putRecord(m.body, vendorType()),
			expect:     expectStatus(400),
			rows:       []string{"5.2/malformed"},
		})
	}

	g.add(fixtureCase{
		id:   "record-put-400-bad-version",
		spec: "§5.2",
		row:  "v is not 1",
		note: []string{
			"v is 2 on a /v1/ path. §4.1 is explicit that this is a rejection rather than an application " +
				"of the unknown-field rule: v pins the format, so it is not an unknown field.",
			"Every other unrecognised member is ignored (§10), which is what makes an additive change to " +
				"v1 deployable at all.",
		},
		conditions: []string{condBadVersion},
		first:      condBadVersion,
		ordered:    true,
		request:    putRecord(render(set(mm, "v", "2")), vendorType()),
		expect:     expectStatus(400),
		rows:       []string{"5.2/bad-version"},
	})

	// TTL, both sides of the skew grace.
	ttlPubs, next := highPublishers(g.next, 2)
	g.next = next

	atGrace := Now + MaxTTL + SkewGrace
	graceEnv, err := ttlPubs[0].envelope(g.ctx, atGrace)
	if err != nil {
		return err
	}
	g.add(fixtureCase{
		id:   "record-put-204-at-ttl-skew-grace",
		spec: "§5.2",
		row:  "Accepted and stored",
		note: []string{
			fmt.Sprintf("expires_at is now + max_ttl + %d, exactly the grace §5.2 asks a directory to allow "+
				"above max_ttl before rejecting.", SkewGrace),
			"The grace exists because expires_at is computed from the publisher's clock and evaluated " +
				"against the directory's, and neither party can observe the other's. Servers SHOULD leave " +
				"headroom and directories SHOULD allow grace — both, not either: one alone still permits " +
				"the failure, which presents as a directory rejecting every publish for no visible reason.",
		},
		first:   condAccepted,
		mutates: true,
		request: putRecord(render(envelopeMembers(graceEnv)), vendorType()),
		expect:  expectStatus(204),
		rows:    []string{"5.2/accepted"},
	})

	overGrace := Now + MaxTTL + SkewGrace + 1
	overEnv, err := ttlPubs[1].envelope(g.ctx, overGrace)
	if err != nil {
		return err
	}
	g.add(fixtureCase{
		id:   "record-put-400-ttl-too-long",
		spec: "§5.2",
		row:  "expires_at exceeds now + max_ttl",
		note: []string{
			"One second beyond the grace. Everything else about this envelope is valid.",
			"An over-long TTL is 400 despite also concerning expires_at, because its remedy differs from " +
				"the 409 rows: reduce the configured TTL and re-solve the proof of work, rather than " +
				"republish with a later expiry.",
		},
		conditions: []string{condTTLTooLong},
		first:      condTTLTooLong,
		ordered:    true,
		request:    putRecord(render(envelopeMembers(overEnv)), vendorType()),
		expect:     expectStatus(400),
		rows:       []string{"5.2/ttl-too-long"},
	})

	// lookup_id is not SHA-256(wk_pub). Every other condition holds: the proof
	// of work is solved over the stated identifier and the signature covers it.
	mismatchPubs, next := highPublishers(g.next, 2)
	g.next = next
	stated := mismatchPubs[1].lookupID
	signer := mismatchPubs[0]
	mismatchPoW, err := pubSolve(g.ctx, stated, RecordExpiresAt)
	if err != nil {
		return err
	}
	mismatchEnv := record.Envelope{
		V:         record.Version,
		LookupID:  b64.Encode(stated),
		WKPub:     b64.Encode(signer.pub),
		ExpiresAt: RecordExpiresAt,
		CT:        b64.Encode(signer.ct),
		Nonce:     b64.Encode(signer.nonce),
		PoW:       b64.Encode(mismatchPoW),
		Sig: b64.Encode(record.Sign(signer.priv, record.Version,
			stated, signer.pub, RecordExpiresAt, signer.nonce, signer.ct)),
	}
	g.add(fixtureCase{
		id:   "record-put-403-lookup-mismatch",
		spec: "§5.2",
		row:  "lookup_id is not SHA-256(wk_pub)",
		note: []string{
			"lookup_id is a valid 32-byte identifier belonging to a different key. The proof of work is " +
				"solved over the identifier as stated and the signature verifies under wk_pub, so this " +
				"fixture violates the binding and nothing else.",
			"One SHA-256 settles it, which is why §5.2 puts it ahead of the Ed25519 verification: a " +
				"flooding client is rejected on the cheap check.",
		},
		conditions: []string{condLookupMismatch},
		first:      condLookupMismatch,
		ordered:    true,
		request:    putRecord(render(envelopeMembers(mismatchEnv)), vendorType()),
		expect:     expectStatus(403),
		rows:       []string{"5.2/lookup-mismatch"},
	})

	// pow does not satisfy pow_bits. The proof is not part of the signing
	// input, so the signature is still valid.
	powPubs, next := highPublishers(g.next, 1)
	g.next = next
	powEnv, err := powPubs[0].envelope(g.ctx, RecordExpiresAt)
	if err != nil {
		return err
	}
	weak := insufficientPoW(powPubs[0].lookupID, RecordExpiresAt)
	g.add(fixtureCase{
		id:   "record-put-403-pow-insufficient",
		spec: "§5.2",
		row:  "pow does not satisfy pow_bits",
		note: []string{
			fmt.Sprintf("SHA-256(\"trig-pow-v1\" || lookup_id || expires_at || pow) has fewer than %d "+
				"leading zero bits, with expires_at and pow each 8 bytes big-endian per §0.1.", PoWBits),
			"pow is not part of the envelope signing input (§4.1), so the signature on this envelope is " +
				"valid: this fixture violates the proof of work and nothing else.",
		},
		conditions: []string{condPoWInsufficient},
		first:      condPoWInsufficient,
		ordered:    true,
		request:    putRecord(render(set(envelopeMembers(powEnv), "pow", jsonString(b64.Encode(weak)))), vendorType()),
		expect:     expectStatus(403),
		rows:       []string{"5.2/pow"},
	})

	// sig does not verify under wk_pub.
	sigPubs, next := highPublishers(g.next, 2)
	g.next = next
	sigEnv, err := sigPubs[0].envelope(g.ctx, RecordExpiresAt)
	if err != nil {
		return err
	}
	wrongSig := record.Sign(sigPubs[1].priv, record.Version,
		sigPubs[0].lookupID, sigPubs[0].pub, RecordExpiresAt, sigPubs[0].nonce, sigPubs[0].ct)
	g.add(fixtureCase{
		id:   "record-put-403-sig-invalid",
		spec: "§5.2",
		row:  "sig does not verify under wk_pub",
		note: []string{
			"A syntactically valid 64-byte Ed25519 signature made with a different key, over the correct " +
				"canonical bytes. The signature is the authorisation: there is no header to check and no " +
				"account to consult.",
			"It is the most expensive check in the pipeline by roughly two orders of magnitude, which is " +
				"why §5.2 puts it last of the cryptographic three.",
		},
		conditions: []string{condSigInvalid},
		first:      condSigInvalid,
		ordered:    true,
		request:    putRecord(render(set(envelopeMembers(sigEnv), "sig", jsonString(b64.Encode(wrongSig)))), vendorType()),
		expect:     expectStatus(403),
		rows:       []string{"5.2/sig"},
	})

	// expires_at is not strictly greater than the directory's current time.
	expiredPubs, next := highPublishers(g.next, 2)
	g.next = next
	atNow, err := expiredPubs[0].envelope(g.ctx, Now)
	if err != nil {
		return err
	}
	g.add(fixtureCase{
		id:   "record-put-409-expires-at-equals-now",
		spec: "§5.2",
		row:  "expires_at is not strictly greater than the directory's current time",
		note: []string{
			"expires_at is exactly now. §5.2: a record is live if and only if expires_at is strictly " +
				"greater than the directory's current time; at equality it is absent.",
			"Equality is not a corner worth leaving open — §5.2's requirement that two conforming " +
				"directories return identical results is not a guarantee if it has a one-second hole in it.",
		},
		conditions: []string{condExpired},
		first:      condExpired,
		ordered:    true,
		request:    putRecord(render(envelopeMembers(atNow)), vendorType()),
		expect:     expectStatus(409),
		rows:       []string{"5.2/expired"},
	})

	beforeNow, err := expiredPubs[1].envelope(g.ctx, Now-1)
	if err != nil {
		return err
	}
	g.add(fixtureCase{
		id:   "record-put-409-expires-at-in-the-past",
		spec: "§5.2",
		row:  "expires_at is not strictly greater than the directory's current time",
		note: []string{
			"One second before now. 409 rather than 400 because the remedy is the publisher's to apply " +
				"and is the same as the recency rule's: republish with a later expiry, one branch in the " +
				"publisher rather than two.",
		},
		conditions: []string{condExpired},
		first:      condExpired,
		ordered:    true,
		request:    putRecord(render(envelopeMembers(beforeNow)), vendorType()),
		expect:     expectStatus(409),
		rows:       []string{"5.2/expired"},
	})

	// The recency rule, in three parts: equal, older, and newer.
	equalEnv, err := g.recency.envelope(g.ctx, g.recencyExpires)
	if err != nil {
		return err
	}
	g.add(fixtureCase{
		id:   "record-put-409-not-newer-equal",
		spec: "§5.2",
		row:  "expires_at is not strictly greater than that of an unexpired stored record under the same lookup_id",
		note: []string{
			"A byte-for-byte replay of the record already stored under this lookup_id. Within an epoch " +
				"the write key is stable, so a captured earlier envelope still verifies — the recency rule " +
				"is what stops a replay silently rolling the server's published address back until the " +
				"next republish, where the rollback would present as a stale address rather than an error.",
			"Strictly greater: equal is rejected.",
		},
		conditions: []string{condNotNewer},
		first:      condNotNewer,
		ordered:    true,
		request:    putRecord(render(envelopeMembers(equalEnv)), vendorType()),
		expect:     expectStatus(409),
		rows:       []string{"5.2/not-newer"},
	})

	olderEnv, err := g.recency.envelope(g.ctx, g.recencyExpires-1)
	if err != nil {
		return err
	}
	g.add(fixtureCase{
		id:   "record-put-409-not-newer-older",
		spec: "§5.2",
		row:  "expires_at is not strictly greater than that of an unexpired stored record under the same lookup_id",
		note: []string{
			"An expiry one second below the stored record's, and still comfortably in the future — so " +
				"this fixture fails the recency rule and not the future-expiry check above it.",
		},
		conditions: []string{condNotNewer},
		first:      condNotNewer,
		ordered:    true,
		request:    putRecord(render(envelopeMembers(olderEnv)), vendorType()),
		expect:     expectStatus(409),
		rows:       []string{"5.2/not-newer"},
	})

	newerEnv, err := g.recency.envelope(g.ctx, g.recencyExpires+1)
	if err != nil {
		return err
	}
	g.add(fixtureCase{
		id:   "record-put-204-newer-replaces",
		spec: "§5.2",
		row:  "Accepted and stored",
		note: []string{
			"One second above the stored record's expiry is enough. On success the record replaces the " +
				"existing one under the same lookup_id — there is one record per lookup_id (§4.3).",
			"This fixture mutates state: after it, the record served under this identifier is this one.",
		},
		first:   condAccepted,
		mutates: true,
		request: putRecord(render(envelopeMembers(newerEnv)), vendorType()),
		expect:  expectStatus(204),
		rows:    []string{"5.2/accepted"},
	})

	return g.buildOrderFixtures(overLimit)
}

// buildOrderFixtures is the part of §5.2 that single-fault testing cannot
// reach.
//
// §5.2 requires the conditions to be evaluated in the order of its table and
// the directory to return the code of the first that fails. A request violating
// two conditions therefore has exactly one correct answer, and a publisher's
// retry logic — driven entirely by the status code — depends on getting the
// same answer from every directory. Nothing about a single-fault fixture can
// detect an implementation that checks the signature before the size.
func (g *generator) buildOrderFixtures(overLimit string) error {
	// Two conditions: too large and malformed. 413 wins.
	brokenOverLimit := overLimit[:len(overLimit)-1] + ","
	g.add(fixtureCase{
		id:   "record-put-order-413-before-400-malformed",
		spec: "§5.2",
		row:  "Evaluation order: two conditions violated",
		note: []string{
			"The body is max_record_bytes + 1 bytes and is not well-formed JSON. Size is row 3 and " +
				"malformation row 4, so the answer is 413.",
			"An implementation that parses before measuring answers 400 here, and it is right about the " +
				"body and wrong about the protocol: the size check exists so that an oversized body is " +
				"never parsed.",
		},
		conditions: []string{condTooLarge, condMalformed},
		first:      condTooLarge,
		ordered:    true,
		request:    putRecord(brokenOverLimit, vendorType()),
		expect:     expectStatus(413),
		rows:       []string{"5.2/order", "5.2/too-large"},
	})

	// Two conditions: lookup mismatch and expired. 403 wins.
	pubs, next := highPublishers(g.next, 2)
	g.next = next
	stated := pubs[1].lookupID
	signer := pubs[0]
	solved, err := pubSolve(g.ctx, stated, Now)
	if err != nil {
		return err
	}
	env := record.Envelope{
		V:         record.Version,
		LookupID:  b64.Encode(stated),
		WKPub:     b64.Encode(signer.pub),
		ExpiresAt: Now,
		CT:        b64.Encode(signer.ct),
		Nonce:     b64.Encode(signer.nonce),
		PoW:       b64.Encode(solved),
		Sig: b64.Encode(record.Sign(signer.priv, record.Version,
			stated, signer.pub, Now, signer.nonce, signer.ct)),
	}
	g.add(fixtureCase{
		id:   "record-put-order-403-lookup-before-409-expired",
		spec: "§5.2",
		row:  "Evaluation order: two conditions violated",
		note: []string{
			"lookup_id is not SHA-256(wk_pub) (row 7) and expires_at equals now (row 10). The answer is 403.",
			"The two codes carry different remedies — 403 means the envelope is wrong, 409 means republish " +
				"with a later expiry — so a directory that answered 409 would send a conforming publisher " +
				"into a retry loop it can never escape.",
		},
		conditions: []string{condLookupMismatch, condExpired},
		first:      condLookupMismatch,
		ordered:    true,
		request:    putRecord(render(envelopeMembers(env)), vendorType()),
		expect:     expectStatus(403),
		rows:       []string{"5.2/order"},
	})

	// Two conditions: signature invalid and not newer. 403 wins.
	replayPoW, err := pubSolve(g.ctx, g.recency.lookupID, g.recencyExpires)
	if err != nil {
		return err
	}
	otherKey, next := highPublishers(g.next, 1)
	g.next = next
	badSigReplay := record.Envelope{
		V:         record.Version,
		LookupID:  b64.Encode(g.recency.lookupID),
		WKPub:     b64.Encode(g.recency.pub),
		ExpiresAt: g.recencyExpires,
		CT:        b64.Encode(g.recency.ct),
		Nonce:     b64.Encode(g.recency.nonce),
		PoW:       b64.Encode(replayPoW),
		Sig: b64.Encode(record.Sign(otherKey[0].priv, record.Version,
			g.recency.lookupID, g.recency.pub, g.recencyExpires, g.recency.nonce, g.recency.ct)),
	}
	g.add(fixtureCase{
		id:   "record-put-order-403-sig-before-409-not-newer",
		spec: "§5.2",
		row:  "Evaluation order: two conditions violated",
		note: []string{
			"The signature does not verify (row 9) and the expiry does not exceed the stored record's " +
				"(row 11). The answer is 403.",
			"The recency rule is last in the order because it is the only condition requiring a storage " +
				"read. A rejected publish never touches the database, which is also why this fixture " +
				"leaves the stored record untouched.",
		},
		conditions: []string{condSigInvalid, condNotNewer},
		first:      condSigInvalid,
		ordered:    true,
		request:    putRecord(render(envelopeMembers(badSigReplay)), vendorType()),
		expect:     expectStatus(403),
		rows:       []string{"5.2/order"},
	})

	// Three conditions: TTL, proof of work, signature. 400 wins.
	threePubs, next := highPublishers(g.next, 2)
	g.next = next
	over := Now + MaxTTL + SkewGrace + 1
	threeEnv := record.Envelope{
		V:         record.Version,
		LookupID:  b64.Encode(threePubs[0].lookupID),
		WKPub:     b64.Encode(threePubs[0].pub),
		ExpiresAt: over,
		CT:        b64.Encode(threePubs[0].ct),
		Nonce:     b64.Encode(threePubs[0].nonce),
		PoW:       b64.Encode(insufficientPoW(threePubs[0].lookupID, over)),
		Sig: b64.Encode(record.Sign(threePubs[1].priv, record.Version,
			threePubs[0].lookupID, threePubs[0].pub, over, threePubs[0].nonce, threePubs[0].ct)),
	}
	g.add(fixtureCase{
		id:   "record-put-order-400-ttl-before-403-pow-and-sig",
		spec: "§5.2",
		row:  "Evaluation order: three conditions violated",
		note: []string{
			"expires_at is beyond max_ttl plus the skew grace (row 6), the proof of work is insufficient " +
				"(row 8) and the signature does not verify (row 9). The answer is 400.",
			"This is the case where an implementation ordering by cost alone diverges: both 403 conditions " +
				"are cheaper to reach than they look, and neither may be evaluated first.",
		},
		conditions: []string{condTTLTooLong, condPoWInsufficient, condSigInvalid},
		first:      condTTLTooLong,
		ordered:    true,
		request:    putRecord(render(envelopeMembers(threeEnv)), vendorType()),
		expect:     expectStatus(400),
		rows:       []string{"5.2/order"},
	})

	// Four conditions: version, lookup binding, proof of work, signature. 400.
	fourPubs, next := highPublishers(g.next, 3)
	g.next = next
	fourEnv := record.Envelope{
		V:         2,
		LookupID:  b64.Encode(fourPubs[1].lookupID),
		WKPub:     b64.Encode(fourPubs[0].pub),
		ExpiresAt: RecordExpiresAt,
		CT:        b64.Encode(fourPubs[0].ct),
		Nonce:     b64.Encode(fourPubs[0].nonce),
		PoW:       b64.Encode(insufficientPoW(fourPubs[1].lookupID, RecordExpiresAt)),
		Sig: b64.Encode(record.Sign(fourPubs[2].priv, record.Version,
			fourPubs[1].lookupID, fourPubs[0].pub, RecordExpiresAt, fourPubs[0].nonce, fourPubs[0].ct)),
	}
	g.add(fixtureCase{
		id:   "record-put-order-400-version-before-three-403s",
		spec: "§5.2",
		row:  "Evaluation order: four conditions violated",
		note: []string{
			"v is 2 (row 5), lookup_id is not SHA-256(wk_pub) (row 7), the proof of work is insufficient " +
				"(row 8) and the signature does not verify (row 9). The answer is 400.",
			"Three of the four violations draw 403, so an implementation that evaluated the cryptographic " +
				"conditions first would answer 403 consistently and look entirely reasonable doing it.",
		},
		conditions: []string{condBadVersion, condLookupMismatch, condPoWInsufficient, condSigInvalid},
		first:      condBadVersion,
		ordered:    true,
		request:    putRecord(render(envelopeMembers(fourEnv)), vendorType()),
		expect:     expectStatus(400),
		rows:       []string{"5.2/order"},
	})

	// Four conditions with the limiter first. 429.
	limitPubs, next := highPublishers(g.next, 1)
	g.next = next
	limitEnv := record.Envelope{
		V:         2,
		LookupID:  b64.Encode(limitPubs[0].lookupID),
		WKPub:     b64.Encode(limitPubs[0].pub),
		ExpiresAt: Now,
		CT:        b64.Encode(limitPubs[0].ct),
		Nonce:     b64.Encode(limitPubs[0].nonce),
		PoW:       b64.Encode(insufficientPoW(limitPubs[0].lookupID, Now)),
		Sig: b64.Encode(record.Sign(limitPubs[0].priv, record.Version,
			limitPubs[0].lookupID, limitPubs[0].pub, Now, limitPubs[0].nonce, limitPubs[0].ct)),
	}
	oversizedBadVersion, err := padTo(envelopeMembers(limitEnv), MaxRecordBytes+1)
	if err != nil {
		return err
	}
	g.add(fixtureCase{
		id:       "record-put-order-429-before-everything",
		spec:     "§5.2",
		row:      "Evaluation order: four conditions violated",
		instance: InstanceLimitsOfOne,
		note: []string{
			"The source's allowance is spent (row 2), the body is over max_record_bytes (row 3), v is 2 " +
				"(row 5) and expires_at equals now (row 10). The answer is 429.",
			"Rate limiting is first in the order precisely so that none of the work below it is done. An " +
				"implementation that answered 413 here has read and measured a body it was entitled to " +
				"drop, which is the cost the ordering exists to avoid.",
		},
		conditions: []string{condRateLimited, condTooLarge, condBadVersion, condExpired},
		first:      condRateLimited,
		ordered:    true,
		prior: []PriorRequest{{
			Note:         "Spends this source's single PUT allowance without storing anything.",
			Repeat:       1,
			ExpectStatus: 400,
			Request:      putRecord("{}", vendorType()),
		}},
		request: putRecord(oversizedBadVersion, vendorType()),
		expect:  expectStatus(429),
		rows:    []string{"5.2/order", "5.2/rate-limited"},
	})

	// Two pairs that cannot discriminate, kept because the reasoning §5.2
	// gives for their order rests on them.
	bluntPubs, next := highPublishers(g.next, 2)
	g.next = next
	bluntEnv := record.Envelope{
		V:         record.Version,
		LookupID:  b64.Encode(bluntPubs[0].lookupID),
		WKPub:     b64.Encode(bluntPubs[0].pub),
		ExpiresAt: RecordExpiresAt,
		CT:        b64.Encode(bluntPubs[0].ct),
		Nonce:     b64.Encode(bluntPubs[0].nonce),
		PoW:       b64.Encode(insufficientPoW(bluntPubs[0].lookupID, RecordExpiresAt)),
		Sig: b64.Encode(record.Sign(bluntPubs[1].priv, record.Version,
			bluntPubs[0].lookupID, bluntPubs[0].pub, RecordExpiresAt, bluntPubs[0].nonce, bluntPubs[0].ct)),
	}
	g.add(fixtureCase{
		id:   "record-put-order-403-pow-and-sig-are-indistinguishable",
		spec: "§5.2",
		row:  "Evaluation order: two conditions violated, same code",
		note: []string{
			"The proof of work is insufficient (row 8) and the signature does not verify (row 9). Both " +
				"draw 403, so this fixture cannot detect an implementation that evaluates them in the " +
				"wrong order — and it says so rather than implying a check it does not perform.",
			"It is here because §5.2's ordering argument rests on this pair: the SHA-256 precedes the " +
				"Ed25519 verification, which costs roughly two orders of magnitude more. The order is " +
				"unobservable on the wire and load-bearing under flood.",
		},
		conditions: []string{condPoWInsufficient, condSigInvalid},
		first:      condPoWInsufficient,
		ordered:    true,
		blunt:      true,
		request:    putRecord(render(envelopeMembers(bluntEnv)), vendorType()),
		expect:     expectStatus(403),
		rows:       []string{"5.2/order"},
	})

	expiredReplayPoW, err := pubSolve(g.ctx, g.recency.lookupID, Now)
	if err != nil {
		return err
	}
	expiredReplay := record.Envelope{
		V:         record.Version,
		LookupID:  b64.Encode(g.recency.lookupID),
		WKPub:     b64.Encode(g.recency.pub),
		ExpiresAt: Now,
		CT:        b64.Encode(g.recency.ct),
		Nonce:     b64.Encode(g.recency.nonce),
		PoW:       b64.Encode(expiredReplayPoW),
		Sig: b64.Encode(record.Sign(g.recency.priv, record.Version,
			g.recency.lookupID, g.recency.pub, Now, g.recency.nonce, g.recency.ct)),
	}
	g.add(fixtureCase{
		id:   "record-put-order-409-expired-and-not-newer",
		spec: "§5.2",
		row:  "Evaluation order: two conditions violated, same code",
		note: []string{
			"expires_at equals now (row 10) and does not exceed the stored record's expiry (row 11). Both " +
				"draw 409, deliberately: §5.2 groups codes by the publisher's remedy, and the remedy for " +
				"both is the same — republish with a later expiry, one branch in the publisher rather than two.",
			"So this fixture also cannot discriminate, and is not intended to.",
		},
		conditions: []string{condExpired, condNotNewer},
		first:      condExpired,
		ordered:    true,
		blunt:      true,
		request:    putRecord(render(envelopeMembers(expiredReplay)), vendorType()),
		expect:     expectStatus(409),
		rows:       []string{"5.2/order"},
	})

	return nil
}

// pubSolve solves a proof of work for an identifier that has no publisher of
// its own — the lookup-mismatch fixtures state an identifier belonging to a
// different key, and the proof must cover the identifier as stated.
func pubSolve(ctx context.Context, lookupID []byte, expiresAt int64) ([]byte, error) {
	p := &publisher{lookupID: lookupID}
	return p.solve(ctx, expiresAt)
}

// padTo appends an unknown member of exactly the size needed to bring the
// rendered object to total bytes.
func padTo(ms []member, total int) (string, error) {
	const name = "_pad"

	base := len(render(append(append([]member(nil), ms...), member{name, `""`})))
	if base > total {
		return "", fmt.Errorf("apivectors: cannot pad to %d bytes: the envelope already needs %d", total, base)
	}
	padded := append(append([]member(nil), ms...), member{name, jsonString(strings.Repeat("p", total-base))})

	out := render(padded)
	if len(out) != total {
		return "", fmt.Errorf("apivectors: padded to %d bytes, want %d", len(out), total)
	}
	return out, nil
}

// buildLookupFixtures covers DIRECTORY-SPEC.md §5.3.
func (g *generator) buildLookupFixtures() error {
	all := recordsBody(g.initial)
	empty := recordsBody(nil)

	matched, err := matchingRecords(g.initial, "8", 1)
	if err != nil {
		return err
	}
	if len(matched) != len(g.initial) {
		return fmt.Errorf("apivectors: prefix 8 at bits=1 matches %d of %d records, want all",
			len(matched), len(g.initial))
	}
	missed, err := matchingRecords(g.initial, "0", 1)
	if err != nil {
		return err
	}
	if len(missed) != 0 {
		return fmt.Errorf("apivectors: prefix 0 at bits=1 matches %d records, want none", len(missed))
	}

	capNote := fmt.Sprintf(
		"This instance holds %d records, so §5.3's cap is max(0, floor(log2(%d / k_min))) = %d with the "+
			"normative k_min of %d. bits = 0 and bits = 1 are accepted and anything wider is 400.",
		len(g.initial), len(g.initial), query.Cap(int64(len(g.initial))), query.KMin)

	verbatimNote := "The response contains the adversarially formatted record, so it is byte-exact only " +
		"if the directory reproduced the stored bytes rather than re-serialising them (§5.2)."

	g.add(fixtureCase{
		id:   "record-get-200-bits-zero-empty-prefix",
		spec: "§5.3",
		row:  "A directory MUST accept both ?prefix=&bits=0 and ?bits=0 with prefix absent",
		note: []string{
			"bits = 0 with prefix supplied empty. This is the query every conforming client sends to an " +
				"instance too small to provide an anonymity set, and it returns the whole table.",
			verbatimNote,
			"The order of records is not significant and clients MUST NOT depend on it. The expected body " +
				"is written in the RECOMMENDED order — ascending lookup_id — because a byte comparison " +
				"needs one; compare the elements as a multiset if your instance orders differently.",
		},
		first:   condAccepted,
		request: getRecord("prefix=&bits=0"),
		expect:  expectRecords(all),
		rows:    []string{"5.3/bits-zero", "5.3/match", "5.3/content-type", "5.2/verbatim"},
	})

	g.add(fixtureCase{
		id:   "record-get-200-bits-zero-prefix-absent",
		spec: "§5.3",
		row:  "A directory MUST accept both ?prefix=&bits=0 and ?bits=0 with prefix absent",
		note: []string{
			"The other spelling. An absent prefix and an empty prefix are the same query at bits = 0, and " +
				"a directory must accept both — a distinction url.Values-style APIs cannot express in the " +
				"value alone, which is why it is stated.",
		},
		first:   condAccepted,
		request: getRecord("bits=0"),
		expect:  expectRecords(all),
		rows:    []string{"5.3/bits-zero", "5.3/match", "5.2/verbatim"},
	})

	g.add(fixtureCase{
		id:   "record-get-200-prefix-matches",
		spec: "§5.3",
		row:  "Returns every non-expired envelope whose lookup_id begins with the given bit prefix",
		note: []string{
			"prefix=8 at bits=1 selects identifiers whose first bit is 1, which is every record in this " +
				"instance. The padding bits of the character are zero here, so this is the plain case.",
			capNote,
			verbatimNote,
		},
		first:   condAccepted,
		request: getRecord("prefix=8&bits=1"),
		expect:  expectRecords(all),
		rows:    []string{"5.3/match", "5.2/verbatim"},
	})

	g.add(fixtureCase{
		id:   "record-get-200-padding-bits-masked",
		spec: "§5.3",
		row:  "Where bits is not a multiple of four a directory MUST mask and ignore the trailing bits",
		note: []string{
			"prefix=f at bits=1 carries one significant bit — 1 — and three padding bits that are all set. " +
				"Masked, it is the same query as prefix=8, and it returns the same records.",
			"A directory that rejected non-zero padding bits answers 400 here, and a directory that " +
				"compared the character rather than the masked bits answers with an empty array. Both are " +
				"wrong on the ordinary path rather than on an edge case: at 100,000 records the RECOMMENDED " +
				"bits is 10, which occupies three hex characters and leaves two bits unused.",
		},
		first:   condAccepted,
		request: getRecord("prefix=f&bits=1"),
		expect:  expectRecords(all),
		rows:    []string{"5.3/mask-padding-bits", "5.3/match", "5.2/verbatim"},
	})

	g.add(fixtureCase{
		id:   "record-get-200-uppercase-prefix",
		spec: "§5.3",
		row:  "prefix is hex, case-insensitive",
		note: []string{
			"The same query as the one before it, spelled in upper case. Directories MUST accept both a3f " +
				"and A3F.",
		},
		first:   condAccepted,
		request: getRecord("prefix=F&bits=1"),
		expect:  expectRecords(all),
		rows:    []string{"5.3/uppercase", "5.3/mask-padding-bits", "5.2/verbatim"},
	})

	g.add(fixtureCase{
		id:   "record-get-200-empty-result",
		spec: "§5.3",
		row:  "A directory with no matching records returns 200 with an empty records array, never 404",
		note: []string{
			"prefix=0 at bits=1 selects identifiers whose first bit is 0, and this instance holds none.",
			"200 with an empty array, never 404. A 404 would tell a client the directory has nothing to " +
				"say about anything, when what it has is nothing in this bucket.",
		},
		first:   condAccepted,
		request: getRecord("prefix=0&bits=1"),
		expect:  expectRecords(empty),
		rows:    []string{"5.3/empty-result"},
	})

	g.add(fixtureCase{
		id:   "record-get-200-empty-result-padding-bits-masked",
		spec: "§5.3",
		row:  "Where bits is not a multiple of four a directory MUST mask and ignore the trailing bits",
		note: []string{
			"prefix=7 at bits=1 masks to the same query as prefix=0: one significant bit of 0, three " +
				"padding bits that are set. The empty array is the correct answer, and a 400 is not.",
		},
		first:   condAccepted,
		request: getRecord("prefix=7&bits=1"),
		expect:  expectRecords(empty),
		rows:    []string{"5.3/mask-padding-bits", "5.3/empty-result"},
	})

	rejections := []struct {
		id    string
		row   string
		query string
		note  []string
		rows  []string
	}{
		{
			"record-get-400-over-precise",
			"Directories MUST enforce a maximum bits and reject over-precise queries with 400",
			"prefix=80&bits=2",
			[]string{
				"bits = 2 exceeds this instance's cap of 1. " + capNote,
				"A client asking for a 32-bit prefix has defeated the entire privacy design; the " +
					"server-side cap is what makes the anonymity set a protocol guarantee rather than a " +
					"client courtesy.",
				"The cap is computed against the true record count, not the figure §5.1 permits an " +
					"instance to understate — which is what makes §5.1's promise unconditional that a " +
					"client following the advertised count can never be rejected here.",
			},
			[]string{"5.3/over-precise"},
		},
		{
			"record-get-400-bits-absent",
			"bits is REQUIRED",
			"prefix=8",
			[]string{
				"bits is REQUIRED and a directory MUST NOT infer it from the length of prefix. Inference " +
					"is the tempting shortcut and the one that breaks interoperability silently: it makes " +
					"a3f mean 12 bits everywhere, so a client that meant 10 gets a narrower bucket and a " +
					"smaller anonymity set than it asked for, with nothing reporting an error.",
			},
			[]string{"5.3/bits-required"},
		},
		{
			"record-get-400-bits-leading-zero",
			"bits is one or more ASCII digits: no sign, no leading zeros",
			"prefix=8&bits=01",
			[]string{
				"A leading zero is two spellings of one value, which is the defect §4.4's canonical-encoding " +
					"rule closes for base64url. It is rejected here rather than normalised.",
			},
			[]string{"5.3/bits-lexical"},
		},
		{
			"record-get-400-bits-not-a-number",
			"bits is one or more ASCII digits",
			"prefix=8&bits=one",
			[]string{"No other notation."},
			[]string{"5.3/bits-lexical"},
		},
		{
			"record-get-400-bits-signed",
			"bits is one or more ASCII digits: no sign",
			"prefix=8&bits=-1",
			[]string{
				"No sign. A directory that parsed this as a signed integer and then sized a buffer from " +
					"it has a worse problem than a 400.",
			},
			[]string{"5.3/bits-lexical"},
		},
		{
			"record-get-400-bits-above-256",
			"bits MUST NOT exceed 256, the width of a lookup_id",
			"prefix=" + strings.Repeat("8", 65) + "&bits=257",
			[]string{
				"257 bits with a correctly sized prefix of 65 hex characters, so the only thing wrong with " +
					"the query is its width.",
				"On this instance the cap of 1 rejects it first, and both bind to 400, so the code cannot " +
					"say which rule applied. The 256 bound is stated in §5.3 so that an implementation " +
					"sizing a buffer from the parameter has something to size it against.",
			},
			[]string{"5.3/bits-max-256"},
		},
		{
			"record-get-400-prefix-not-hex",
			"A directory MUST reject any character outside [0-9a-fA-F] with 400",
			"prefix=g&bits=1",
			[]string{
				"'g' is outside the hex alphabet. Every character is validated, including one whose bits " +
					"the mask would discard entirely.",
			},
			[]string{"5.3/prefix-hex"},
		},
		{
			"record-get-400-prefix-too-long",
			"prefix MUST contain exactly ceil(bits / 4) hex characters",
			"prefix=88&bits=1",
			[]string{
				"Two characters where one is required. Too many carries bits the client did not declare.",
			},
			[]string{"5.3/prefix-length"},
		},
		{
			"record-get-400-prefix-empty-with-bits",
			"prefix MUST contain exactly ceil(bits / 4) hex characters",
			"prefix=&bits=1",
			[]string{
				"An empty prefix is only meaningful at bits = 0.",
			},
			[]string{"5.3/prefix-length"},
		},
		{
			"record-get-400-prefix-absent-with-bits",
			"prefix MUST contain exactly ceil(bits / 4) hex characters",
			"bits=1",
			[]string{
				"An absent prefix with bits above zero. The pair of this and the bits = 0 fixtures is what " +
					"pins the one place absence and emptiness differ.",
			},
			[]string{"5.3/prefix-length"},
		},
		{
			"record-get-400-repeated-prefix",
			"A query supplying prefix or bits more than once MUST be rejected rather than resolved",
			"prefix=8&prefix=8&bits=1",
			[]string{
				"Both occurrences agree, and it is still rejected. HTTP stacks disagree about which " +
					"occurrence wins, so resolving one means two directories reading the same query " +
					"differently — the failure mode of duplicate JSON members in §5.2. Failing closed on " +
					"the ambiguity costs nothing, because no honest client emits one.",
			},
			[]string{"5.3/repeated-parameter"},
		},
		{
			"record-get-400-repeated-bits",
			"A query supplying prefix or bits more than once MUST be rejected rather than resolved",
			"prefix=8&bits=1&bits=0",
			[]string{
				"Here the two occurrences disagree, which is the case where resolving it silently changes " +
					"the anonymity set the client asked for.",
			},
			[]string{"5.3/repeated-parameter"},
		},
	}

	for _, r := range rejections {
		g.add(fixtureCase{
			id:      r.id,
			spec:    "§5.3",
			row:     r.row,
			note:    r.note,
			first:   "", // §5.3 binds every rejection to 400 and gives no order.
			request: getRecord(r.query),
			expect:  expectStatus(400),
			rows:    r.rows,
		})
	}

	g.add(fixtureCase{
		id:       "record-get-429-rate-limited",
		spec:     "§5.3",
		row:      "Rate limited",
		instance: InstanceLimitsOfOne,
		note: []string{
			"§6.2 gives GET /v1/record its own allowance, counted independently of publishes and of " +
				"signal channel access.",
			"§5.3 has no status table of its own and states no code for a rate-limited lookup. 429 is " +
				"what §5.2 and §5.4 bind rate limiting to, and it is the only code whose remedy — back off " +
				"or move on — is the right one here.",
			"This instance holds no records, so the prior request returns an empty array; the allowance " +
				"is spent either way.",
		},
		conditions: []string{condRateLimited},
		first:      condRateLimited,
		prior: []PriorRequest{{
			Note:         "Spends this source's single GET /v1/record allowance.",
			Repeat:       1,
			ExpectStatus: 200,
			Request:      getRecord("bits=0"),
		}},
		request: getRecord("bits=0"),
		expect:  expectStatus(429),
		rows:    []string{"5.3/rate-limited"},
	})

	return nil
}

// buildSignalFixtures covers DIRECTORY-SPEC.md §5.4.
func (g *generator) buildSignalFixtures() {
	blob := Body{Encoding: BodyBase64URL, Value: b64.Encode([]byte{0x00, 0x10, 0x20, 0xff})}

	g.add(fixtureCase{
		id:   "signal-post-204-stored",
		spec: "§5.4",
		row:  "POST — Stored",
		note: []string{
			"A channel holding nothing accepts the write. The directory treats the body as bytes and MUST " +
				"NOT attempt to parse, validate or interpret it.",
		},
		conditions: []string{},
		first:      condStored,
		mutates:    true,
		request:    postSignal(g.freeChannel, blob),
		expect:     expectStatus(204),
		rows:       []string{"5.4/post-stored"},
	})

	g.add(fixtureCase{
		id:   "signal-post-204-expired-blob-replaced",
		spec: "§5.4",
		row:  "POST — Stored",
		note: []string{
			"This channel holds a blob that expired before now. §5.4 rejects a second write only where " +
				"the channel already holds an *unexpired* blob, so this is a first write.",
			"Expiry is a property of the blob and the clock, not of sweep scheduling — the same rule §5.2 " +
				"states for records.",
		},
		first:   condStored,
		mutates: true,
		request: postSignal(g.expiredChannel, blob),
		expect:  expectStatus(204),
		rows:    []string{"5.4/post-stored"},
	})

	g.add(fixtureCase{
		id:   "signal-post-204-at-size-limit",
		spec: "§5.4",
		row:  "POST — Stored",
		note: []string{
			fmt.Sprintf("A body of exactly the §4.3 signal channel payload limit, %d bytes. The body is "+
				"the single byte 0x61 repeated; see encoding.body_encodings.", signal.MaxBlobBytes),
		},
		first:   condStored,
		mutates: true,
		request: postSignal(g.sizeChannel, Body{Encoding: BodyRepeatedByte, Byte: 0x61, Length: signal.MaxBlobBytes}),
		expect:  expectStatus(204),
		rows:    []string{"5.4/post-stored"},
	})

	g.add(fixtureCase{
		id:   "signal-post-413-too-large",
		spec: "§5.4",
		row:  "POST — body exceeds the §4.3 signal channel payload limit",
		note: []string{
			fmt.Sprintf("One byte over the limit: %d bytes.", signal.MaxBlobBytes+1),
		},
		conditions: []string{condSignalLarge},
		first:      condSignalLarge,
		request:    postSignal(g.freeChannel, Body{Encoding: BodyRepeatedByte, Byte: 0x61, Length: signal.MaxBlobBytes + 1}),
		expect:     expectStatus(413),
		rows:       []string{"5.4/post-too-large"},
	})

	g.add(fixtureCase{
		id:   "signal-post-409-first-write-wins",
		spec: "§5.4",
		row:  "POST — channel already holds an unexpired blob",
		note: []string{
			"The channel holds an unexpired blob, and the stored blob is left untouched.",
			"This is a security property rather than an error case. Under overwrite semantics anyone who " +
				"guessed or observed a channel identifier could replace a legitimate blob with their own, " +
				"turning the rendezvous into an injection point; failing closed reduces that to a denial " +
				"of service the participants detect immediately.",
		},
		conditions: []string{condConflict},
		first:      condConflict,
		request:    postSignal(g.heldChannel, blob),
		expect:     expectStatus(409),
		rows:       []string{"5.4/post-conflict"},
	})

	badChannels := []struct {
		id      string
		channel string
		note    []string
	}{
		{
			"signal-post-400-channel-too-short",
			"short",
			[]string{"A channel_id is 32 bytes, base64url: exactly 43 unpadded characters."},
		},
		{
			"signal-post-400-channel-padded",
			g.paddedChannel(),
			[]string{
				"The padded spelling of the same 32 bytes. §4.4 forbids emitting padding and requires " +
					"padded input to be rejected rather than stripped.",
			},
		},
		{
			"signal-post-400-channel-non-canonical",
			g.nonCanonicalChannel(),
			[]string{
				"43 characters decoding to the right 32 bytes, but with non-zero unused bits in the final " +
					"character. §5.4 identifies a channel by its decoded bytes, not by the text that " +
					"spelled them: an implementation keying on the text would treat two spellings as two " +
					"channels and accept a second write where a conforming directory returns 409. The " +
					"canonical-encoding rule of §4.4 closes the same gap from the other side, and both apply.",
			},
		},
	}

	for _, c := range badChannels {
		g.add(fixtureCase{
			id:         c.id,
			spec:       "§5.4",
			row:        "POST — channel_id is not exactly 32 bytes of unpadded base64url",
			note:       c.note,
			conditions: []string{condBadChannel},
			first:      condBadChannel,
			request:    postSignal(c.channel, blob),
			expect:     expectStatus(400),
			rows:       []string{"5.4/post-bad-channel"},
		})
	}

	g.add(fixtureCase{
		id:   "signal-get-200-delivered",
		spec: "§5.4",
		row:  "GET — blob present",
		note: []string{
			"The blob is returned exactly as posted, including its NUL bytes, its 0xff and the three " +
				"characters a JSON encoder would rewrite. The directory MUST NOT interpret the body.",
			"Content-Type is application/octet-stream: a directory forbidden to interpret the body must " +
				"not claim a type for it.",
			"Delivery is destructive — this fixture mutates state, and a second GET on this channel " +
				"would long-poll.",
		},
		first:   condDelivered,
		mutates: true,
		request: getSignal(g.heldChannel),
		expect:  expectBlob(g.heldBlob),
		rows:    []string{"5.4/get-delivered", "5.4/octet-stream"},
	})

	g.add(fixtureCase{
		id:   "signal-get-204-empty",
		spec: "§5.4",
		row:  "GET — long-poll window elapsed with no blob",
		note: []string{
			"204, deliberately not 404. A client's correct response to 204 is to poll again; to 404, to " +
				"try a different directory. Conflating them means a client either hammers an instance that " +
				"will never answer or abandons one that would have, and PAIRING-SPEC.md §6.3 has both " +
				"devices polling as its normal path.",
			"The response arrives after the instance's long-poll window elapses, which §5.4 caps at 30 " +
				"seconds. A conformance harness MAY shorten the window: this fixture asserts the status, " +
				"not the duration.",
		},
		first:   condEmpty,
		request: getSignal(g.freeChannel),
		expect:  expectStatus(204),
		rows:    []string{"5.4/get-empty"},
	})

	g.add(fixtureCase{
		id:   "signal-get-400-bad-channel",
		spec: "§5.4",
		row:  "GET — channel_id is not exactly 32 bytes of unpadded base64url",
		note: []string{
			"42 characters: one short of the 43 an unpadded 32-byte value occupies. The identifier is " +
				"checked before the channel is looked up, so no channel is created by a malformed request.",
		},
		conditions: []string{condBadChannel},
		first:      condBadChannel,
		request:    getSignal(g.freeChannel[:len(g.freeChannel)-1]),
		expect:     expectStatus(400),
		rows:       []string{"5.4/get-bad-channel"},
	})

	g.add(fixtureCase{
		id:       "signal-post-429-rate-limited",
		spec:     "§5.4",
		row:      "either — rate limited",
		instance: InstanceLimitsOfOne,
		note: []string{
			"POST and GET on a signal channel share one allowance (§6.4), so the prior request here is a " +
				"GET and it is the POST that is refused.",
			"The prior request is a GET with a malformed channel_id, which spends the allowance without " +
				"long-polling and without creating a channel.",
		},
		conditions: []string{condRateLimited},
		first:      condRateLimited,
		prior: []PriorRequest{{
			Note:         "Spends this source's single signal allowance.",
			Repeat:       1,
			ExpectStatus: 400,
			Request:      getSignal("short"),
		}},
		request: postSignal(g.freeChannel, blob),
		expect:  expectStatus(429),
		rows:    []string{"5.4/rate-limited"},
	})

	g.add(fixtureCase{
		id:       "signal-get-429-rate-limited",
		spec:     "§5.4",
		row:      "either — rate limited",
		instance: InstanceLimitsOfOne,
		note: []string{
			"The same allowance from the other side: a POST spends it and the GET is refused.",
		},
		conditions: []string{condRateLimited},
		first:      condRateLimited,
		prior: []PriorRequest{{
			Note:         "Spends this source's single signal allowance.",
			Repeat:       1,
			ExpectStatus: 400,
			Request:      postSignal("short", blob),
		}},
		request: getSignal(g.freeChannel),
		expect:  expectStatus(429),
		rows:    []string{"5.4/rate-limited"},
	})

	g.add(fixtureCase{
		id:       "signal-post-429-draining",
		spec:     "§5.4",
		row:      "either — instance at capacity, or shutting down",
		instance: InstanceDraining,
		note: []string{
			"An instance that is full or draining answers 429, not 204 and not 404. 204 would tell the " +
				"client to poll again immediately, hot-looping against an instance that has just declined " +
				"it; 404 would tell the client this directory does not broker signal channels at all — " +
				"which is wrong, and sticky, because a client that believes it will stop asking.",
			"A harness with no way to drive its instance into this state cannot run this fixture. That is " +
				"a property of the harness rather than of the directory, and the row is normative either way.",
		},
		conditions: []string{condRateLimited},
		first:      condRateLimited,
		request:    postSignal(g.freeChannel, blob),
		expect:     expectStatus(429),
		rows:       []string{"5.4/draining"},
	})

	g.add(fixtureCase{
		id:       "signal-get-429-draining",
		spec:     "§5.4",
		row:      "either — instance at capacity, or shutting down",
		instance: InstanceDraining,
		note: []string{
			"The same on the read side, and it returns promptly rather than holding the poll open: a " +
				"graceful shutdown must not wait 30 seconds on an idle poller.",
		},
		conditions: []string{condRateLimited},
		first:      condRateLimited,
		request:    getSignal(g.heldChannel),
		expect:     expectStatus(429),
		rows:       []string{"5.4/draining"},
	})

	g.add(fixtureCase{
		id:       "signal-post-404-disabled",
		spec:     "§5.4",
		row:      "either — instance advertises \"signal\": false",
		instance: InstanceSignalDisabled,
		note: []string{
			"404 is the one outcome in the §5.4 table that means \"this directory does not broker signal " +
				"channels\", and it is reserved for the instance that advertises so in GET /v1/meta.",
		},
		conditions: []string{condDisabled},
		first:      condDisabled,
		request:    postSignal(g.freeChannel, blob),
		expect:     expectStatus(404),
		rows:       []string{"5.4/disabled"},
	})

	g.add(fixtureCase{
		id:       "signal-get-404-disabled",
		spec:     "§5.4",
		row:      "either — instance advertises \"signal\": false",
		instance: InstanceSignalDisabled,
		note: []string{
			"The same on the read side. Pairing the advertised capability with the behaviour of the route " +
				"matters: a client that believes a directory brokers signal channels and finds 404 will " +
				"stop trying it altogether.",
		},
		conditions: []string{condDisabled},
		first:      condDisabled,
		request:    getSignal(g.heldChannel),
		expect:     expectStatus(404),
		rows:       []string{"5.4/disabled"},
	})
}

// paddedChannel and nonCanonicalChannel are the two malformed spellings of a
// valid channel identifier. Both are derived from a real one so that the only
// thing wrong with them is the spelling.
func (g *generator) paddedChannel() string {
	out, err := padded(g.freeChannel)
	if err != nil {
		// Unreachable: freeChannel is produced by this package's own encoder.
		return g.freeChannel + "="
	}
	return out
}

func (g *generator) nonCanonicalChannel() string {
	out, err := nonCanonical(g.freeChannel)
	if err != nil {
		// Reached only if the identifier's final character already carries
		// non-zero unused bits, which cannot happen for an encoder that
		// emits canonical output.
		return g.freeChannel
	}
	return out
}

// buildCORSFixtures covers the preflights of DIRECTORY-SPEC.md §5.5. The
// wildcard origin and the absence of Access-Control-Allow-Credentials are
// asserted on every fixture in the file, through response_invariants.
func (g *generator) buildCORSFixtures() {
	preflights := []struct {
		id      string
		path    string
		methods []string
		note    string
	}{
		{
			"cors-options-record-preflight",
			"/v1/record",
			[]string{"GET", "PUT", "OPTIONS"},
			"§5.2 RECOMMENDS publishers send the vendor media type, which is precisely what forces a " +
				"browser to preflight every publish.",
		},
		{
			"cors-options-signal-preflight",
			"/v1/signal/" + g.freeChannel,
			[]string{"GET", "POST", "OPTIONS"},
			"The preflight is per route, and §5.5 names this one explicitly.",
		},
	}

	for _, p := range preflights {
		e := expectStatus(204)
		e.Headers = map[string]string{"Access-Control-Allow-Headers": "Content-Type"}
		e.HeaderTokens = map[string][]string{"Access-Control-Allow-Methods": p.methods}

		g.add(fixtureCase{
			id:   p.id,
			spec: "§5.5",
			row:  "OPTIONS preflight",
			note: []string{
				p.note,
				"OPTIONS is HTTP transport mechanics for the four operations of §5. It is not a fifth " +
					"operation and does not bear on the constraint in §10.",
				"Access-Control-Allow-Methods is compared as a token set: the header must list every " +
					"method given, and order and spacing are not significant.",
			},
			first: condAccepted,
			request: Request{
				Method: "OPTIONS",
				Path:   p.path,
				Query:  "",
				Headers: map[string]string{
					"Origin":                         "https://client.example.net",
					"Access-Control-Request-Method":  "PUT",
					"Access-Control-Request-Headers": "Content-Type",
				},
				Body: Body{Encoding: BodyEmpty},
			},
			expect: e,
			rows:   []string{"5.5/preflight", "5.5/allow-origin", "5.5/no-credentials"},
		})
	}
}

// checkAdversarialRecord fails generation if the record that catches
// re-serialisation has lost any of the four properties that make it catch it.
//
// It is checked here as well as in the tests because a generated artefact that
// silently stopped testing the thing it exists to test is worse than one that
// fails to build.
func checkAdversarialRecord(body string) error {
	checks := []struct {
		name string
		ok   bool
	}{
		{"non-minimal whitespace", strings.Contains(body, "\n") && strings.Contains(body, "  ")},
		{"a '<' character", strings.Contains(body, "<")},
		{"a '>' character", strings.Contains(body, ">")},
		{"an '&' character", strings.Contains(body, "&")},
		{"an unknown nested member", strings.Contains(body, "\"_extension\"") && strings.Contains(body, "\"nested\"")},
		{"a member order differing from §4.1", strings.Index(body, "\"sig\"") < strings.Index(body, "\"v\"")},
	}
	for _, c := range checks {
		if !c.ok {
			return fmt.Errorf("apivectors: the adversarially formatted record no longer carries %s", c.name)
		}
	}
	if len(body) > MaxRecordBytes {
		return fmt.Errorf("apivectors: the adversarially formatted record is %d bytes, over max_record_bytes", len(body))
	}
	return nil
}

// checkDistinctIdentifiers fails generation if two pre-loaded records share a
// lookup_id, which would silently collapse the initial state.
func checkDistinctIdentifiers(recs []storedRecord) error {
	seen := make(map[string]struct{}, len(recs))
	for _, r := range recs {
		key := string(r.publisher.lookupID)
		if _, dup := seen[key]; dup {
			return fmt.Errorf("apivectors: two pre-loaded records share a lookup_id")
		}
		seen[key] = struct{}{}
		if r.publisher.lookupID[0]&0x80 == 0 {
			return fmt.Errorf("apivectors: a pre-loaded record's identifier does not begin with a 1 bit")
		}
		if len(r.publisher.lookupID) != sha256.Size {
			return fmt.Errorf("apivectors: a pre-loaded record's identifier is not 32 bytes")
		}
	}
	return nil
}
