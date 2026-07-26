// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package apivectors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/trigstation/trigstationd/internal/accept"
	"github.com/trigstation/trigstationd/internal/api"
	"github.com/trigstation/trigstationd/internal/clientaddr"
	"github.com/trigstation/trigstationd/internal/ratelimit"
	"github.com/trigstation/trigstationd/internal/reject"
	sigstore "github.com/trigstation/trigstationd/internal/signal"
	"github.com/trigstation/trigstationd/internal/store"
)

// committedPath resolves testdata/api-vectors.json from this package's
// directory.
func committedPath() string {
	return filepath.Join("..", "..", filepath.FromSlash(Path))
}

func load(t *testing.T) *File {
	t.Helper()
	raw, err := os.ReadFile(committedPath())
	if err != nil {
		t.Fatalf("read api vectors: %v (run: go run ./cmd/gen-api-vectors -o %s)", err, Path)
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse api vectors: %v", err)
	}
	return &f
}

// TestCommittedAPIVectorsMatchGenerator keeps the committed file honest. If a
// fixture changes, this fails rather than the file silently describing
// requests nobody makes.
//
// It also proves generation is deterministic, which is what lets an
// independent implementer regenerate and diff rather than trust.
func TestCommittedAPIVectorsMatchGenerator(t *testing.T) {
	committed, err := os.ReadFile(committedPath())
	if err != nil {
		t.Fatalf("read api vectors: %v", err)
	}

	f, err := Generate(context.Background())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	regenerated, err := Marshal(f)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if !bytes.Equal(committed, regenerated) {
		t.Errorf("%s is out of date with the code.\nRegenerate with: go run ./cmd/gen-api-vectors -o %s",
			Path, Path)
	}
}

// pollWindow is how long the harness holds a long-poll open.
//
// The file declares §5.4's 30-second ceiling as a maximum rather than a
// setting, and says a conformance harness may shorten it because the
// GET-with-no-blob fixture asserts the status and not the duration. This is
// that shortening: a suite that spent thirty seconds on one fixture would stop
// being run, which is a worse outcome for the property than a short window is.
const pollWindow = 50 * time.Millisecond

// clock is the fixed time source every fixture is evaluated against.
//
// It is settable only because the initial state includes a signal channel
// loaded in the past, so that its blob has expired by `now`. Every fixture
// request itself is issued with the clock reading exactly File.Now.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

type harness struct {
	t      *testing.T
	api    *api.Server
	store  *store.Store
	signal *sigstore.Store
	clock  *clock
}

// build constructs an instance exactly as the file describes it, loads the
// declared initial state, and puts it into whatever state the instance names.
func build(t *testing.T, f *File, inst Instance) *harness {
	t.Helper()

	recordStore, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("opening the record store: %v", err)
	}
	t.Cleanup(func() { recordStore.Close() })

	var signalStore *sigstore.Store
	if inst.Signal {
		signalStore = sigstore.New(sigstore.Options{
			TTL:          time.Duration(inst.SignalTTL) * time.Second,
			PollWindow:   pollWindow,
			MaxBlobBytes: inst.MaxSignalBlobBytes,
		})
	}

	clk := &clock{t: time.Unix(f.Now, 0).UTC()}

	handler, err := api.New(api.Config{
		Store:   recordStore,
		Signal:  signalStore,
		Limiter: ratelimit.New(limiterOptions(inst.RateLimits)),
		// No trusted proxies: the harness is the immediate peer, so every
		// request in a fixture run counts against one key. That is what makes
		// the prior_requests mechanism work at all.
		ClientAddr: clientaddr.New(nil),
		Limits: accept.Limits{
			MaxRecordBytes: inst.MaxRecordBytes,
			MaxTTL:         inst.MaxTTL,
			PoWBits:        inst.PoWBits,
			SkewGrace:      inst.SkewGrace,
		},
		SourceURL: inst.SourceURL,
		Now:       clk.Now,
	})
	if err != nil {
		t.Fatalf("building the handler: %v", err)
	}

	h := &harness{t: t, api: handler, store: recordStore, signal: signalStore, clock: clk}

	if inst.LoadInitialRecords {
		h.loadRecords(f)
	}
	if inst.LoadInitialChannels {
		h.loadChannels(f)
	}
	if inst.Draining {
		handler.Drain()
	}

	return h
}

func limiterOptions(l RateLimits) ratelimit.Options {
	return ratelimit.Options{
		PutRecord: l.PutRecord,
		GetRecord: l.GetRecord,
		Signal:    l.Signal,
		Window:    time.Duration(l.WindowSeconds) * time.Second,
	}
}

// loadRecords issues the PUT the file describes for each pre-loaded record.
//
// Loading through the API rather than through the store is deliberate: it
// proves the declared initial state is reachable by any harness with an HTTP
// client, and it proves each pre-loaded envelope is itself a legal publish.
func (h *harness) loadRecords(f *File) {
	h.t.Helper()

	for _, r := range f.InitialState.Records {
		h.clock.set(time.Unix(r.LoadedAt, 0).UTC())

		body, err := r.Envelope.Bytes()
		if err != nil {
			h.t.Fatalf("initial record %s: %v", r.ID, err)
		}
		resp, _ := h.do(Request{
			Method:  "PUT",
			Path:    "/v1/record",
			Headers: map[string]string{"Content-Type": vendorMediaType},
			Body:    Body{Encoding: BodyUTF8, Value: string(body)},
		})
		if resp.StatusCode != r.LoadExpectStatus {
			h.t.Fatalf("loading initial record %s returned %d, want %d",
				r.ID, resp.StatusCode, r.LoadExpectStatus)
		}
	}

	h.clock.set(time.Unix(f.Now, 0).UTC())
}

// loadChannels posts each pre-loaded blob with the clock reading its
// posted_at, then returns the clock to now. One channel is loaded far enough
// in the past that its blob has expired, which is the difference between §5.4's
// "holds an unexpired blob" and "holds a blob".
func (h *harness) loadChannels(f *File) {
	h.t.Helper()

	for _, c := range f.InitialState.SignalChannels {
		h.clock.set(time.Unix(c.PostedAt, 0).UTC())

		blob, err := c.Blob.Bytes()
		if err != nil {
			h.t.Fatalf("initial channel %s: %v", c.ID, err)
		}
		resp, _ := h.do(Request{
			Method:  "POST",
			Path:    "/v1/signal/" + c.ChannelID,
			Headers: map[string]string{},
			Body:    Body{Encoding: BodyBase64URL, Value: encodeLookupID(blob)},
		})
		if resp.StatusCode != c.LoadExpectStatus {
			h.t.Fatalf("loading initial channel %s returned %d, want %d",
				c.ID, resp.StatusCode, c.LoadExpectStatus)
		}
	}

	h.clock.set(time.Unix(f.Now, 0).UTC())
}

// do issues one request through the real handler, entry point and all: the
// CORS wrapper, the router and the handler underneath it.
func (h *harness) do(r Request) (*http.Response, []byte) {
	h.t.Helper()

	body, err := r.Body.Bytes()
	if err != nil {
		h.t.Fatalf("materialising a request body: %v", err)
	}

	target := r.Path
	if r.Query != "" {
		target += "?" + r.Query
	}

	var reader io.Reader = http.NoBody
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req := httptest.NewRequest(r.Method, target, reader)
	for name, value := range r.Headers {
		req.Header.Set(name, value)
	}

	rec := httptest.NewRecorder()
	h.api.ServeHTTP(rec, req)

	resp := rec.Result()
	read, err := io.ReadAll(resp.Body)
	if err != nil {
		h.t.Fatalf("reading a response body: %v", err)
	}
	resp.Body.Close()
	return resp, read
}

// TestFixturesDriveTheHandler is the self-check: every fixture in the
// committed file, driven through the real handler, against a fresh instance in
// the declared initial state.
//
// It is the test that makes the file a deliverable rather than a description.
// A fixture whose expectation no longer matches the implementation fails here,
// so the file cannot drift into being wrong while remaining committed.
func TestFixturesDriveTheHandler(t *testing.T) {
	f := load(t)

	byName := map[string]Instance{}
	for _, inst := range f.Instances {
		byName[inst.Name] = inst
	}

	if len(f.Fixtures) == 0 {
		t.Fatal("the file carries no fixtures: this check would pass vacuously")
	}

	for _, fixture := range f.Fixtures {
		t.Run(fixture.ID, func(t *testing.T) {
			inst, ok := byName[fixture.Instance]
			if !ok {
				t.Fatalf("fixture names instance %q, which the file does not declare", fixture.Instance)
			}

			h := build(t, f, inst)

			for i, prior := range fixture.PriorRequests {
				repeat := prior.Repeat
				if repeat < 1 {
					repeat = 1
				}
				for n := 0; n < repeat; n++ {
					resp, _ := h.do(prior.Request)
					if resp.StatusCode != prior.ExpectStatus {
						t.Fatalf("prior request %d (attempt %d) returned %d, want %d",
							i, n+1, resp.StatusCode, prior.ExpectStatus)
					}
				}
			}

			resp, read := h.do(fixture.Request)

			if resp.StatusCode != fixture.Expect.Status {
				t.Errorf("status = %d, want %d\nbody: %s", resp.StatusCode, fixture.Expect.Status, truncate(read))
			}

			want, err := fixture.Expect.Body.Bytes()
			if err != nil {
				t.Fatalf("materialising the expected body: %v", err)
			}
			if err := compareBody(fixture.Expect.Comparison, want, read); err != nil {
				t.Errorf("body: %v", err)
			}

			checkHeaders(t, fixture.Expect, f.ResponseInvariants, resp.Header)
		})
	}
}

// compareBody applies the comparison the fixture declares.
func compareBody(mode string, want, got []byte) error {
	switch mode {
	case CompareEmpty:
		if len(got) != 0 {
			return fmt.Errorf("want no body, got %d bytes: %s", len(got), truncate(got))
		}
		return nil

	case CompareExactBytes:
		if !bytes.Equal(want, got) {
			return fmt.Errorf("bytes differ:\n want %s\n got  %s", truncate(want), truncate(got))
		}
		return nil

	case CompareJSONObject:
		var a, b any
		if err := json.Unmarshal(want, &a); err != nil {
			return fmt.Errorf("the expected body is not JSON: %v", err)
		}
		if err := json.Unmarshal(got, &b); err != nil {
			return fmt.Errorf("the response is not JSON: %v", err)
		}
		if !reflect.DeepEqual(a, b) {
			return fmt.Errorf("objects differ:\n want %s\n got  %s", truncate(want), truncate(got))
		}
		return nil

	case CompareRecordsArray:
		return compareRecordsArray(want, got)
	}
	return fmt.Errorf("unknown comparison %q", mode)
}

// compareRecordsArray compares a §5.3 response as a multiset of envelopes,
// each compared as bytes.
//
// Bytes, not parsed values. §5.2 requires the bytes a directory returns to be
// the bytes it received, and D-27 names the trap directly: comparing parsed
// structures is exactly the comparison that passes with a re-serialising
// directory, which is why that fault survives ordinary testing.
//
// A multiset because §5.3 says the order of `records` is not significant and
// clients MUST NOT depend on it. The expected body is written in the
// RECOMMENDED order, and an implementation ordering differently is conforming.
func compareRecordsArray(want, got []byte) error {
	wantEls, err := recordElements(want)
	if err != nil {
		return fmt.Errorf("the expected body: %v", err)
	}
	gotEls, err := recordElements(got)
	if err != nil {
		return fmt.Errorf("the response: %v", err)
	}

	if len(wantEls) != len(gotEls) {
		return fmt.Errorf("want %d records, got %d", len(wantEls), len(gotEls))
	}

	sort.Strings(wantEls)
	sort.Strings(gotEls)
	for i := range wantEls {
		if wantEls[i] != gotEls[i] {
			return fmt.Errorf("record %d differs byte for byte:\n want %s\n got  %s",
				i, truncate([]byte(wantEls[i])), truncate([]byte(gotEls[i])))
		}
	}
	return nil
}

// recordElements returns the raw bytes of each element of a §5.3 response.
//
// json.RawMessage keeps the literal bytes of the value it captured, including
// whatever whitespace was inside it, which is what makes this a byte
// comparison rather than a structural one.
func recordElements(body []byte) ([]string, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &members); err != nil {
		return nil, fmt.Errorf("not a JSON object: %v", err)
	}
	raw, ok := members["records"]
	if !ok {
		return nil, fmt.Errorf("has no records member")
	}
	if len(members) != 1 {
		return nil, fmt.Errorf("has %d members, want only records", len(members))
	}

	var elements []json.RawMessage
	if err := json.Unmarshal(raw, &elements); err != nil {
		return nil, fmt.Errorf("records is not an array: %v", err)
	}

	out := make([]string, 0, len(elements))
	for _, e := range elements {
		out = append(out, string(e))
	}
	return out, nil
}

func checkHeaders(t *testing.T, expect Expect, invariants ResponseInvariants, got http.Header) {
	t.Helper()

	for name, value := range invariants.Headers {
		if have := got.Get(name); have != value {
			t.Errorf("%s = %q, want %q (§5.5, required on every /v1/ response)", name, have, value)
		}
	}
	for _, name := range invariants.HeadersAbsent {
		if _, present := got[http.CanonicalHeaderKey(name)]; present {
			t.Errorf("%s is present: §5.5 forbids it", name)
		}
	}

	for name, value := range expect.Headers {
		if have := got.Get(name); have != value {
			t.Errorf("%s = %q, want %q", name, have, value)
		}
	}
	for name, tokens := range expect.HeaderTokens {
		have := got.Get(name)
		present := map[string]bool{}
		for _, tok := range strings.Split(have, ",") {
			present[strings.ToUpper(strings.TrimSpace(tok))] = true
		}
		for _, want := range tokens {
			if !present[strings.ToUpper(want)] {
				t.Errorf("%s = %q, missing token %q", name, have, want)
			}
		}
	}
	for _, name := range expect.HeadersAbsent {
		if _, present := got[http.CanonicalHeaderKey(name)]; present {
			t.Errorf("%s is present, want absent", name)
		}
	}
}

func truncate(b []byte) string {
	const limit = 400
	if len(b) <= limit {
		return string(b)
	}
	return string(b[:limit]) + fmt.Sprintf("… (%d bytes total)", len(b))
}

// recordConditions and signalConditions map the condition names in the file
// onto the normative tables in internal/reject.
//
// This is what stops the file from being a transcript of the implementation's
// behaviour. Each fixture states its expected status as a literal from the
// specification's table; this check asserts that literal is the code the table
// binds to the condition the fixture says it violates. A fixture with the
// wrong status fails here even if the handler happens to agree with it.
var recordConditions = map[string]reject.RecordReason{
	condAccepted:        reject.RecordAccepted,
	condRateLimited:     reject.RecordRateLimited,
	condTooLarge:        reject.RecordTooLarge,
	condMalformed:       reject.RecordMalformed,
	condBadVersion:      reject.RecordBadVersion,
	condTTLTooLong:      reject.RecordTTLTooLong,
	condLookupMismatch:  reject.RecordLookupMismatch,
	condPoWInsufficient: reject.RecordPoWInsufficient,
	condSigInvalid:      reject.RecordSigInvalid,
	condExpired:         reject.RecordExpired,
	condNotNewer:        reject.RecordNotNewer,
}

var signalConditions = map[string]reject.SignalReason{
	condStored:      reject.SignalStored,
	condDelivered:   reject.SignalDelivered,
	condEmpty:       reject.SignalEmpty,
	condBadChannel:  reject.SignalBadChannel,
	condSignalLarge: reject.SignalTooLarge,
	condConflict:    reject.SignalConflict,
	condRateLimited: reject.SignalRateLimited,
	condDisabled:    reject.SignalDisabled,
}

// TestExpectedStatusesMatchTheNormativeTables checks every §5.2 and §5.4
// fixture's declared status against internal/reject, and checks that the
// conditions each fixture claims to violate are listed in the evaluation order
// §5.2 makes normative.
func TestExpectedStatusesMatchTheNormativeTables(t *testing.T) {
	f := load(t)

	for _, fixture := range f.Fixtures {
		t.Run(fixture.ID, func(t *testing.T) {
			switch fixture.Spec {
			case "§5.2":
				checkRecordFixture(t, fixture)
			case "§5.4":
				reason, ok := signalConditions[fixture.ExpectFirst]
				if !ok {
					t.Fatalf("expect_first %q is not a §5.4 condition", fixture.ExpectFirst)
				}
				if got := reason.HTTPStatus(); got != fixture.Expect.Status {
					t.Errorf("expect_first %q binds to %d, but the fixture expects %d",
						fixture.ExpectFirst, got, fixture.Expect.Status)
				}
			}
		})
	}
}

func checkRecordFixture(t *testing.T, fixture Fixture) {
	t.Helper()

	reason, ok := recordConditions[fixture.ExpectFirst]
	if !ok {
		t.Fatalf("expect_first %q is not a §5.2 condition", fixture.ExpectFirst)
	}
	if got := reason.HTTPStatus(); got != fixture.Expect.Status {
		t.Errorf("expect_first %q binds to %d, but the fixture expects %d",
			fixture.ExpectFirst, got, fixture.Expect.Status)
	}

	if !fixture.OrderIsNormative {
		return
	}

	if len(fixture.Conditions) == 0 {
		if fixture.ExpectFirst != condAccepted {
			t.Errorf("no condition is violated but expect_first is %q", fixture.ExpectFirst)
		}
		return
	}

	if fixture.Conditions[0] != fixture.ExpectFirst {
		t.Errorf("expect_first is %q but the first violated condition is %q",
			fixture.ExpectFirst, fixture.Conditions[0])
	}

	// The listed conditions must be in the table's order, so that a reader can
	// take the list at face value.
	for i := 1; i < len(fixture.Conditions); i++ {
		prev, ok := recordConditions[fixture.Conditions[i-1]]
		if !ok {
			t.Fatalf("%q is not a §5.2 condition", fixture.Conditions[i-1])
		}
		cur, ok := recordConditions[fixture.Conditions[i]]
		if !ok {
			t.Fatalf("%q is not a §5.2 condition", fixture.Conditions[i])
		}
		if cur <= prev {
			t.Errorf("conditions are not listed in the §5.2 evaluation order: %q precedes %q",
				fixture.Conditions[i-1], fixture.Conditions[i])
		}
	}

	// A fixture that claims to discriminate must violate conditions whose
	// codes actually differ, or it is asserting something it cannot see.
	if len(fixture.Conditions) > 1 && fixture.Discriminating {
		first := recordConditions[fixture.Conditions[0]].HTTPStatus()
		distinct := false
		for _, name := range fixture.Conditions[1:] {
			if recordConditions[name].HTTPStatus() != first {
				distinct = true
			}
		}
		if !distinct {
			t.Errorf("every violated condition draws %d, so this fixture cannot discriminate, "+
				"but it does not say so", first)
		}
	}
}

// TestRecordFixturesViolateExactlyWhatTheyClaim checks the isolation claim
// that the single-fault fixtures rest on.
//
// The handler test proves each fixture draws the expected code. It cannot
// prove the code came from the condition the fixture names — a fixture meant to
// violate the proof of work alone would still answer 403 if its signature were
// also broken, and would silently stop testing what it claims to. This runs
// each fixture's body through the §5.2 pipeline and compares the *reason*.
//
// Rate limiting is not evaluated here: it belongs to the transport, because it
// is the only part of the service that touches a client address. The recency
// rule is not either: it needs a storage read, so a fixture that violates it
// must reach the end of this pipeline accepted.
func TestRecordFixturesViolateExactlyWhatTheyClaim(t *testing.T) {
	f := load(t)

	byName := map[string]Instance{}
	for _, inst := range f.Instances {
		byName[inst.Name] = inst
	}

	checked := 0
	for _, fixture := range f.Fixtures {
		if fixture.Spec != "§5.2" || fixture.ExpectFirst == condRateLimited {
			continue
		}
		checked++

		t.Run(fixture.ID, func(t *testing.T) {
			inst := byName[fixture.Instance]
			body, err := fixture.Request.Body.Bytes()
			if err != nil {
				t.Fatalf("materialising the request body: %v", err)
			}

			want := recordConditions[fixture.ExpectFirst]
			if fixture.ExpectFirst == condNotNewer {
				// Everything this pipeline can see must pass, or the fixture is
				// testing an earlier condition while claiming the last one.
				want = reject.RecordAccepted
			}

			got, _ := accept.Check(body, f.Now, accept.Limits{
				MaxRecordBytes: inst.MaxRecordBytes,
				MaxTTL:         inst.MaxTTL,
				PoWBits:        inst.PoWBits,
				SkewGrace:      inst.SkewGrace,
			}, false)

			if got != want {
				t.Errorf("the §5.2 pipeline returns reason %d, but the fixture claims %q (reason %d): "+
					"this fixture is not testing the condition it names",
					got, fixture.ExpectFirst, want)
			}
		})
	}

	if checked == 0 {
		t.Error("no §5.2 fixture was checked")
	}
}

// TestEveryTableRowIsCovered fails if a declared row of a normative table has
// no fixture, if a fixture belongs to no row, or if coverage names a fixture
// that does not exist.
func TestEveryTableRowIsCovered(t *testing.T) {
	f := load(t)

	ids := map[string]bool{}
	for _, fixture := range f.Fixtures {
		ids[fixture.ID] = true
	}

	covered := map[string]bool{}
	for _, row := range f.Coverage {
		if len(row.Fixtures) == 0 {
			t.Errorf("%s %q has no fixture", row.Table, row.Row)
		}
		for _, id := range row.Fixtures {
			if !ids[id] {
				t.Errorf("%s %q names fixture %q, which does not exist", row.Table, row.Row, id)
			}
			covered[id] = true
		}
	}

	for _, fixture := range f.Fixtures {
		if !covered[fixture.ID] {
			t.Errorf("fixture %q belongs to no coverage row", fixture.ID)
		}
	}

	// The eleven rows of §5.2 and the ten of §5.4 are what §9 names. Counting
	// them here means a row quietly dropped from the coverage table fails
	// rather than reducing what is checked.
	counts := map[string]int{}
	for _, row := range f.Coverage {
		counts[row.Table]++
	}
	for table, want := range map[string]int{"§5.2": 14, "§5.4": 11} {
		if counts[table] < want {
			t.Errorf("the coverage table lists %d rows for %s, want at least %d",
				counts[table], table, want)
		}
	}
}

// TestFixtureShapeIsWellFormed checks the properties a harness in another
// language relies on: an encoding it can read, a comparison it can apply, an
// instance that exists, and a body that materialises.
func TestFixtureShapeIsWellFormed(t *testing.T) {
	f := load(t)

	instances := map[string]bool{}
	for _, inst := range f.Instances {
		instances[inst.Name] = true
		if inst.SourceURL == "" {
			t.Errorf("instance %q declares an empty source_url: AGPL §13 compliance is not optional", inst.Name)
		}
	}

	seen := map[string]bool{}
	for _, fixture := range f.Fixtures {
		if seen[fixture.ID] {
			t.Errorf("duplicate fixture id %q", fixture.ID)
		}
		seen[fixture.ID] = true

		if !instances[fixture.Instance] {
			t.Errorf("%s: instance %q is not declared", fixture.ID, fixture.Instance)
		}
		if len(fixture.Note) == 0 {
			t.Errorf("%s: no note. A fixture an implementer cannot read is a fixture they cannot act on",
				fixture.ID)
		}
		if !strings.HasPrefix(fixture.Request.Path, "/v1/") {
			t.Errorf("%s: path %q is not under /v1/", fixture.ID, fixture.Request.Path)
		}
		if _, err := fixture.Request.Body.Bytes(); err != nil {
			t.Errorf("%s: request body does not materialise: %v", fixture.ID, err)
		}
		if _, err := fixture.Expect.Body.Bytes(); err != nil {
			t.Errorf("%s: expected body does not materialise: %v", fixture.ID, err)
		}
		if fixture.Expect.Comparison == CompareEmpty && fixture.Expect.Body.Encoding != BodyEmpty {
			t.Errorf("%s: comparison is %q but the expected body is not declared empty",
				fixture.ID, CompareEmpty)
		}
		if fixture.Expect.Body.Encoding == "" {
			t.Errorf("%s: the expected body has no encoding. An empty body must say so explicitly",
				fixture.ID)
		}
	}
}

// TestMetaFixturesCarryEverySpecifiedMember checks §5.1's "all seven members
// are REQUIRED" against the expected bytes rather than against a decoded
// struct, since a struct with an omitempty tag would decode identically and
// emit differently.
//
// It also checks source_url is populated, which is a licence obligation
// expressed as a test: AGPL §13 requires anyone offering a modified version
// over a network to give its users a way to obtain the modified source, and
// this member is how a conforming directory discharges that.
func TestMetaFixturesCarryEverySpecifiedMember(t *testing.T) {
	f := load(t)

	seen := 0
	for _, fixture := range f.Fixtures {
		if fixture.Spec != "§5.1" {
			continue
		}
		seen++

		t.Run(fixture.ID, func(t *testing.T) {
			var members map[string]json.RawMessage
			if err := json.Unmarshal([]byte(fixture.Expect.Body.Value), &members); err != nil {
				t.Fatalf("the expected meta body is not a JSON object: %v", err)
			}
			for _, name := range []string{
				"v", "record_count", "max_ttl", "max_record_bytes", "pow_bits", "signal", "source_url",
			} {
				if _, ok := members[name]; !ok {
					t.Errorf("member %q is absent: §5.1 makes all seven REQUIRED", name)
				}
			}
			if len(members) != 7 {
				t.Errorf("the expected meta body has %d members, want 7", len(members))
			}

			var sourceURL string
			if err := json.Unmarshal(members["source_url"], &sourceURL); err != nil {
				t.Fatalf("source_url is not a string: %v", err)
			}
			if strings.TrimSpace(sourceURL) == "" {
				t.Error("source_url is empty: AGPL §13 compliance is not optional")
			}
		})
	}

	if seen == 0 {
		t.Error("no §5.1 fixture: the meta shape is unchecked")
	}
}

// TestTheClockIsFixed asserts the property the whole file rests on: one
// declared clock, and every time in the file consistent with it.
func TestTheClockIsFixed(t *testing.T) {
	f := load(t)

	if f.Now == 0 {
		t.Fatal("the file declares no clock")
	}
	if f.Now != Now {
		t.Errorf("the file's clock is %d, the generator's is %d", f.Now, Now)
	}

	for _, r := range f.InitialState.Records {
		if r.LoadedAt != f.Now {
			t.Errorf("record %s is loaded at %d, not at now", r.ID, r.LoadedAt)
		}
		if r.ExpiresAt <= f.Now {
			t.Errorf("record %s expires at %d, which is not after now: it would be absent for every "+
				"purpose the moment it was stored", r.ID, r.ExpiresAt)
		}
	}

	var held, expired int
	for _, c := range f.InitialState.SignalChannels {
		if c.Held {
			held++
			if c.ExpiresAt <= f.Now {
				t.Errorf("channel %s is declared held but expires at %d", c.ID, c.ExpiresAt)
			}
			continue
		}
		expired++
		if c.ExpiresAt > f.Now {
			t.Errorf("channel %s is declared not held but expires at %d", c.ID, c.ExpiresAt)
		}
	}
	if held == 0 || expired == 0 {
		t.Errorf("the initial state has %d held and %d expired channels; §5.4's first-write-wins rule "+
			"applies only to an unexpired blob, so both are needed", held, expired)
	}
}

// TestAdversarialRecordCarriesEveryProperty is the guard on the fixture most
// likely to be quietly simplified.
//
// A directory that re-serialises stored envelopes passes every test that
// compares parsed structures, which is why §5.2 requires a conformance test to
// compare bytes and why D-27 says assembling the response around the stored
// bytes avoids the problem rather than detecting it. This record is what
// detects it, and it only detects it while it carries all four properties.
func TestAdversarialRecordCarriesEveryProperty(t *testing.T) {
	f := load(t)

	var body string
	for _, r := range f.InitialState.Records {
		if r.ID == "record-adversarial-formatting" {
			body = r.Envelope.Value
		}
	}
	if body == "" {
		t.Fatal("the initial state carries no adversarially formatted record")
	}
	if err := checkAdversarialRecord(body); err != nil {
		t.Fatal(err)
	}

	// Compacting it, or re-marshalling it through encoding/json, must produce
	// something different — otherwise the record would pass a re-serialising
	// directory and the fixture would be testing nothing.
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(body)); err != nil {
		t.Fatalf("the record is not valid JSON: %v", err)
	}
	if compact.String() == body {
		t.Error("compacting the record changes nothing: it would not catch a directory that compacts")
	}

	var members map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &members); err != nil {
		t.Fatalf("the record is not a JSON object: %v", err)
	}
	remarshalled, err := json.Marshal(members)
	if err != nil {
		t.Fatalf("re-marshalling: %v", err)
	}
	if string(remarshalled) == body {
		t.Error("re-marshalling the record reproduces it exactly: it would not catch a directory that " +
			"rebuilds the envelope from what it parsed")
	}
	if !strings.Contains(body, "<") {
		t.Error("the record no longer carries a '<'")
	}
	if strings.Contains(string(remarshalled), "<") {
		t.Error("re-marshalling the record leaves '<' unescaped on this toolchain, so this record no " +
			"longer demonstrates the HTML-escaping fault §5.2 names — the compaction fault above is " +
			"still caught, but the escaping one would need a different demonstration")
	}

	// At least one fixture must return this record, or nothing checks any of
	// the above at the transport layer.
	returning := 0
	for _, fixture := range f.Fixtures {
		if strings.Contains(fixture.Expect.Body.Value, body) {
			returning++
		}
	}
	if returning == 0 {
		t.Error("no fixture expects a response containing the adversarially formatted record")
	}
}

// TestNoFixtureDependsOnAnother restates requirement two mechanically: the file
// claims order independence, and that claim is only true because every fixture
// is driven against a fresh instance.
//
// The check is that the claim is declared and that the fixtures which mutate
// state are marked, so a harness that cannot reset knows which ones to run last.
func TestNoFixtureDependsOnAnother(t *testing.T) {
	f := load(t)

	if !f.Harness.ResetBetweenFixtures || !f.Harness.OrderIndependent {
		t.Error("the file no longer claims order independence; if that is deliberate, the fixtures " +
			"that depend on one another must say which")
	}

	mutating := 0
	for _, fixture := range f.Fixtures {
		if fixture.MutatesState {
			mutating++
		}
	}
	if mutating == 0 {
		t.Error("no fixture is marked as mutating state, which cannot be right: a publish that is " +
			"accepted stores a record and a delivered blob is consumed")
	}
}
