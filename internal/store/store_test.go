// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

package store

import (
	"bytes"
	"context"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/trigstation/trigstationd/internal/b64"
	"github.com/trigstation/trigstationd/internal/query"
	"github.com/trigstation/trigstationd/internal/record"
	"github.com/trigstation/trigstationd/internal/reject"
)

// open returns a store over a fresh database in the test's temporary
// directory, closed when the test ends.
func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "records.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

// lookupID returns a 32-byte identifier beginning with the given bytes. The
// tail is a fixed filler, because only the leading bits ever matter here.
func lookupID(head ...byte) []byte {
	id := bytes.Repeat([]byte{0x5a}, record.LookupIDLen)
	copy(id, head)
	return id
}

// envelopeJSON builds an envelope body the way some other implementation's
// serialiser might: its own key order, its own whitespace, and optionally a
// member this directory has never heard of.
//
// It is deliberately not built with encoding/json. The property under test is
// that these exact bytes survive storage, and a marshaller would normalise the
// very things that make the test meaningful.
func envelopeJSON(id []byte, expiresAt int64, extra string) []byte {
	var b strings.Builder
	b.WriteString("{\n")
	b.WriteString("    \"expires_at\" :  " + strconv.FormatInt(expiresAt, 10) + ",\n")
	if extra != "" {
		b.WriteString("    " + extra + ",\n")
	}
	b.WriteString("  \"v\":1,\n")
	b.WriteString("\t\"lookup_id\": \"" + b64.Encode(id) + "\",\n")
	b.WriteString("  \"wk_pub\":\"" + b64.Encode(wkPubFor(id)) + "\"\n")
	b.WriteString("}")
	return []byte(b.String())
}

func wkPubFor(id []byte) []byte {
	wk := bytes.Repeat([]byte{0x11}, record.WKPubLen)
	copy(wk, id[:4])
	return wk
}

// put stores an envelope built for id and returns the reason, failing the test
// on a storage error.
func put(t *testing.T, s *Store, id []byte, expiresAt, now int64, extra string) (reject.RecordReason, []byte) {
	t.Helper()
	env := envelopeJSON(id, expiresAt, extra)
	reason, err := s.Put(context.Background(), Record{
		LookupID:  id,
		WKPub:     wkPubFor(id),
		ExpiresAt: expiresAt,
		Envelope:  env,
	}, now)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	return reason, env
}

// all returns every unexpired envelope, which is the bits=0 query §5.3 requires
// every directory to accept.
func all(t *testing.T, s *Store, now int64) [][]byte {
	t.Helper()
	got, err := s.ByPrefix(context.Background(), mustQuery(t, nil, 0), now)
	if err != nil {
		t.Fatalf("ByPrefix: %v", err)
	}
	return got
}

// TestRoundTripIsByteIdentical is the verbatim-storage rule of §5.2.
//
// The unknown-member case is the one that matters and the one easiest to leave
// out: an implementation that parses the envelope and re-serialises it from the
// fields it knows passes every other test in this file. It would strip a member
// introduced under §10's additive-change policy, silently, so a server and
// client both running a later revision could not use this directory as a
// transport and nothing would report an error.
func TestRoundTripIsByteIdentical(t *testing.T) {
	tests := []struct {
		name  string
		extra string
	}{
		{"no unknown members", ""},
		{"unknown scalar member", `"future_hint": "a value this directory has never heard of"`},
		{"unknown composite member", `"future_field": {"nested": [1, 2, 3], "deep": {"x": null}}`},
		{"unknown member that looks like a known one", `"expires_at_ms": 1753574400000`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := open(t)
			id := lookupID(0x12, 0x34, 0x56, 0x78)

			reason, want := put(t, s, id, 2000, 1000, tt.extra)
			if reason != reject.RecordAccepted {
				t.Fatalf("Put = %v, want RecordAccepted", reason)
			}

			got := all(t, s, 1000)
			if len(got) != 1 {
				t.Fatalf("ByPrefix returned %d envelopes, want 1", len(got))
			}
			if !bytes.Equal(got[0], want) {
				t.Errorf("envelope was not returned verbatim:\n got %q\nwant %q", got[0], want)
			}
			if tt.extra != "" && !bytes.Contains(got[0], []byte(tt.extra)) {
				t.Errorf("the unknown member was stripped: %q is absent from %q", tt.extra, got[0])
			}
		})
	}
}

// TestRoundTripPreservesArbitraryBytes checks that the envelope column is a
// blob and not text: an envelope is stored as received, and nothing in this
// package is entitled to assume it is valid UTF-8 or valid JSON.
func TestRoundTripPreservesArbitraryBytes(t *testing.T) {
	s := open(t)
	id := lookupID(0x01, 0x02, 0x03, 0x04)

	want := []byte{'{', 0x00, 0xff, 0xfe, '\n', 0x80, '}'}
	if _, err := s.Put(context.Background(), Record{
		LookupID:  id,
		WKPub:     wkPubFor(id),
		ExpiresAt: 2000,
		Envelope:  want,
	}, 1000); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got := all(t, s, 1000)
	if len(got) != 1 || !bytes.Equal(got[0], want) {
		t.Errorf("got % x, want % x", got, want)
	}
}

// TestRecencyRule is the last condition of §5.2: a publish is accepted only if
// its expires_at is strictly greater than that of an unexpired stored record
// under the same lookup_id.
//
// Equal is rejected. Within an epoch the write key is stable, so a captured
// envelope still verifies; without strict monotonicity a replay would roll the
// published address back and present as a stale address rather than an error.
func TestRecencyRule(t *testing.T) {
	const now = 1000

	tests := []struct {
		name    string
		stored  int64
		publish int64
		want    reject.RecordReason
	}{
		{"strictly newer", 2000, 2001, reject.RecordAccepted},
		{"much newer", 2000, 9000, reject.RecordAccepted},
		{"equal", 2000, 2000, reject.RecordNotNewer},
		{"one second older", 2000, 1999, reject.RecordNotNewer},
		{"much older, still unexpired", 2000, 1001, reject.RecordNotNewer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := open(t)
			id := lookupID(0x12, 0x34, 0x56, 0x78)

			reason, first := put(t, s, id, tt.stored, now, "")
			if reason != reject.RecordAccepted {
				t.Fatalf("first Put = %v, want RecordAccepted", reason)
			}

			reason, second := put(t, s, id, tt.publish, now, `"second": true`)
			if reason != tt.want {
				t.Fatalf("second Put = %v, want %v", reason, tt.want)
			}

			// A rejected publish must leave the stored record untouched. An
			// implementation that wrote first and judged afterwards would still
			// return the right reason here while having already overwritten the
			// address the recency rule exists to protect.
			want := second
			if tt.want != reject.RecordAccepted {
				want = first
			}
			got := all(t, s, now)
			if len(got) != 1 {
				t.Fatalf("ByPrefix returned %d envelopes, want 1", len(got))
			}
			if !bytes.Equal(got[0], want) {
				t.Errorf("stored envelope = %q, want %q", got[0], want)
			}
		})
	}
}

// TestExpiredRecordSetsNoRecencyFloor is the interaction of the two rules in
// §5.2: an expired record is absent for every purpose, so it does not block a
// publish, whatever its expiry was.
//
// The last case is the sharp one. A publish whose expires_at is *lower* than
// the lapsed record's is admitted by the recency rule, because a record that
// has lapsed is not there to be compared against. That closes no replay window:
// such an envelope has necessarily lapsed too, and the caller has already
// rejected it under §5.2's future-expiry condition — a condition this package
// deliberately does not duplicate.
func TestExpiredRecordSetsNoRecencyFloor(t *testing.T) {
	tests := []struct {
		name    string
		stored  int64
		now     int64
		publish int64
		want    reject.RecordReason
	}{
		{"stored record still live, older publish blocked", 5000, 4000, 4500, reject.RecordNotNewer},
		{"stored record still live, equal publish blocked", 5000, 4000, 5000, reject.RecordNotNewer},
		{"stored record lapsed, later publish admitted", 5000, 6000, 6500, reject.RecordAccepted},
		{"stored record lapsed at exactly now, publish admitted", 5000, 5000, 5500, reject.RecordAccepted},
		{"stored record lapsed, lower expiry still admitted", 5000, 6000, 4000, reject.RecordAccepted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := open(t)
			id := lookupID(0x12, 0x34, 0x56, 0x78)

			if reason, _ := put(t, s, id, tt.stored, tt.stored-1000, ""); reason != reject.RecordAccepted {
				t.Fatalf("first Put = %v, want RecordAccepted", reason)
			}
			if reason, _ := put(t, s, id, tt.publish, tt.now, `"second": true`); reason != tt.want {
				t.Errorf("second Put = %v, want %v", reason, tt.want)
			}
		})
	}
}

// TestExpiredRecordIsAbsentBeforeSweep is §5.2's rule that expiry is a property
// of the record and the clock, never of sweep scheduling. No sweep runs in this
// test at all.
func TestExpiredRecordIsAbsentBeforeSweep(t *testing.T) {
	tests := []struct {
		name string
		now  int64
		want int
	}{
		{"well before expiry", 1000, 1},
		{"one second before expiry", 4999, 1},
		{"at expires_at", 5000, 0},
		{"one second after expiry", 5001, 0},
		{"long after expiry", 999999, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := open(t)
			id := lookupID(0x12, 0x34, 0x56, 0x78)
			if reason, _ := put(t, s, id, 5000, 100, ""); reason != reject.RecordAccepted {
				t.Fatalf("Put = %v, want RecordAccepted", reason)
			}

			if got := len(all(t, s, tt.now)); got != tt.want {
				t.Errorf("ByPrefix at now=%d returned %d envelopes, want %d", tt.now, got, tt.want)
			}

			n, err := s.Count(context.Background(), tt.now)
			if err != nil {
				t.Fatalf("Count: %v", err)
			}
			if n != int64(tt.want) {
				t.Errorf("Count at now=%d = %d, want %d", tt.now, n, tt.want)
			}
		})
	}
}

// TestSweepChangesNothingObservable is the other half of the same rule: a
// directory must behave identically immediately before and after its own sweep
// runs, so two directories with identical input and clock agree regardless of
// when either last swept.
func TestSweepChangesNothingObservable(t *testing.T) {
	const now = 5000

	s := open(t)
	live := []struct {
		id      []byte
		expires int64
	}{
		{lookupID(0x00, 0x00, 0x00, 0x01), 5001},
		{lookupID(0x40, 0x00, 0x00, 0x02), 9000},
		{lookupID(0xff, 0xff, 0xff, 0xf3), 6000},
	}
	dead := []struct {
		id      []byte
		expires int64
	}{
		{lookupID(0x00, 0x00, 0x00, 0x04), 5000}, // expires exactly at now
		{lookupID(0x80, 0x00, 0x00, 0x05), 4999},
		{lookupID(0xff, 0xff, 0xff, 0xf6), 1},
	}
	for _, r := range live {
		put(t, s, r.id, r.expires, 0, "")
	}
	for _, r := range dead {
		put(t, s, r.id, r.expires, 0, "")
	}

	queries := []struct {
		name   string
		prefix []byte
		bits   uint
	}{
		{"everything", nil, 0},
		{"top bit clear", []byte{0x00}, 1},
		{"top bit set", []byte{0x80}, 1},
		{"a full column prefix", []byte{0xff, 0xff, 0xff, 0xf3}, 32},
	}

	before := make(map[string][][]byte, len(queries))
	for _, q := range queries {
		got, err := s.ByPrefix(context.Background(), mustQuery(t, q.prefix, q.bits), now)
		if err != nil {
			t.Fatalf("ByPrefix(%s): %v", q.name, err)
		}
		before[q.name] = got
	}
	countBefore, err := s.Count(context.Background(), now)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if countBefore != int64(len(live)) {
		t.Fatalf("Count before sweep = %d, want %d", countBefore, len(live))
	}

	removed, err := s.Sweep(context.Background(), now)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if removed != int64(len(dead)) {
		t.Errorf("Sweep removed %d rows, want %d", removed, len(dead))
	}

	for _, q := range queries {
		got, err := s.ByPrefix(context.Background(), mustQuery(t, q.prefix, q.bits), now)
		if err != nil {
			t.Fatalf("ByPrefix(%s) after sweep: %v", q.name, err)
		}
		if !reflect.DeepEqual(got, before[q.name]) {
			t.Errorf("query %q changed across the sweep:\nbefore %q\n after %q", q.name, before[q.name], got)
		}
	}
	countAfter, err := s.Count(context.Background(), now)
	if err != nil {
		t.Fatalf("Count after sweep: %v", err)
	}
	if countAfter != countBefore {
		t.Errorf("Count after sweep = %d, want %d", countAfter, countBefore)
	}

	// A second sweep at the same clock has nothing left to take.
	again, err := s.Sweep(context.Background(), now)
	if err != nil {
		t.Fatalf("second Sweep: %v", err)
	}
	if again != 0 {
		t.Errorf("second Sweep removed %d rows, want 0", again)
	}
}

// prefixFixture is the set of identifiers the bit-length tests query against.
// Only the leading bytes are meaningful.
var prefixFixture = map[string][]byte{
	"A": lookupID(0x00, 0x00, 0x00, 0x00, 0x00),
	"B": lookupID(0x40, 0x00, 0x00, 0x00, 0x00),
	"C": lookupID(0x80, 0x00, 0x00, 0x00, 0x00),
	"D": lookupID(0xa3, 0xf0, 0x00, 0x00, 0x00),
	"E": lookupID(0xa3, 0xc0, 0x00, 0x00, 0x00),
	"F": lookupID(0xff, 0xff, 0xff, 0xff, 0x11),
	"G": lookupID(0xff, 0xff, 0xff, 0xff, 0x22),
}

// TestByPrefixBitLengths walks the bit-length maths at the limits, from the
// zero-bit query every client sends to a new instance up past the width of the
// prefix column.
//
// Cases D and E share their first ten bits and differ at the twelfth; F and G
// share all thirty-two bits of the column and differ only at the fortieth,
// which is the pair that exercises the post-filter. Nothing about a query wider
// than the column is rejected — it simply cannot be answered by the index
// alone.
func TestByPrefixBitLengths(t *testing.T) {
	const now = 1000

	s := open(t)
	envelopes := map[string][]byte{}
	for name, id := range prefixFixture {
		reason, env := put(t, s, id, 5000, now, `"name": "`+name+`"`)
		if reason != reject.RecordAccepted {
			t.Fatalf("Put %s = %v, want RecordAccepted", name, reason)
		}
		envelopes[name] = env
	}

	tests := []struct {
		name   string
		prefix []byte
		bits   uint
		want   []string
	}{
		{"zero bits returns everything", nil, 0, []string{"A", "B", "C", "D", "E", "F", "G"}},
		{"zero bits with an empty prefix slice", []byte{}, 0, []string{"A", "B", "C", "D", "E", "F", "G"}},
		// A and B lead with 0x00 and 0x40; C, D, E, F and G lead with 0x80,
		// 0xa3, 0xa3, 0xff and 0xff, all of which have the top bit set.
		{"one bit clear", []byte{0x00}, 1, []string{"A", "B"}},
		{"one bit set", []byte{0x80}, 1, []string{"C", "D", "E", "F", "G"}},
		{"four bits", []byte{0xa0}, 4, []string{"D", "E"}},
		{"four bits, no match", []byte{0x10}, 4, nil},
		// bits=10 is the recommended width at 100,000 records, and the two
		// spellings below differ only in the six insignificant trailing bits
		// that §5.3 requires a directory to mask and ignore.
		{"ten bits, trailing bits zeroed", []byte{0xa3, 0xc0}, 10, []string{"D", "E"}},
		{"ten bits, trailing bits set", []byte{0xa3, 0xff}, 10, []string{"D", "E"}},
		{"twelve bits selects D", []byte{0xa3, 0xf0}, 12, []string{"D"}},
		{"twelve bits selects E", []byte{0xa3, 0xc0}, 12, []string{"E"}},
		{"thirty-two bits, shared by two records", []byte{0xff, 0xff, 0xff, 0xff}, 32, []string{"F", "G"}},
		{"thirty-two bits, single record", []byte{0xa3, 0xf0, 0x00, 0x00}, 32, []string{"D"}},
		// Past the column width the range scan cannot separate F from G, so
		// these two cases fail unless the full lookup_id is checked afterwards.
		{"forty bits selects F", []byte{0xff, 0xff, 0xff, 0xff, 0x11}, 40, []string{"F"}},
		{"forty bits selects G", []byte{0xff, 0xff, 0xff, 0xff, 0x22}, 40, []string{"G"}},
		{"forty bits, no match", []byte{0xff, 0xff, 0xff, 0xff, 0x33}, 40, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.ByPrefix(context.Background(), mustQuery(t, tt.prefix, tt.bits), now)
			if err != nil {
				t.Fatalf("ByPrefix: %v", err)
			}

			want := make([][]byte, 0, len(tt.want))
			for _, name := range tt.want {
				want = append(want, envelopes[name])
			}
			if len(got) != len(want) {
				t.Fatalf("ByPrefix(bits=%d) returned %d envelopes, want %d (%v)", tt.bits, len(got), len(want), tt.want)
			}
			for _, w := range want {
				if !containsEnvelope(got, w) {
					t.Errorf("ByPrefix(bits=%d) is missing an expected envelope: %q", tt.bits, w)
				}
			}
		})
	}
}

// TestPrefixAboveInt32RoundTrips is the half of the keyspace an implementation
// that narrows the prefix column to int32 loses.
//
// It asserts the stored column value directly as well as the query result,
// because a narrowing bug that happened to be symmetric on read and write would
// still return the right records while writing a negative prefix that no other
// implementation would agree with.
func TestPrefixAboveInt32RoundTrips(t *testing.T) {
	const now = 1000

	tests := []struct {
		name       string
		id         []byte
		wantPrefix int64
		query      []byte
		bits       uint
	}{
		{"leading 0xff", lookupID(0xff, 0xff, 0xff, 0xff), 4294967295, []byte{0xff}, 8},
		{"at the int32 boundary", lookupID(0x80, 0x00, 0x00, 0x00), 2147483648, []byte{0x80}, 1},
		{"just below the boundary", lookupID(0x7f, 0xff, 0xff, 0xff), 2147483647, []byte{0x7f}, 8},
		{"leading 0xff with a tail", lookupID(0xff, 0x01, 0x02, 0x03), 4278256131, []byte{0xff, 0x01, 0x02, 0x03}, 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := open(t)
			reason, want := put(t, s, tt.id, 5000, now, "")
			if reason != reject.RecordAccepted {
				t.Fatalf("Put = %v, want RecordAccepted", reason)
			}

			var stored int64
			err := s.db.QueryRow(`SELECT prefix FROM records`).Scan(&stored)
			if err != nil {
				t.Fatalf("reading the prefix column: %v", err)
			}
			if stored != tt.wantPrefix {
				t.Errorf("prefix column = %d, want %d", stored, tt.wantPrefix)
			}

			got, err := s.ByPrefix(context.Background(), mustQuery(t, tt.query, tt.bits), now)
			if err != nil {
				t.Fatalf("ByPrefix: %v", err)
			}
			if len(got) != 1 || !bytes.Equal(got[0], want) {
				t.Errorf("a range scan did not find the record: got %d envelopes", len(got))
			}
		})
	}
}

// TestEmptyResultIsEmptyNotNil pins the shape §5.3 requires: a directory with
// no matching records returns 200 with an empty records array, never 404 and
// never a null.
func TestEmptyResultIsEmptyNotNil(t *testing.T) {
	s := open(t)
	got, err := s.ByPrefix(context.Background(), mustQuery(t, nil, 0), 1000)
	if err != nil {
		t.Fatalf("ByPrefix: %v", err)
	}
	if got == nil {
		t.Error("ByPrefix returned nil, which marshals to null rather than []")
	}
	if len(got) != 0 {
		t.Errorf("ByPrefix returned %d envelopes from an empty store", len(got))
	}
}

// TestShortPrefixCannotReachTheStore records where a caller error is now
// caught. §5.3 requires prefix to carry exactly ceil(bits/4) hex characters, so
// fewer bytes than bits asks for is a bug rather than a query with a different
// answer.
//
// ByPrefix no longer has to defend against it: a Query cannot be constructed
// short, so by the time storage sees one the condition is unrepresentable. That
// is a better place for the check than a runtime guard inside the query path —
// but it is only true while Query stays constructible in exactly two places, so
// this test pins it rather than trusting it.
func TestShortPrefixCannotReachTheStore(t *testing.T) {
	if _, err := query.FromBits([]byte{0xa3}, 16); err == nil {
		t.Error("query.FromBits accepted a prefix carrying fewer bytes than bits requires")
	}
}

// TestPutRejectsUnstorableRecords covers the guards on the way in. None of
// these should reach storage — a malformed envelope is refused during parsing —
// but a caller that ignored the error must still not see RecordAccepted.
func TestPutRejectsUnstorableRecords(t *testing.T) {
	tests := []struct {
		name string
		rec  Record
	}{
		{"lookup_id too short", Record{LookupID: []byte{0x01, 0x02}, ExpiresAt: 2000, Envelope: []byte("{}")}},
		{"lookup_id absent", Record{ExpiresAt: 2000, Envelope: []byte("{}")}},
		{"lookup_id too long", Record{LookupID: bytes.Repeat([]byte{1}, 33), ExpiresAt: 2000, Envelope: []byte("{}")}},
		{"envelope absent", Record{LookupID: lookupID(0x01), ExpiresAt: 2000}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := open(t)
			reason, err := s.Put(context.Background(), tt.rec, 1000)
			if err == nil {
				t.Fatal("Put returned no error")
			}
			if reason == reject.RecordAccepted {
				t.Error("Put failed open: the reason accompanying an error must never be RecordAccepted")
			}
			if n, _ := s.Count(context.Background(), 1000); n != 0 {
				t.Errorf("Count = %d after a rejected Put, want 0", n)
			}
		})
	}
}

// TestErrorsOmitTheOffendingValue is the "no request logging" rule at the point
// it is easiest to break: an error that helpfully quotes the identifier that
// caused it. See internal/b64 for the same guard.
func TestErrorsOmitTheOffendingValue(t *testing.T) {
	s := open(t)
	secret := []byte("a-lookup-id-that-must-not-appear-in-any-error")

	_, err := s.Put(context.Background(), Record{
		LookupID:  secret,
		WKPub:     bytes.Repeat([]byte{0x11}, record.WKPubLen),
		ExpiresAt: 2000,
		Envelope:  []byte(`{"secret-envelope-body": true}`),
	}, 1000)
	if err == nil {
		t.Fatal("want an error for a lookup_id of the wrong length")
	}
	for _, leaked := range []string{string(secret), "secret-envelope-body"} {
		if strings.Contains(err.Error(), leaked) {
			t.Errorf("error message leaked a stored value: %v", err)
		}
	}
}

// TestOpenInMemory covers the ":memory:" path, which has to work for tests and
// ephemeral runs and which fails in a confusing way if the connection pool is
// left to open more than one connection: each gets its own empty database.
func TestOpenInMemory(t *testing.T) {
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open(:memory:): %v", err)
	}
	defer s.Close()

	id := lookupID(0xff, 0x00, 0x00, 0x01)
	reason, want := put(t, s, id, 5000, 1000, `"in": "memory"`)
	if reason != reject.RecordAccepted {
		t.Fatalf("Put = %v, want RecordAccepted", reason)
	}

	// Repeated so that a pool handing out a second connection would be caught.
	for i := 0; i < 8; i++ {
		got := all(t, s, 1000)
		if len(got) != 1 || !bytes.Equal(got[0], want) {
			t.Fatalf("read %d returned %d envelopes, want 1 matching", i, len(got))
		}
	}
}

// TestOpenIsIdempotent checks that Open on an existing database creates nothing
// and loses nothing.
func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.db")

	first, err := Open(path)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	id := lookupID(0xab, 0xcd, 0xef, 0x01)
	reason, want := put(t, first, id, 5000, 1000, `"persisted": true`)
	if reason != reject.RecordAccepted {
		t.Fatalf("Put = %v, want RecordAccepted", reason)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer second.Close()

	got := all(t, second, 1000)
	if len(got) != 1 || !bytes.Equal(got[0], want) {
		t.Fatalf("reopened store returned %d envelopes, want 1 matching", len(got))
	}
}

// TestCountIsTrue asserts Count reports the true number of unexpired records.
// §5.1 permits record_count to be understated in the meta response, but §5.3
// computes the server-side maximum bits against the true count, so the
// rounding belongs to the meta handler and not here.
func TestCountIsTrue(t *testing.T) {
	const now = 1000

	s := open(t)
	for i := 0; i < 7; i++ {
		put(t, s, lookupID(byte(i), 0x00, 0x00, 0x00), 5000, now, "")
	}
	for i := 0; i < 3; i++ {
		put(t, s, lookupID(0x90, byte(i), 0x00, 0x00), 1500, now, "")
	}

	tests := []struct {
		name string
		now  int64
		want int64
	}{
		{"all live", now, 10},
		{"three lapsed", 2000, 7},
		{"all lapsed", 6000, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.Count(context.Background(), tt.now)
			if err != nil {
				t.Fatalf("Count: %v", err)
			}
			if got != tt.want {
				t.Errorf("Count at now=%d = %d, want %d", tt.now, got, tt.want)
			}
		})
	}
}

func containsEnvelope(haystack [][]byte, needle []byte) bool {
	for _, h := range haystack {
		if bytes.Equal(h, needle) {
			return true
		}
	}
	return false
}

// mustQuery builds a query.Query from a binary prefix for tests. The masking
// rule lives in internal/query; this is only the adapter.
func mustQuery(t *testing.T, prefix []byte, bits uint) query.Query {
	t.Helper()
	q, err := query.FromBits(prefix, bits)
	if err != nil {
		t.Fatalf("query.FromBits(bits=%d): %v", bits, err)
	}
	return q
}
