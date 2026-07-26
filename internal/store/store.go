// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright

// Package store is the record persistence layer, DIRECTORY-SPEC.md §9.
//
// One table, three behaviours, and nothing else. The three are worth stating
// plainly because each is a correctness property rather than an implementation
// detail, and each is easy to break in a way that still looks like it works.
//
// # Envelopes are stored and returned verbatim
//
// The envelope column holds the byte sequence the directory received, and
// ByPrefix reproduces those bytes unchanged (§5.2). The other columns exist
// only to index it: they are parsed out of that same envelope by the caller,
// and the representation returned to a client is always the stored bytes,
// never a re-serialisation of the parsed fields.
//
// This is what makes §10's additive-change policy work. An envelope may carry a
// field introduced after this directory was written; a directory that rebuilt
// the JSON from the fields it happened to know would strip that field silently,
// so a server and client both running a later revision could not use an older
// directory as a transport and nothing would report an error. A re-serialising
// implementation passes every test that does not specifically look for this,
// which is why TestRoundTripIsByteIdentical carries an unknown-member case.
//
// # An expired record is absent for every purpose, swept or not
//
// Expiry is a function of the record and the clock, never of sweep scheduling
// (§5.2). Every statement in this package that reads or overwrites a record
// carries the caller's clock and applies the same predicate, so a directory
// behaves identically immediately before and after its own sweep runs, and two
// directories given identical input and an identical clock agree. Sweep only
// reclaims space; removing it entirely would change no answer this package
// gives.
//
// # The recency rule
//
// A publish is accepted only if its expires_at is strictly greater than that of
// any unexpired record already stored under the same lookup_id (§5.2). Equal is
// rejected. Combined with the rule above, an expired stored record sets no
// floor at all — a publish whose expiry is lower than the lapsed record's is
// still accepted, and this closes no replay window, because an envelope older
// than the lapsed one has itself lapsed and fails the future-expiry check that
// the caller applies first.
//
// Put is responsible for that one condition and no other. Every other §5.2
// condition is settled before storage is touched, which is also why the recency
// rule is last in the evaluation order: it is the only one needing a read.
//
// # No logging
//
// This package logs nothing and imports no logging package. Returned errors
// name the failure mode and never the lookup_id, wk_pub or envelope that caused
// it. See CLAUDE.md, "No request logging", and the guards in nolog_test.go,
// which read this package's own source rather than trusting review.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/trigstation/trigstationd/internal/query"
	"github.com/trigstation/trigstationd/internal/record"
	"github.com/trigstation/trigstationd/internal/reject"

	// The driver is modernc.org/sqlite, a pure-Go translation of SQLite, and
	// registers itself under the name "sqlite" rather than "sqlite3". The
	// popular mattn/go-sqlite3 needs CGO and a C toolchain, which would end the
	// single static cross-compiled binary that makes a directory replaceable.
	_ "modernc.org/sqlite"
)

// Errors returned when a caller hands this package something it cannot store
// or query. Each names the failure mode and never the offending value.
var (
	ErrLookupIDLen   = errors.New("store: lookup_id is not the required length")
	ErrEmptyEnvelope = errors.New("store: envelope is empty")
)

// There is deliberately no short-prefix error. A query.Query cannot be built
// with fewer bytes than its bit count requires, so by the time a query reaches
// this package the condition is unrepresentable rather than merely unlikely.

// Record is one row: the envelope as received, plus the fields parsed out of it
// for indexing.
//
// The prefix column is not a member. It is derived here from LookupID, so it
// cannot drift out of agreement with the identifier it indexes.
type Record struct {
	// LookupID is the 32-byte identifier, SHA-256(wk_pub). The caller has
	// already verified that binding (§5.2); this package only stores it.
	LookupID []byte

	// WKPub is the 32-byte epoch write key.
	WKPub []byte

	// ExpiresAt is the expiry from the envelope, seconds since the Unix epoch.
	ExpiresAt int64

	// Envelope is the received body, byte for byte. It is never rebuilt from
	// the fields above.
	Envelope []byte
}

// Store is a handle on the records table.
type Store struct {
	db *sql.DB
}

// Schema is DIRECTORY-SPEC.md §9's table, unchanged.
//
// IF NOT EXISTS throughout, so that Open on an existing database is a no-op
// rather than a migration.
const schema = `
CREATE TABLE IF NOT EXISTS records (
  lookup_id  BLOB PRIMARY KEY,
  prefix     INTEGER NOT NULL,
  wk_pub     BLOB NOT NULL,
  expires_at INTEGER NOT NULL,
  envelope   BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_prefix  ON records(prefix);
CREATE INDEX IF NOT EXISTS idx_expires ON records(expires_at);
`

// Open opens or creates the database at path and ensures the schema is present.
//
// path is an ordinary filesystem path, or ":memory:" for a database that lives
// only as long as the handle.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", dataSourceName(path))
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}

	if inMemory(path) {
		// Every new connection to ":memory:" gets its own empty database, so a
		// pooled handle would see the schema appear and disappear depending on
		// which connection served the statement. One connection is the whole
		// fix, and an in-memory database exists for tests and ephemeral runs
		// where serialised access costs nothing.
		db.SetMaxOpenConns(1)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: schema: %w", err)
	}

	return &Store{db: db}, nil
}

// Close releases the database handle.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("store: close: %w", err)
	}
	return nil
}

// putSQL is the whole of §5.2's storage behaviour in one statement.
//
// The DO UPDATE clause's WHERE is the recency rule. It admits the write when
// either the stored record has already lapsed — in which case it is absent for
// every purpose and sets no floor, so even a lower expiry is accepted — or the
// incoming expiry is strictly greater than the stored one. Equal satisfies
// neither and is rejected, which is the point: within an epoch the write key is
// stable, so a captured envelope still verifies, and without strict
// monotonicity a replay would silently roll the published address back.
//
// A conflict the WHERE rejects updates no row, so RowsAffected distinguishes
// the two outcomes without a second statement and without a transaction: the
// read and the write are one statement and cannot interleave.
const putSQL = `
INSERT INTO records (lookup_id, prefix, wk_pub, expires_at, envelope)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(lookup_id) DO UPDATE SET
  prefix     = excluded.prefix,
  wk_pub     = excluded.wk_pub,
  expires_at = excluded.expires_at,
  envelope   = excluded.envelope
WHERE records.expires_at <= ?
   OR excluded.expires_at > records.expires_at
`

// Put stores rec, replacing any record under the same lookup_id, and reports
// whether the recency rule of DIRECTORY-SPEC.md §5.2 admitted it.
//
// now is the directory's clock in seconds since the Unix epoch, passed in
// rather than read here so that the boundary cases are testable.
//
// The returned reason is RecordAccepted or RecordNotNewer. Put deliberately
// does not re-check the conditions the caller has already settled — size,
// version, TTL bound, lookup_id binding, proof of work, signature and
// future-expiry — because duplicating a rule is how two copies of it come to
// disagree.
//
// When the returned error is non-nil the reason carries no meaning and the
// caller must not act on it. It is never RecordAccepted in that case, so a
// caller that ignores the error still fails closed.
func (s *Store) Put(ctx context.Context, rec Record, now int64) (reject.RecordReason, error) {
	if len(rec.LookupID) != record.LookupIDLen {
		return reject.RecordMalformed, ErrLookupIDLen
	}
	if len(rec.Envelope) == 0 {
		return reject.RecordMalformed, ErrEmptyEnvelope
	}

	res, err := s.db.ExecContext(ctx, putSQL,
		rec.LookupID, prefix32(rec.LookupID), rec.WKPub, rec.ExpiresAt, rec.Envelope,
		now,
	)
	if err != nil {
		return reject.RecordMalformed, fmt.Errorf("store: put: %w", err)
	}

	n, err := res.RowsAffected()
	if err != nil {
		return reject.RecordMalformed, fmt.Errorf("store: put: %w", err)
	}
	if n == 0 {
		return reject.RecordNotNewer, nil
	}
	return reject.RecordAccepted, nil
}

// byPrefixSQL narrows the scan with the prefix index and drops expired rows.
//
// lookup_id comes back alongside the envelope because the prefix column carries
// only the first 32 bits and a narrower query has to be confirmed against the
// full identifier.
const byPrefixSQL = `
SELECT lookup_id, envelope
FROM records
WHERE prefix BETWEEN ? AND ?
  AND expires_at > ?
ORDER BY lookup_id
`

// ByPrefix returns the verbatim envelope of every unexpired record whose
// lookup_id begins with the query's bit prefix (DIRECTORY-SPEC.md §5.3).
//
// It takes a query.Query rather than a loose prefix and bit count so that the
// masked prefix, the column range and the post-filter travel together as one
// value. The §5.3 masking rule is implemented once, in internal/query, and this
// package consumes it: two copies of a protocol rule is how two implementations
// of the same protocol come to disagree, and that hazard does not stop at the
// boundary of a single codebase.
//
// The query's bits may exceed 32, which the prefix column alone cannot answer.
// Those queries are narrowed on the column and settled against the full
// lookup_id. The exact test runs on every candidate row rather than only when
// bits exceeds 32, so the query has one correctness argument instead of two, at
// the cost of a byte comparison across a result set §5.3 bounds at roughly 2k
// records.
//
// Enforcing §5.3's maximum bits is not done here. That bound is computed from
// the true record count against the instance's k_min, which is a policy the
// handler holds.
//
// The result is never nil, so that an empty result encodes as [] and not null.
// §5.3 requires 200 with an empty records array, never 404.
func (s *Store) ByPrefix(ctx context.Context, q query.Query, now int64) ([][]byte, error) {
	lo, hi := q.Range()

	rows, err := s.db.QueryContext(ctx, byPrefixSQL, lo, hi, now)
	if err != nil {
		return nil, fmt.Errorf("store: query: %w", err)
	}
	defer rows.Close()

	envelopes := [][]byte{}
	for rows.Next() {
		// Scanning into *[]byte copies out of the driver's buffer, so the
		// envelope stays valid after the next Next.
		var lookupID, envelope []byte
		if err := rows.Scan(&lookupID, &envelope); err != nil {
			return nil, fmt.Errorf("store: scan: %w", err)
		}
		if !q.Matches(lookupID) {
			continue
		}
		envelopes = append(envelopes, envelope)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: query: %w", err)
	}

	return envelopes, nil
}

// Sweep deletes records that expired at or before now and returns how many rows
// went.
//
// Nothing else in this package consults it. Expiry is a property of the record
// and the clock (§5.2), so every read already excludes a lapsed row and Sweep
// reclaims space without changing a single answer. A directory that never swept
// would return the same results, only from a larger table.
func (s *Store) Sweep(ctx context.Context, now int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM records WHERE expires_at <= ?`, now)
	if err != nil {
		return 0, fmt.Errorf("store: sweep: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: sweep: %w", err)
	}
	return n, nil
}

// Count returns the true number of unexpired records.
//
// True, not understated. §5.1 permits record_count to be reduced in the meta
// response to avoid disclosing instance scale, but that rounding is the meta
// handler's business: §5.3 computes the server-side maximum bits against the
// true count, so a store that understated here would tighten the directory's
// own cap below what a client following the advertised figure is entitled to
// ask for.
func (s *Store) Count(ctx context.Context, now int64) (int64, error) {
	var n int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM records WHERE expires_at > ?`, now).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count: %w", err)
	}
	return n, nil
}

// dataSourceName turns a filesystem path into the driver's DSN.
//
// The pragmas are set in the DSN rather than executed after opening because
// database/sql pools connections: busy_timeout is per-connection, so a pragma
// run once would apply to whichever connection happened to serve it. WAL keeps
// lookups reading while a publish writes, which suits a workload of roughly six
// publishes and two hundred lookups a second (§9.1).
func dataSourceName(path string) string {
	if inMemory(path) {
		return path
	}
	return "file:" + uriPath(path) + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
}

// inMemory reports whether the path names a database with no file behind it.
func inMemory(path string) bool {
	return path == ":memory:" || strings.Contains(path, "mode=memory")
}

// uriPath escapes a filesystem path for use in a SQLite URI filename.
//
// A URI filename is a URL: '?' opens the query where the pragmas live, '#'
// opens a fragment, and '%' introduces an escape. Windows separators have to
// become forward slashes. The replacements are applied in one pass, so the
// escape introduced for '%' is not itself rescanned.
func uriPath(path string) string {
	return strings.NewReplacer(
		`\`, "/",
		"%", "%25",
		"?", "%3f",
		"#", "%23",
	).Replace(path)
}
