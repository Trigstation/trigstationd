# CLAUDE.md — trigstationd

Reference implementation of the Trigstation directory service.

A zero-knowledge coordination service that lets a self-hosted media server be
located by its paired clients over the internet. It stores encrypted address
records and brokers short-lived rendezvous channels. It never carries media,
never holds accounts, and cannot read what it stores.

---

## The spec is authoritative

`DIRECTORY-SPEC.md` in the `/spec` repo defines the wire format and
API. This repo implements it. Where code and spec disagree, the spec is right and
the code is a bug.

**Do not change the protocol.** Several things in the spec look like they could
be improved and are load-bearing:

- The HKDF info strings (`trig-write-v1`, `trig-record-v1`, `trig-mailbox-v1`,
  `trig-pair-*`, `trig-devpair-*`) and the proof-of-work prefix `trig-pow-v1`
  are byte-exact wire format. Changing one silently breaks interoperability with
  every other implementation.
- Signatures are computed over **raw concatenated bytes** in the documented field
  order, never over serialised JSON. JSON key ordering and whitespace are not
  stable across languages. Do not "simplify" this by signing the JSON.
- AES-256-GCM was chosen over ChaCha20 variants for standard-library
  availability on .NET, Java and WebCrypto. Do not switch it.
- Base64url is **unpadded**. Accept unpadded input, never emit padding.
- Signal channels are **first-write-wins**, rejecting a second write with `409`.
  Overwrite semantics would turn the rendezvous into an injection point.

If something in the spec is ambiguous, underspecified or appears wrong, **raise
it rather than resolving it in code**. Spec bugs get fixed in the spec.

---

## Non-negotiable design invariants

1. The directory never carries media. Address records and connection setup only.
2. The directory cannot read what it stores. Records are encrypted to paired
   clients; the server holds no decryption key and performs no key derivation.
3. No accounts. No users table, no API keys, no allowlist, no CAPTCHA.
4. Records are self-verifying. Authorisation is the signature, not a header.
5. Records expire. Nothing accumulates.
6. Any instance is replaceable. Instances never communicate with each other.
7. **The API stays at four operations.** Anything that would add a fifth is a
   proposal to make directories less replaceable. Do not add convenience
   endpoints, health dashboards, metrics endpoints, or admin routes.

---

## No request logging

This is a hard requirement, not a configurable default.

The code to log request paths, client IP addresses, lookup prefixes or channel
identifiers **must not exist**. Not disabled, not behind a flag, not at debug
level — absent.

Error logs must not contain identifiers. When logging a failure, log the failure
mode, never the value that caused it.

This is the property that makes the service credible. A directory operator who
cannot log is one who cannot be compelled to produce logs.

---

## Go constraints

- **CGO must stay disabled.** Build with `CGO_ENABLED=0`. The deployment story is
  a single static binary that cross-compiles from one machine, and that is what
  makes directories genuinely replaceable.
- **Use `modernc.org/sqlite`, not `mattn/go-sqlite3`.** The popular driver
  requires CGO and a C toolchain, which breaks the above. Note the driver name
  differs: `sqlite`, not `sqlite3`, in `sql.Open`.
- **Standard library first.** The cryptography needed is `crypto/ed25519`,
  `crypto/sha256` and `crypto/rand`. The directory never performs key agreement,
  key derivation or decryption. `go.mod` should stay close to empty — justify any
  dependency added beyond the SQLite driver.
- Postgres support is optional, behind a build tag or config flag. SQLite is the
  default.
- Schema is the single table in `DIRECTORY-SPEC.md` §9. Signal channels are
  memory-only and never persisted.

Build check:

```
CGO_ENABLED=0 go build ./... && CGO_ENABLED=0 go vet ./...
```

---

## Licensing obligations

Licensed **AGPL-3.0-or-later**. Two consequences that affect the code itself.

### Source file headers

Every `.go` file carries a notice, so the terms travel if a file is copied out of
the repo. Full header in `main.go`:

```go
// Trigstation directory service — a zero-knowledge coordination service
// for self-hosted media servers.
// Copyright (C) 2026  Simon Wright
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
// or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Affero General Public
// License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
```

SPDX short form in every other file:

```go
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright
```

New files get a header. This is not optional tidying.

### Section 13 — the network clause

AGPL §13 requires that anyone who modifies this software and offers it over a
network gives those users a way to obtain the modified source.

The conforming implementation is a `source_url` field in `GET /v1/meta`:

```json
{
  "v": 1,
  "record_count": 104233,
  "source_url": "https://github.com/trigstation/trigstationd"
}
```

It ships populated and documented so that compliance is the default rather than
something an operator has to discover. An operator running a fork changes the URL
to point at their own source.

Do not remove this field, do not make it optional, and do not let it default to
empty. It is a licence obligation expressed as code.

This is an additive change to the v1 wire format, which the versioning policy in
`DIRECTORY-SPEC.md` §10 permits.

---

## Testing

- Table-driven tests, standard library `testing`. No assertion framework.
- **Test vectors are a deliverable, not a by-product.** A known `S_dir` and epoch
  with expected `WriteSeed`, `WK_pub`, `LookupID`, `RecordKey`, and a fully
  formed envelope, committed as JSON so independent implementations can verify
  against the spec rather than against this codebase.
- Cover the cases prose cannot pin down: epoch boundary behaviour, clock skew
  fallback to the previous epoch, prefix bit-length maths at the limits,
  rejection of over-precise prefix queries, proof-of-work verification, and
  first-write-wins on signal channels.
- Verify the rejection paths in §5.2 individually. Each one is a security
  property, not an error case.

---

## Style

- NZ/British spelling in comments, documentation and user-facing strings.
  Identifiers follow Go convention.
- Costs and figures in NZ dollars.
- Errors returned, not logged and swallowed.
- Prefer clarity over cleverness. Design goal 3 is that someone can reimplement
  this from the spec in a weekend, and this codebase is the worked example.

---

## When you hit ambiguity

Stop and ask. Do not resolve protocol questions by picking something reasonable
— a reasonable choice that differs from another implementation's reasonable
choice is an interoperability failure that surfaces months later.

The known-uncertain areas are listed in `DIRECTORY-SPEC.md` §11.

---

## After a spec amendment: re-audit every package

**Applying a spec patch is not the end of a ruling.** The code that was written
before the amendment does not implement it, and nothing will tell you.

This is not hypothetical. Eighteen amendments landed during phase 2 after five
packages had already been written and committed. Three of them — duplicate JSON
members, leading zeros in `bits`, the draining-instance `429` — were never
implemented. They were found later, by a task that happened to test across a
package boundary. A process that catches this by luck is not a process.

So, after applying **any** batch of spec patches, and before continuing with
feature work:

1. Audit every existing package against every amendment in the batch. Not only
   the packages that look related — the three that were missed were in
   `internal/accept`, `internal/query` and `internal/signal`, and each looked
   like somebody else's problem from the others.
2. Record the audit in the next report as a table: amendment against package
   checked, with the outcome. A table with "no change needed" in most cells is
   the evidence that the audit happened.
3. Only then resume.

The corollary is that a conformance gap found this way is a process failure
worth reporting, not just a bug worth fixing.
