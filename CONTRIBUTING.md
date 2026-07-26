# Contributing to trigstationd

This is the reference implementation of the Trigstation directory service. The
protocol lives in a separate repository —
[trigstation/spec](https://github.com/trigstation/spec) — and **where the code
and the specification disagree, the specification is right and this is a bug.**

Protocol questions belong there, not here. A change to observable behaviour
needs a specification change first.

## The Developer Certificate of Origin

Contributions are accepted under the [Developer Certificate of
Origin](https://developercertificate.org/). There is no contributor licence
agreement, and consequently no unilateral relicensing.

Sign off every commit:

```
git commit -s
```

## Before you start

```
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go vet ./...
CGO_ENABLED=0 go test ./... -count=1
gofmt -l .
```

All four must be clean. CI additionally runs `go test ./... -race`, which
requires cgo and therefore cannot run on a machine without a C toolchain — if
you are changing anything concurrent, run it in a container:

```
docker run --rm -v "$PWD:/src" -w /src -e CGO_ENABLED=1 golang:1.26 \
  go test ./... -race -count=1
```

## Non-negotiable constraints

**These are project constraints, not style preferences, and they bind every
contributor.** They used to live in `CLAUDE.md`, which was the wrong home: a
human reading that file could reasonably assume it was addressed to somebody
else. The normative statement is here; `CLAUDE.md` now defers to it.

### The design invariants

From `DIRECTORY-SPEC.md`. A change that breaks one of these is a proposal to
make this a different project, and belongs in the spec repository as an issue
rather than here as a pull request.

1. The directory never carries media. Address records and connection setup only.
2. The directory cannot read what it stores. It holds no decryption key and
   performs no key derivation.
3. No accounts. No users table, no API keys, no allowlist, no CAPTCHA.
4. Records are self-verifying. Authorisation is the signature, not a header.
5. Records expire. Nothing accumulates.
6. Any instance is replaceable. Instances never communicate with each other.
7. The API stays at four operations.

### Four constraints a well-intentioned change breaks by accident

**1. The code to log request data must not exist.** Not disabled, not behind a
flag, not at debug level — absent. No client address, request path, lookup
prefix, channel identifier or envelope byte may reach any output stream, ever.
CI rejects an import of `log` or `log/slog` anywhere in the tree, several
packages parse their own source for rendering calls applied to
identifier-bearing values, and `silence_test.go` runs the real binary and
asserts it writes nothing beyond its startup banner.

The prohibition is on **request-derived data**, not on all output, and the line
matters in both directions — one error leaks, the other makes the service
undebuggable.

*May be printed.* Operator configuration echoed at startup: the bind address,
the database path, the source URL, the configured limits. None of it records
anybody's request. A panic value and its stack may be printed too — a fault in
this program is not a fact about a client, and a directory that fails silently
is one nobody can debug, for no privacy gain.

*May not be printed, ever.* Anything derived from a request, whether or not it
also appears in configuration: a client address, a lookup prefix, a channel
identifier, a request URI, a header value, an envelope byte. The origin of the
value does not matter; what matters is that observing it tells you something
about who was talking to the directory and what they asked for.

`silence_test.go` asserts over *non-banner* output for exactly this reason. Its
first version swept everything and failed on the startup banner, because the
banner contains the bind address — the operator's own configuration, not a
client's address, even though the two are the same kind of value.

**2. `CGO_ENABLED=0` must build, and cross-compile.** The deployment story is a
single static binary produced from one machine, and that is what makes
directories genuinely replaceable. Use `modernc.org/sqlite`, never
`mattn/go-sqlite3`.

**3. Four operations. Not five.** No `/health`, no `/metrics`, no `/debug`, no
admin route. A test enumerates the router and fails on a fifth. If you think the
container needs a health check, use `GET /v1/meta` — it is unauthenticated,
cheap and always present.

**4. `go.mod` stays close to empty.** One direct dependency, the SQLite driver.
Anything else needs justifying against what it replaces.

## After a specification change

**Applying a spec patch is not the end of a ruling.** Code written before the
amendment does not implement it and nothing will tell you. Audit every existing
package against every amendment in the batch, and record the audit as a table of
amendment against package checked.

Audit **every** package, not only the ones that look related: the three
amendments once missed this way were in `internal/accept`, `internal/query` and
`internal/signal`, and each looked like somebody else's problem from the others.
They were found by a later task that happened to test across a package boundary,
which is catching it by luck rather than by process.

A conformance gap found this way is a process failure worth reporting, not just
a bug worth fixing.

## Testing style

- Table-driven, standard library `testing`, no assertion framework.
- **Test the property, not the implementation.** Where a test encodes a
  normative rule, say which section and why — several tests exist to fail if the
  rule is quietly relaxed, and a future reader must be able to tell those from
  incidental coverage.
- **Prove a test can fail.** Where a test guards something important, break the
  thing deliberately, confirm the test catches it, and restore. A test that
  cannot fail reads as coverage while providing none, which is worse than an
  acknowledged gap.
- Where a guard needs an exemption, exempt **by name** and add a second test
  asserting the exempted symbol exists. An exemption that silently widens is
  worse than no guard.

## Test vectors are a deliverable

`testdata/vectors.json` and `testdata/api-vectors.json` are what let a second
implementation exist. Both are generated and self-checking, and CI fails if a
committed file no longer matches what the generator produces.

If you change anything touching a derivation, a signing input, a status table or
the evaluation order, regenerate:

```
go run ./cmd/gen-vectors      -o testdata/vectors.json
go run ./cmd/gen-api-vectors  -o testdata/api-vectors.json
```

and say in the pull request **why** a value changed. An unexplained vector diff
is a protocol change wearing a code change as a disguise.

## Code of conduct

There isn't one yet, and that is deliberate rather than an oversight:
governance documents for a community that does not exist are overhead nobody
benefits from.

The trigger is recorded so the decision is not simply forgotten. The Contributor
Covenant goes in when the first outside contribution lands, or when the project
is linked somewhere public with a discussion attached — whichever comes first.
Until then, the standard is ordinary professional courtesy.

## Licence headers

Every `.go` file carries an SPDX header; `main.go` carries the full notice. CI
enforces it. This is a licence obligation so the terms travel if a file is
copied out of the repo, not tidying.

```go
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Simon Wright
```

## Style

NZ/British spelling in comments, documentation and user-facing strings;
identifiers follow Go convention. Costs in NZ dollars. Errors returned, not
logged and swallowed. Prefer clarity over cleverness — design goal 3 is that
someone can reimplement this from the specification in a weekend, and this
codebase is meant to be the worked example.
