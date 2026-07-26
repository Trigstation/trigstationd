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

## Four constraints that are not negotiable

These are the ones a well-intentioned change breaks by accident.

**1. The code to log request data must not exist.** Not disabled, not behind a
flag, not at debug level — absent. No client address, request path, lookup
prefix, channel identifier or envelope byte may reach any output stream, ever.
CI rejects an import of `log` or `log/slog` anywhere in the tree, several
packages parse their own source for rendering calls applied to
identifier-bearing values, and `silence_test.go` runs the real binary and
asserts it writes nothing beyond its startup banner.

Operator configuration echoed at startup is not request-derived data and may be
printed. A panic value and its stack may be printed, with no request context.
The distinction is in [CLAUDE.md](CLAUDE.md); get it wrong in either direction
and you either leak or you make the service undebuggable.

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

This is not hypothetical: three of eighteen amendments were once missed this
way, and were found by a later task that happened to test across a package
boundary. [CLAUDE.md](CLAUDE.md) has the full note.

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
