# Changelog

All notable changes to `trigstationd` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Protocol changes are not code changes.** Where a release changes observable
wire behaviour, the entry names the `DIRECTORY-SPEC.md` section and the
`DECISIONS.md` entry that settled it. The specification lives in
[trigstation/spec](https://github.com/trigstation/spec) and has its own history;
where the two disagree, the specification is right and this is a bug.

<!--
Entries go under: Added, Changed, Deprecated, Removed, Fixed, Security.

Two conventions worth keeping:

  - A change to a test vector is never "just" a code change. Say why the value
    moved and which section required it, because an unexplained vector diff is a
    protocol change wearing a code change as a disguise.
  - Credit reporters by whatever name they ask for, per SECURITY.md.
-->

## [Unreleased]

## [0.1.1] — 2026-07-27

**This is the final release. The project is archived** — see the README for why.
`0.1.1` exists because `0.1.0` was tagged but never completed: its container
image could not be pulled by anyone, and it did not contain `trigcheck`, which
`docs/deploy-check.md` §6 requires. Use this release, not that one.

### What is and is not verified

Stated plainly, because a release that overstates its own testing is worse than
one that says less.

- **The source is tested.** `go vet` and the full suite pass, including a test
  that runs the real binary and asserts it emits nothing beyond its startup
  line, and both sets of conformance vectors reproduce.
- **The container image was pulled and run on a live host, and serves.**
  `ghcr.io/trigstation/trigstationd:0.1.1`, digest
  `sha256:de8368a0b0344c87e11ba55e044923f809782a0995b69ced7eb6d2fcac5e49a7`,
  was pulled anonymously onto a host that had never held it and with no
  registry credentials, and came up **on the first attempt with no
  intervention**. It then served `dir.trigstation.com` over a production Let's
  Encrypt certificate: `/v1/meta` answering `200` with a verified chain, the
  `308` redirect intact, HTTP/3 advertised, and a record published before the
  swap returned byte-for-byte afterwards.
- **The released `trigcheck` binary was downloaded, checksum-verified and
  run against that instance**, following `docs/deploy-check.md` §6 as written.
  It decrypted the record under the derived `RecordKey` and verified the inner
  signature under `ik_pub`. Both released artefacts were therefore confirmed
  together, each against the other, over the public internet.
- **darwin/arm64 and windows/amd64 were compiled and never executed**, on their
  target platforms or anywhere else. Only `linux/amd64` has been run.
- **The release workflow's own smoke test never passed.** It failed on the
  published package being private, which was corrected afterwards by hand; the
  run could not then be re-triggered. The verification above was performed
  manually instead and is the stronger of the two — it used a real host, a real
  certificate and a real record rather than a scratch container — but the
  automated gate is red and saying otherwise would be false.

### Added

- `trigcheck` is now cross-compiled and published alongside `trigstationd`.
  `docs/deploy-check.md` §6 is written around it, and an operator deploying the
  published image has no Go toolchain to build it with.
- The release workflow asserts that the published package is publicly pullable,
  before attempting the pull, so the failure names the fix rather than arriving
  as a bare `unauthorized`. The check uses the registry's anonymous-token
  endpoint: a token is issued without credentials only for a public package.

### Changed

- `docs/deploy-check.md` has now been executed end to end against a real public
  instance and corrected throughout from what happened rather than what was
  expected. It no longer states a memory prerequisite, which was only ever
  needed for compiling on the deployment host; it checks out a release tag
  rather than the default branch; and it explains the three required ports
  separately, since TLS-ALPN-01 means port 80 does not carry the challenge.

## [0.1.0] — 2026-07-27

**Tagged but never released.** The published container image was private and
could not be pulled, and the release did not include `trigcheck`. Superseded by
`0.1.1`; the entry below describes the work, which is unchanged.

### Added

Everything. This is the first release; the entries below are what it contains
rather than a record of change from a previous version.

- The four operations of `DIRECTORY-SPEC.md` §5: `GET /v1/meta`,
  `PUT /v1/record`, `GET /v1/record`, and `POST`/`GET /v1/signal/{channel_id}`.
- Storage against the §9 schema, SQLite by default, with envelopes stored and
  returned byte-for-byte so that §10's additive-change policy works through an
  older directory.
- Per-source rate limiting that retains no address: keys are truncated to `/24`
  and `/64`, held in memory, and discarded with their window (§6.4).
- Trusted-proxy handling for deployment behind a TLS terminator, including the
  right-to-left walk over `X-Forwarded-For` (§6.4).
- Cross-origin support, so browser clients can use a directory at all (§5.5).
- Graceful shutdown that drains long-polls rather than waiting them out.
- **Derivation test vectors** (`testdata/vectors.json`) covering §3.3, §4.1,
  §4.2 and §6.1.
- **API conformance vectors** (`testdata/api-vectors.json`): 82 transport-shaped
  fixtures covering every row of the §5.2, §5.3 and §5.4 status tables, their
  normative evaluation orders, and verbatim storage. Both sets are generated and
  self-checking.
- A Dockerfile, a compose stack with Caddy, and `docs/deploy-check.md`.
- `cmd/trigcheck`, which publishes one record and reads it back. A directory
  should be checkable on its own: requiring a client library to confirm a round
  trip means no directory can be verified until one exists in the operator's
  language. It is a conformance check rather than a client — no epoch fallback
  window, no racing endpoints, no connecting to what it finds, no persisted
  state.

### Security

- The service writes nothing about any request. Enforced four ways rather than
  asserted: CI rejects a logging import anywhere in the tree, several packages
  parse their own source for rendering calls applied to identifier-bearing
  values, `internal/api` permits exactly one function to touch an output stream,
  and a test drives the real binary and asserts it emits nothing beyond its
  startup banner.
- The shipped Caddy configuration disables the **error** log as well as the
  access log. Caddy's error log is on by default and records `remote_ip`,
  `client_ip` and the full request URI — which carries a lookup prefix — on any
  per-request failure. Disabling the access log does not affect it.

  Confirmed by experiment on a public instance rather than by reading: with the
  `exclude` line removed, three `502`s during a rolling restart wrote the
  client's address, the full URI and the lookup prefix three times over.
  Restored, the same three requests wrote nothing. §9.2 and `DECISIONS.md` I-8.
- Container output is captured under a **bounded** driver, 1 MB across 3 files,
  rather than silenced. Silencing satisfies §9.2's letter and defeats it: it
  discards certificate renewal failures, so TLS stops one day with no signal,
  and it makes every `docker compose logs | grep` verification succeed
  vacuously. Enforcement belongs in the components that emit client data, not in
  a driver that cannot tell a certificate error from a request.

[Unreleased]: https://github.com/trigstation/trigstationd/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/trigstation/trigstationd/releases/tag/v0.1.1
[0.1.0]: https://github.com/trigstation/trigstationd/releases/tag/v0.1.0
