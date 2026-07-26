# Phase 2 — storage, the API, and deployment

Status: **complete.** The service runs, is deployable, and has been exercised
end to end against a live binary rather than only in tests.

One spec question is open (§5) and does not block anything shipped.

---

## 1. What was built

| Package | Owns |
|---|---|
| `internal/reject` | The §5.2 and §5.4 status tables, and the normative evaluation order |
| `internal/query` | §5.3 prefix parsing, masking, the bit-length cap |
| `internal/accept` | The §5.2 acceptance pipeline, minus the recency rule |
| `internal/store` | SQLite against the §9 schema; verbatim envelopes, recency, sweep |
| `internal/signal` | In-memory rendezvous; first-write-wins, long-poll, drain |
| `internal/ratelimit` | Per-source limits on a truncated key, retaining no address |
| `internal/clientaddr` | §6.4 trusted-proxy resolution, rightmost `X-Forwarded-For` |
| `internal/api` + `main.go` | The four operations, CORS, config, graceful shutdown |

Plus `Dockerfile`, `docker-compose.yml`, `Caddyfile`, `.dockerignore`,
`.env.example`, `README.md`, and `.github/workflows/ci.yml`.

## 2. Verification

Run, not asserted.

```
$ CGO_ENABLED=0 go build ./...        exit 0
$ CGO_ENABLED=0 go vet ./...          exit 0
$ CGO_ENABLED=0 go test ./... -count=1
ok  .../internal/accept      1.681s      ok  .../internal/ratelimit  0.674s
ok  .../internal/api         4.227s      ok  .../internal/record     1.289s
ok  .../internal/b64         0.582s      ok  .../internal/reject     1.477s
ok  .../internal/clientaddr  1.301s      ok  .../internal/signal     4.416s
ok  .../internal/derive      1.078s      ok  .../internal/store      2.854s
ok  .../internal/pow         0.586s      ok  .../internal/vectors    1.268s
ok  .../internal/query       1.597s
$ gofmt -l .                          (empty)
```

217 passing top-level tests. `-race` passes across the whole tree on
linux/amd64 in a `golang:1.26` container; it cannot run natively here because
the race detector requires cgo and this machine has no working C toolchain for
Go. CI runs it, so it is checked on every push rather than when someone
remembers.

Cross-compile: linux/amd64, linux/arm64, darwin/arm64, windows/amd64 all build
at `CGO_ENABLED=0`. Vectors regenerate byte-identical.

### The live run

The binary was built and exercised, which no amount of unit testing substitutes
for:

- `/v1/meta` returns all seven members with `source_url` populated.
- `/health`, `/healthz`, `/metrics`, `/debug/pprof/`, `/`, `/v1/`, `/v1/stats`
  all `404`.
- CORS present on ordinary responses; `OPTIONS` preflight answered.
- Empty `-source-url` refuses to start and exits `1`.
- A real signed publish → `204`; replay → `409`; lookup returns the envelope
  **byte-for-byte** including a nested unknown member and non-minimal
  whitespace; duplicate member → `400`; padded base64 → `400`.

**Across those requests the process wrote 43 bytes to stderr** — one startup
line, no request data. That is the no-logging invariant demonstrated rather than
claimed.

## 3. Spec questions

Nineteen were raised during phase 2 and eighteen were ruled on and applied. One
remains open, and one new one arrived with the deployment work.

### Open — Q19: `X-Forwarded-For` with more than one proxy (§6.4)

D-24 is exact for a single proxy. With a chain — a CDN in front of nginx — the
rightmost entry is the address the innermost proxy observed, which is the *outer
proxy*, so every client behind the CDN collapses into one limiter key. Following
§6.4 literally reintroduces the outage §6.4 exists to prevent.

```
client → CDN → nginx → trigstationd
arriving XFF:  "1.2.3.4(spoofed), client_real, cdn_egress"
peer:          nginx
rightmost:     cdn_egress   ← one key for every client behind that CDN
```

**Recommendation: walk leftward while entries are themselves inside the trusted
list, stopping at the first that is not.** This strengthens D-24 rather than
contradicting it — an entry is only ever used when everything to its right is
trusted, so the spoofed leftmost value is unreachable unless the operator has
trusted the attacker's own address. It is a strict generalisation: under-
enumerate the hops and it degrades to exactly D-24's present behaviour, useless
but never bypassable. It is also what nginx's `real_ip_recursive` and Caddy's
`trusted_proxies` already do.

Not urgent — the shipped single-Caddy deployment is correct either way — but
operator configuration becomes non-portable if implementations differ, and the
divergence is invisible on the wire because limiter keying is not observable in
a response.

### New — Q20: the spec forbids logging in the directory but is silent about the proxy it mandates

§6.4 and §9 prohibit the directory from emitting client addresses. §9's
deployment story requires a TLS-terminating proxy in front of it. That proxy
sees every client address in the clear, and **the most popular one logs them by
default on the error path** (see §5 below). A conforming implementation shipping
nginx or Traefik would leak by default and still be conforming.

**Recommendation:** extend §6.4's prohibition to the terminating proxy in the
shipped deployment, or add an explicit requirement to §9. This is handled in
this repo's `Caddyfile`, but a rule that only one implementation happens to
follow is not a rule.

## 4. Three conformance gaps, and how they happened

The eighteen spec patches were applied *after* the first five packages were
written, and only the base64 rules were retrofitted at the time. Three
amendments were therefore never implemented, and were found by the HTTP layer's
end-to-end tests rather than by package review.

| Rule | Was | Now |
|---|---|---|
| §5.2 duplicate JSON members rejected | duplicated `"v"` → `204` | `400` |
| §5.3 no leading zeros in `bits` | `?bits=00` → `200` | `400` |
| §5.4 draining instance answers `429` | `GET` → `204` | `429` |

Each was reproduced by measurement before being fixed and re-probed after.

Two details worth keeping. The duplicate-member test covers **every** member
with the value repeated verbatim, because a test written around `expires_at`
alone would have passed with the bug present — Go's last-wins decode tripped the
TTL bound for an unrelated reason. And the shutdown fix reads `s.closed` under
the lock rather than recording which `select` arm fired, so a poll whose
deadline races the shutdown still answers correctly.

**Process lesson worth recording:** amending the spec is not the end of a
ruling. Every already-committed package needs re-auditing against the
amendments, and that step was missed. It was caught here only because a later
task happened to test across the boundary.

## 5. The Caddy error log — a leak in a component with no Go code in it

Caddy's **access** log is off by default. Its **error** log is on, and on any
per-request failure it writes `remote_ip`, `client_ip`, the full URI and the
request headers. A rolling restart of the directory is enough to dump every
current client address into the host's journal.

`log { output discard }` does **not** stop it: the error logger is not the
access logger. Only `exclude http.log.error` does.

Reproduced independently before accepting the finding, with a control:

```
config A  (log { output discard } only)
  request → 502
  "remote_ip":"172.17.0.1"
  "client_ip":"172.17.0.1"
  "uri":"/v1/record?prefix=deadbeef"

config B  (exclude http.log.error, as shipped)
  request → 502
  lines carrying an identifier: 0
```

The leaked URI carries a **lookup prefix**, which `CLAUDE.md` names alongside
client addresses as something that must never be logged. So the naive
configuration leaks precisely what the service exists to avoid leaking, from a
component containing none of the code that prevents it. This is the concrete
instance of Q20.

An earlier attempt at this test produced zero hits for both configurations. That
was a broken harness, not a refutation — Git Bash was rewriting the container
mount path, so Caddy loaded neither config and served its default site.
Recorded because the symmetric result looked like evidence and was not.

## 6. The rate-limiter outage, reproduced with a control

§6.4's reverse-proxy rule was the most serious find of the preflight. It was
verified by A/B rather than reasoning, with `-rate-get 3`:

```
AS SHIPPED  (-trusted-proxies=172.28.0.0/24)
  A: 400 400 400 429       B: 400   ← different /24, unaffected

CONTROL     (that one line deleted)
  A: 400 400 400 429       B: 429   ← different network, refused
                           C: 429   ← and a third
```

That is the outage. The compose network's subnet is pinned rather than allocated
by Docker, because a trusted-proxy list that does not match the network it names
behaves identically to not setting one, and an allocated subnet differs between
machines.

## 7. Judgement calls made without asking

- **`internal/query` owns the §5.3 maths; `internal/store` consumes it.** Both
  packages had independently implemented masking and prefix matching. They
  agreed — cross-checked over 4,000 random prefixes — but two copies of one
  protocol rule is the drift this project exists to prevent, and that hazard does
  not stop at the boundary of a single codebase. Verified by mutation: disabling
  the mask in `query` fails the storage tests.
- **`internal/reject` written rather than delegated.** The status tables are wire
  format and three packages consume them; a table duplicated three ways drifts.
- **`accept`'s padding check removed** once `b64` enforced it, for the same
  one-rule-one-place reason. Its tests stayed.
- **Panic recovered before net/http sees it.** With `ErrorLog` unset, net/http
  prints `http: panic serving <client address>`. The usual remedy needs `log`,
  which is forbidden outright. Discarding a panic value is poor practice in
  general and the right trade against a code path that prints a client address.
- **Response assembled by hand around stored bytes.** `json.RawMessage` does not
  survive `json.Marshal` — verified directly: whitespace compacted, `<`, `>` and
  `&` escaped. The obvious implementation silently breaks §10.
- **Two clock representations.** `store` takes `int64` Unix seconds matching
  `expires_at` and §0.1; `signal` takes `time.Time` matching a 300 s TTL. The
  handler holds both. Not worth churning either package.
- **Timeouts 15 s above the long-poll window.** `ReadTimeout` is the subtle one:
  net/http arms it for the whole request including the handler, so a 30 s value
  would tear down a connection at the moment a long-poll was due to answer.
- **Rate limits** 120/600/600 per hour per truncated key, generous per §6.4's own
  reasoning about CGNAT.
- **Distroless over scratch**, so that `/tmp` exists for SQLite's sort spills —
  on scratch that failure would be an occasional 500 on a wide prefix scan rather
  than a startup error.
- **No health endpoint.** The compose healthcheck uses `GET /v1/meta`.

## 8. Dependencies

`modernc.org/sqlite v1.54.0`, the only direct requirement, per I-2. Nine
indirect requirements, all its transitive closure.

The toolchain floor moved from Go 1.24 to 1.25.0. **Forced, not chosen** — the
driver and two of its dependencies declare it. Ruled: accept it rather than pin
a stale SQLite.

`CGO_ENABLED=0` still produces a working static binary with SQLite linked in,
verified rather than assumed, because this is the constraint the dependency most
plausibly threatened.

## 9. Not done

- **Q19 and Q20** await rulings. Neither blocks anything shipped.
- **Task 8, API-level conformance vectors** — request/response fixtures for the
  §5.2 and §5.4 status tables, so a second implementation can check its handler
  against the spec rather than against this codebase. Optional in the plan, and
  the natural next piece: `testdata/vectors.json` does this for the crypto and
  nothing yet does it for the API.
- **Real ACME issuance is unverified.** Testing used
  `TRIGSTATION_DOMAIN=localhost`, for which Caddy uses its internal CA. The HTTPS
  path, the redirect and the proxying are exercised; issuance against Let's
  Encrypt is not, and cannot be without a public domain.
- **No Postgres.** Optional per §9 and not started.
- **No benchmark for the 20-bit proof of work.** §6.1's "roughly 100 ms" remains
  unverified, carried over from phase 1b.
- **arm64 and a real VPS untested.** The image cross-compiles; it has not run
  anywhere but this machine.
