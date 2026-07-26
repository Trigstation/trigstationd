# Phase 2 — preflight review

Status: **blocked pending decisions.** No phase 2 code written.

This is a fresh-eyes pass over `DIRECTORY-SPEC.md`, `PAIRING-SPEC.md` and
`DECISIONS.md` before storage and the API are built, as instructed. Eight items
need a ruling; five more are editorial and can be applied without one.

---

## 1. Current state of the tree, verified

Verified by reading the tree, not by trusting the brief.

### What exists

```
CLAUDE.md
DECISIONS.md
spec/DIRECTORY-SPEC.md
spec/PAIRING-SPEC.md
spec/LICENSE-CC0-1.0.txt
trigstationd/
  main.go                      stub; prints to stderr and exits 1
  go.mod                       module .../trigstationd, go 1.24, no require block
  LICENSE                      STUB — full text in LICENSE-AGPL-3.0.txt
  LICENSE-AGPL-3.0.txt
  .gitignore
  cmd/gen-vectors/main.go
  internal/b64/                Encode, Decode, DecodeFixed
  internal/derive/             Epoch, EpochStart, WriteSeed, RecordKey, MailboxID,
                               WriteKey, LookupID + Pair* variants
  internal/pow/                Prefix, Input, LeadingZeroBits, Verify, Solve
  internal/record/             CanonicalEnvelope, Envelope/Decoded/Sign/Verify,
                               Seal/SealWithNonce/Open,
                               MarshalPlaintext/ParsePlaintext/VerifyPayload
  internal/vectors/            generator + self-check
  testdata/vectors.json        4 epoch rows, 3 pairing rows, envelope, pow
  docs/reports/phase-1b.md
```

### Verification actually run

```
$ go version
go version go1.26.5 windows/amd64

$ CGO_ENABLED=0 go build ./...      exit 0
$ CGO_ENABLED=0 go vet ./...        exit 0
$ CGO_ENABLED=0 go test ./... -count=1
?   github.com/trigstation/trigstationd                  [no test files]
?   github.com/trigstation/trigstationd/cmd/gen-vectors  [no test files]
ok  github.com/trigstation/trigstationd/internal/b64      1.066s
ok  github.com/trigstation/trigstationd/internal/derive   1.146s
ok  github.com/trigstation/trigstationd/internal/pow      1.110s
ok  github.com/trigstation/trigstationd/internal/record   1.281s
ok  github.com/trigstation/trigstationd/internal/vectors  1.257s
                                    exit 0
$ gofmt -l .                        (empty)
```

Constraint audit, re-run rather than inherited:

- **Logging:** zero imports of `log` or `log/slog`; zero `log.`/`slog.` call sites.
  The single grep hit is the word "log" inside a comment in `b64/base64url.go:47`.
  Four `fmt.Fprint*` calls exist, all to stderr, none on a request path (there is
  no request path). Clean.
- **Dependencies:** `go.mod` has no `require` block. Standard library only.
- **CGO:** builds clean at `CGO_ENABLED=0`.
- **Licence headers:** all 15 `.go` files carry either the full notice
  (`main.go`) or the SPDX short form. No misses.
- **Endpoints:** zero. No `net/http` import anywhere.

### Spec reconciliation confirmed

All nine items raised in phase 1b are now settled in the spec text — I checked
each against the current file rather than taking the report's word:

| Phase 1b item | Now in spec |
|---|---|
| #1 closed plaintext framing | §4.2, "The plaintext is a closed framing" |
| #2 expired record is absent | §5.2, "treated as absent for every purpose" |
| #3 cap on true vs advertised count | §5.1, "computed against the **true** count" |
| #4 mask, don't reject padding bits | §5.3, "MUST mask and ignore them" |
| #5 `body_len` uint16 rationale | §4.2, "size buffers from the envelope limit" |
| E1 detached sixth condition | §5.2 list is contiguous |
| E2 `~50` in threat model | §8, now "between `k` and `2k`, ~50–100" |
| E3 dangling `README-LICENSING.md` | citation removed |
| E4 vestigial `ts` row | removed from §0.1 |

I also checked the arithmetic behind §5.1's claim that a conforming client can
never trip the server-side cap. It holds: the client takes
`floor(log2(advertised/50))`, the directory caps at `floor(log2(true/20))`,
`advertised ≤ true`, and `50 > 20`, so the client's value is always the smaller.
Good — but see item D, which is the case where it breaks.

### Tree-level problems

1. **There is no git repository.** `git rev-parse` fails; no `.git` anywhere
   under `c:\Projects\trigstation`. The brief instructs me to commit as I go with
   `git commit -s`. I cannot. Needs `git init` and a decision on whether the spec
   and the implementation share one repo or are two (the brief refers to "the
   `/spec` repo", suggesting two, but they are currently one directory tree).
   **Blocking for the commit instruction, not for the code.**
2. **`docs/reports/phase-1.md` does not exist.** Only `phase-1b.md`. The brief
   said to read both. Phase 1b summarises phase 1's outcomes adequately, so I do
   not think anything is lost, but the record has a hole in it.
3. **`claude-code-phase2.md` does not exist.** I am working from the fallback
   scope in the brief.
4. **`LICENSE` is still a stub.** Deliberate per phase 1b §8, but it should be
   filled before anything is published, and it costs nothing to do now.

---

## 2. Spec ambiguities requiring a ruling

Eight. Items A–C are hard blockers: I cannot write the storage layer or any
handler without them. D–H are needed before the corresponding handler.

Each gives the section, what is underspecified, what breaks on divergence, my
recommendation, and a concrete patch.

---

### A. §5.2 — no mapping from rejection condition to status code

**Underspecified.** §5.2 lists six rejection conditions and separately lists six
status codes, and binds only one pair (recency → `409`). Three conditions have no
clear code:

- `expires_at` in the past — `400`, `403` or `409`?
- `expires_at` beyond `max_ttl` — `400` or `403`?
- `pow` insufficient — `403` ("verification failed") or `400`?

There is also no evaluation order, so a request that violates several conditions
gets a different code from different directories even if both agree on the
per-condition mapping.

**What breaks.** This is the item most likely to cause a real field failure. A
publishing server's retry logic is driven entirely by the status code: `400`
means "my request is wrong, do not retry"; `409` means "republish with a later
expiry"; `429` means "back off". A server that receives `400` from directory X
and `409` from directory Y for the identical envelope will either give up on a
recoverable condition or hot-loop on an unrecoverable one. Neither directory is
non-conforming, which is the worst kind of divergence.

**Recommendation.** Bind every condition, and fix the evaluation order.

On the two contested cases:

- **`expires_at` in the past → `409`, not `400`.** It is the same class of
  failure as the recency rule and has the identical remedy: republish with a
  later expiry. Grouping them means a publisher needs one branch, not two.
- **`expires_at` beyond `max_ttl` → `400`.** This is a well-formed request asking
  for something the instance does not offer. The remedy is different — reduce the
  configured TTL and re-solve — so it should not share a code with "stale".

On order: cheapest first, and side-effect-free throughout. Note this puts the two
SHA-256 checks before the Ed25519 verification, which is deliberate — an
Ed25519 verify is roughly two orders of magnitude more expensive than a SHA-256,
and a flooder should be rejected on the cheap check.

**Patch — `spec/DIRECTORY-SPEC.md` §5.2:**

```diff
-Responses: `204` on success, `400` malformed, `403` verification failed,
-`409` stale or replayed, `413` too large, `429` rate limited.
+**Response codes.** Every rejection condition binds to exactly one code:
+
+| Condition | Code |
+|---|---|
+| Accepted and stored | `204` |
+| Rate limited | `429` |
+| Received body exceeds `max_record_bytes` | `413` |
+| Body is not well-formed JSON, a required member is absent, a value is not valid unpadded base64url, or a fixed-width field decodes to the wrong length | `400` |
+| `v` is not `1` | `400` |
+| `expires_at` exceeds `now + max_ttl` | `400` |
+| `lookup_id` is not `SHA-256(wk_pub)` | `403` |
+| `pow` does not satisfy `pow_bits` | `403` |
+| `sig` does not verify under `wk_pub` | `403` |
+| `expires_at` is not strictly greater than the directory's current time | `409` |
+| `expires_at` is not strictly greater than that of an unexpired stored record under the same `lookup_id` | `409` |
+
+**The conditions MUST be evaluated in the order of that table**, and the
+directory MUST return the code of the first condition that fails. Without a
+fixed order, a request violating two conditions receives a different code from
+different directories, and a publisher's retry logic — which is driven entirely
+by the code — diverges accordingly. The order is also cheapest-first: the two
+SHA-256 checks precede the Ed25519 verification, which is roughly two orders of
+magnitude more expensive, so a flooding client is rejected on the cheap check.
+
+A stale `expires_at` and a violated recency rule share `409` because they share
+a remedy — republish with a later expiry. An over-long TTL is `400` because its
+remedy is different: reduce the configured TTL and re-solve the proof of work.
+
+Response bodies carry no diagnostic detail. The code is the whole answer.
```

---

### B. §5.2 / §5.3 / §10 — are stored envelopes returned verbatim or re-serialised?

**Underspecified.** §10 requires unknown fields to be ignored, never rejected.
§5.3 returns `{ "records": [ { …envelope… } ] }`. Nothing says whether that
envelope is the bytes the directory received or a fresh serialisation of the
fields it parsed.

**What breaks.** §10's additive-change policy is the entire forward-compatibility
story, and this decides whether it works. Suppose v1.1 adds an optional
fixed-width envelope field (permitted by §4.1, inserted before `ct`). A server
and client both understand it; the directory between them does not. If the
directory re-serialises from parsed known fields, the new field is silently
dropped and the pair cannot use that directory as a transport — with no error
anywhere. If the directory stores and returns bytes, the field passes through and
§10 works as advertised.

It also decides the storage schema, which is the first thing I need to build:
verbatim means one `BLOB` of received bytes plus denormalised index columns,
which is what §9 already looks like.

**Recommendation.** Verbatim, stated explicitly. It is simpler, strictly more
forward-compatible, and matches the §9 schema's shape. The alternative —
"preserve unknown members" via a map — permits re-serialisation but requires
every implementation to get unknown-member round-tripping right in its own JSON
library, which is exactly the class of thing that differs across languages.

**Patch — `spec/DIRECTORY-SPEC.md` §5.2, after "On success, the record replaces…":**

```diff
+**Envelopes are stored and returned verbatim.** A directory MUST retain the
+envelope as the byte sequence it received, and MUST reproduce those bytes
+unchanged in §5.3 responses. It MUST NOT re-serialise the envelope from the
+fields it parsed. It MAY additionally parse fields into separate storage for
+indexing, but the representation it returns is the stored bytes.
+
+This is what makes the additive-change policy of §10 work in practice. An
+envelope may carry a field introduced after the directory was written; a
+directory that re-serialised from known fields would strip it silently, so a
+server and client both running a later revision could not use an older directory
+as a transport, and nothing would report an error.
```

**And in §5.3, after the JSON example:**

```diff
+Each element of `records` is the stored envelope reproduced byte-for-byte per
+§5.2. A directory with no matching records returns `200` with an empty
+`records` array, never `404`.
```

---

### C. §5.4 — signal channels have no status codes at all

**Underspecified.** §5.4 specifies `409` on second write and nothing else. Not
specified: the success code for `POST`; what a `GET` returns when the long-poll
elapses with no blob; the content type of a `GET` response; the response to a
malformed `channel_id`; the response to an over-size body; and what a directory
advertising `"signal": false` returns.

**What breaks.** The long-poll timeout is the sharp one. The client's correct
behaviour on "nothing arrived yet" is to poll again immediately; its correct
behaviour on "this instance does not do signal channels" is to move to another
directory. If timeout is signalled with `404`, those two are indistinguishable
and a device-pairing client will either hammer a directory that will never answer
or abandon a working one. `PAIRING-SPEC.md` §6.3 has both devices polling
channels as its normal path, so this is the common case.

**Recommendation.** `204` on timeout, `404` for an instance without signal
support. `204` is unambiguous — the request succeeded and there is nothing there.

**Patch — `spec/DIRECTORY-SPEC.md` §5.4, replacing the two bullets:**

```diff
 - `POST /v1/signal/{channel_id}` — body is an opaque blob. Stored until its TTL
   expires. **First write wins**: a POST to a channel that already holds an
   unexpired blob MUST be rejected with `409`.
 - `GET /v1/signal/{channel_id}` — returns the blob, or long-polls up to 30
   seconds for one to appear. Deletes on read.
+
+| Operation | Outcome | Code |
+|---|---|---|
+| `POST` | Stored | `204` |
+| `POST` | `channel_id` is not exactly 32 bytes of unpadded base64url | `400` |
+| `POST` | Body exceeds the §4.3 signal channel payload limit | `413` |
+| `POST` | Channel already holds an unexpired blob | `409` |
+| `GET` | Blob present, or one arrived within the long-poll window | `200` |
+| `GET` | Long-poll window elapsed with no blob | `204` |
+| `GET` | `channel_id` is not exactly 32 bytes of unpadded base64url | `400` |
+| either | Rate limited | `429` |
+| either | Instance advertises `"signal": false` | `404` |
+
+A `GET` that times out returns `204`, not `404`. The client's correct response
+to `204` is to poll again; its correct response to `404` is to try a different
+directory. Conflating them means a client either hammers an instance that will
+never answer or abandons one that would have.
+
+A `200` response carries `Content-Type: application/octet-stream`. The directory
+MUST NOT interpret the body, so it MUST NOT claim a type for it.
+
+A directory MUST NOT hold a long-poll open for longer than 30 seconds, and
+SHOULD hold it for the full 30 unless a blob arrives or the client disconnects.
+Clients MUST tolerate an earlier `204`.
```

---

### D. §5.3 — the `bits` cap is undefined at small record counts

**Underspecified.** §5.3 says directories MUST enforce a maximum `bits`,
RECOMMENDED "such that the expected result set is never below 20". Written as a
formula that is `floor(log2(record_count / 20))`, which is **negative below 20
records and undefined at zero**. §5.3 gives the *client* formula a `max(0, …)`
clamp but gives the cap none.

Three smaller gaps in the same query parsing:

1. **Is `bits` required?** The section heading is `GET /v1/record?prefix=<hex>`
   with no `bits`; the example is `?prefix=a3f&bits=11`. A directory must know
   whether to default `bits = 4 × len(prefix)` or reject.
2. **Is hex case-sensitive?** Unspecified. One implementation will reject `A3F`.
3. **What does `bits=0` look like on the wire?** `ceil(0/4) = 0` hex characters,
   so `prefix` is the empty string — is that `?prefix=&bits=0`, or `prefix`
   omitted, or `400`?

**What breaks.** A brand-new directory has zero records. Every conforming client
computes `bits = max(0, floor(log2(0/50))) = 0` and sends the `bits=0` query. A
directory that computed an unclamped cap rejects it with `400`, so a fresh
directory rejects every lookup it ever receives until it passes 20 records — and
it cannot pass 20 records, because publishing works but nobody can find anything.
This is a cold-start failure that will hit the project's own first instance.

**Also worth naming:** at `bits=0` the directory returns its entire table, which
§1 disclaims ("Search, discover or enumerate. There is no 'list all servers'
operation"). That is inherent rather than fixable — an instance too small to
offer an anonymity set cannot offer one — but the two sections currently
contradict each other and a reader deserves the sentence.

**Recommendation.** Clamp the cap at 0, require `bits`, accept either hex case,
accept both spellings of the empty prefix, and state the small-instance
consequence.

**Patch — `spec/DIRECTORY-SPEC.md` §5.3:**

```diff
-Directories MUST enforce a maximum `bits` (RECOMMENDED: such that the expected
-result set is never below 20) and reject over-precise queries with `400`.
+Directories MUST enforce a maximum `bits` and reject over-precise queries with
+`400`. RECOMMENDED, with `k_min = 20`:
+
+```
+bits_max = max(0, floor(log2(record_count / k_min)))
+```
+
+computed against the **true** record count, per §5.1. **The `max(0, …)` clamp is
+required, not cosmetic.** Below `k_min` records the unclamped expression is
+negative, and at zero records it is undefined — so a directory that omitted the
+clamp would reject the `bits=0` query that every conforming client sends to a
+new instance, and would go on rejecting every lookup it ever received, because
+it could never accumulate records that nobody could find.
+
+A consequence worth stating plainly: an instance holding fewer than `2 × k_min`
+records returns most or all of its table to any query. That is not a violation
+of §1's "no enumerate" so much as its limit — an instance too small to provide
+an anonymity set cannot provide one. It resolves as the instance grows, and in
+the meantime clients querying several directories (§7) are what preserves the
+guarantee.
+
+**Query parameter handling.**
+
+- `bits` is REQUIRED. A directory MUST NOT infer it from the length of
+  `prefix`, and MUST reject a query without it with `400`.
+- `prefix` is hex, case-insensitive. Directories MUST accept both `a3f` and
+  `A3F`, and MUST reject any character outside `[0-9a-fA-F]` with `400`.
+- When `bits` is `0`, `prefix` is the empty string. A directory MUST accept
+  both `?prefix=&bits=0` and `?bits=0` with `prefix` absent.
```

---

### E. §0 / §5.2 — the reserved media type has no defined use

**Underspecified.** §0 reserves `application/vnd.trigstation.record+json` as the
"Record media type". No other section mentions it. So it is unclear whether a
`PUT /v1/record` must send it, whether a directory may reject a request that does
not, and what `GET /v1/record` responds with.

**What breaks.** A directory that enforces the media type rejects every client
that sends `application/json`, and vice versa nothing goes wrong. So the risk is
one-sided but real. It also interacts with item H: a non-standard `Content-Type`
forces a CORS preflight from a browser even on requests that would otherwise
avoid one.

**Recommendation.** Define it as SHOULD-send, MUST-NOT-reject. The body is fully
validated regardless, so rejecting on the header buys nothing.

**Patch — `spec/DIRECTORY-SPEC.md` §5.2, after "Body: an envelope (§4.1)":**

```diff
+A publisher SHOULD send `Content-Type: application/vnd.trigstation.record+json`.
+A directory MUST NOT reject a request on the basis of its `Content-Type`:
+`application/json`, an unrecognised value and an absent header are all
+acceptable. The body is validated in full either way, so rejecting on the header
+gains nothing and costs interoperability with constrained clients — notably
+browsers, for which a non-standard content type forces a CORS preflight.
+
+`GET /v1/record` responds with `Content-Type: application/json`.
```

---

### F. §6.2 — per-source rate limiting versus the no-logging invariant

**Underspecified.** §6.2 requires "Per-source-IP rate limits on `PUT` and `GET`".
§1 says the service does not "Persist logs, request history or client IP
addresses". `DECISIONS.md` I-3 and `CLAUDE.md` go further: the code to log client
IP addresses **must not exist**.

A rate limiter must hold something derived from the source address in memory for
the duration of a window. The spec never says what is permitted. This is the one
point where two invariants meet, and it is currently resolved nowhere.

**What breaks.** Less about interoperability than about the property that makes
the service credible. An operator who says "we do not retain IP addresses" while
running a limiter with a one-hour window keyed by full address is, under a
sufficiently determined reading, retaining IP addresses. The distinction between
that and a logging directory should be written down rather than assumed.

Hashing the address is not a defence worth having: IPv4 is a 32-bit space and a
hash of it is reversed by enumeration in seconds. Truncation genuinely destroys
information.

**Recommendation.** State the constraint in the spec. Truncate rather than hash.
Name the trade-off honestly: an IPv4 `/24` key means up to ~256 hosts share a
bucket, so a noisy neighbour behind CGNAT can rate-limit an innocent server —
which is acceptable only because publish volume per server is around one per day,
so limits can be set generously enough that it rarely bites.

The concrete limit values are an implementation matter and I will pick them
without asking; the truncation granularity is observable to clients and belongs
in the spec.

**Patch — `spec/DIRECTORY-SPEC.md` §6.2, replacing the first bullet:**

```diff
-- Per-source-IP rate limits on `PUT` and `GET`.
+- Per-source rate limits on `PUT` and `GET`, subject to §6.4.
```

**And a new §6.4:**

```diff
+### 6.4 Rate limiting without retaining addresses
+
+Rate limiting is the only point in the service that handles a client address at
+all, and it sits directly against the requirement that the directory does not
+retain them. The following constraints resolve that, and a conforming directory
+MUST meet all of them:
+
+- The source address MUST NOT be written to disk, to a log, or to any output
+  stream, at any severity, under any configuration.
+- Limiter state MUST be held in memory only and MUST be discarded when its
+  window elapses.
+- The state MUST be keyed by a **truncated** form of the address — IPv4 to `/24`
+  and IPv6 to `/64` — not by the full address and not by a hash of it. A hash is
+  not a mitigation: the IPv4 space is 32 bits and any hash of it is reversed by
+  enumeration in seconds. Truncation destroys information; hashing only obscures
+  it.
+- No code path may exist that emits either the key or the untruncated address.
+
+The cost is real and should be stated: an IPv4 `/24` key means up to 256 hosts
+share a bucket, so a host behind carrier-grade NAT can be limited by the
+behaviour of a stranger. This is tolerable only because publish volume is around
+one request per server per day (§9.1), so limits can be set well above honest
+use. Directories SHOULD set them accordingly rather than tightly.
+
+A directory that cannot rate limit under these constraints does not rate limit.
+Abuse resistance is a defence; the inability to produce records is the property
+the service exists to have.
```

---

### G. §5.2 — `max_ttl` has no clock-skew allowance

**Underspecified.** `expires_at` must be "in the future and within `max_ttl`",
both evaluated against the directory's clock. A server computes `expires_at` from
its own. Nothing addresses the gap.

**What breaks.** A server configured to use the full advertised `max_ttl` and
whose clock is 20 seconds ahead of the directory's sends `expires_at` = its
`now + 48h`, which exceeds the directory's `now + 48h`, and is rejected. Under
item A that is a `400` with no diagnostic body, so the operator sees a directory
that rejects everything for no visible reason. Neither party can observe the
other's clock. This will happen in the field to anyone who configures the maximum,
which is the natural thing to configure.

**Recommendation.** Headroom on the server, grace on the directory. Both, because
either alone leaves the other's implementer able to produce the failure.

**Patch — `spec/DIRECTORY-SPEC.md` §5.2, after the `max_record_bytes` paragraph:**

```diff
+**Clock skew on the TTL bound.** `expires_at` is evaluated against the
+directory's clock and computed from the publisher's. A server that requests
+exactly `max_ttl` is rejected by any directory whose clock is behind its own,
+and neither party can observe the other's. Servers SHOULD therefore leave
+headroom — RECOMMENDED: request no more than `max_ttl` minus 300 seconds — and
+directories SHOULD allow a grace of 300 seconds above `max_ttl` before
+rejecting. Both, not either: one alone still permits the failure, which presents
+as a directory rejecting every publish for no visible reason.
```

---

### H. §5 — nothing about cross-origin access, though browsers are a named target

**Underspecified.** §4.4 discusses WebCrypto support in browsers at length and
treats the browser as a target platform. The API section says nothing about CORS.

**What breaks.** A browser client cannot call `GET /v1/record` cross-origin
without `Access-Control-Allow-Origin`, and cannot call `PUT /v1/record` or
`POST /v1/signal/…` at all without an `OPTIONS` preflight being answered. Not a
subtle degradation — the request never leaves the browser. So either browsers are
not actually a target, or every directory needs this and none of them will
implement it consistently by accident.

**Recommendation.** Require it. It is safe here in a way it is not for most
services, because there is no ambient authority to confuse: no cookies, no
credentials, no session. A cross-origin caller can do nothing a direct caller
cannot.

I want to be explicit that `OPTIONS` is not a fifth operation, because invariant
7 in `CLAUDE.md` is absolute and someone will otherwise read this as a breach of
it. It is HTTP transport mechanics for the four operations that exist.

**Patch — `spec/DIRECTORY-SPEC.md`, new subsection at the end of §5:**

```diff
+### 5.5 Cross-origin access
+
+§4.4 names the browser as a target platform, so a directory MUST be usable from
+one. Directories MUST send `Access-Control-Allow-Origin: *` on every `/v1/`
+response, and MUST answer `OPTIONS` preflight requests for `PUT /v1/record` and
+`POST /v1/signal/{channel_id}` with an appropriate `Access-Control-Allow-Methods`
+and `Access-Control-Allow-Headers: Content-Type`.
+
+A wildcard origin is safe here in a way it is not for most services, because the
+API carries no ambient authority: there are no cookies, no credentials and no
+session, and every write is authorised by a signature carried in the body.
+A cross-origin caller can therefore do nothing a direct caller cannot.
+`Access-Control-Allow-Credentials` MUST NOT be sent.
+
+`OPTIONS` is HTTP transport mechanics for the four operations of §5. It is not a
+fifth operation and does not bear on the constraint in §10.
```

---

## 3. Spec errors and contradictions

Five. None needs a ruling; I will apply them on your word alone, or leave them if
you would rather they went in with a batch.

### E1 — `DIRECTORY-SPEC.md` §11.2 and `PAIRING-SPEC.md` §9 disagree on epoch fallback

§11 open question 2: *"Clients currently query the current epoch and fall back to
the previous one."*

`PAIRING-SPEC.md` §9 failure table: *"Clock skew on client | Try current epoch,
then previous, then next. Fail if all three miss."*

Two epochs versus three. `CLAUDE.md`'s testing section says "clock skew fallback
to the previous epoch", agreeing with the directory spec. `DECISIONS.md` leaves it
open.

**Not a phase 2 blocker** — the directory performs no epoch computation
whatsoever; it never derives a key. This is entirely client-side. But it is a
contradiction between two specs that a client implementer must resolve, and the
"next" epoch case is not obviously wrong: a server whose clock is *ahead*
publishes under tomorrow's `LookupID`, and only a client that tries the next
epoch will find it.

Recommend settling it as three epochs (previous, current, next) in both documents
— it costs two extra parallel queries on a path that runs once per session, and
it makes the failure symmetric with respect to which party's clock is wrong. This
overlaps `DECISIONS.md` still-open item 2, so it may be one you want to take
properly rather than by amendment.

### E2 — §4.3's "Records per `lookup_id`: 1 (overwrite)" predates D-6

The limits table says `1 (overwrite)`. §5.2 and `DECISIONS.md` D-6 make it a
*conditional* overwrite: strictly-newer or `409`. A reader who takes §4.3 at face
value implements plain last-write-wins and reintroduces exactly the replay the
recency rule exists to prevent.

```diff
-| Records per `lookup_id` | 1 (overwrite) |
+| Records per `lookup_id` | 1 (conditional overwrite, §5.2) |
```

### E3 — §9's `body` column collides with §4.2's `body`

The §9 schema has `body BLOB NOT NULL`. In §4.2, `body` is the JSON object inside
the payload plaintext — the one thing a directory can never see. The schema
column is presumably the whole received envelope. Since §9 is the one normative
schema in the document, the collision is worth removing.

```diff
 CREATE TABLE records (
   lookup_id  BLOB PRIMARY KEY,
   prefix     INTEGER NOT NULL,
   wk_pub     BLOB NOT NULL,
   expires_at INTEGER NOT NULL,
-  body       BLOB NOT NULL
+  envelope   BLOB NOT NULL   -- the received envelope, verbatim (§5.2)
 );
```

Renaming a column in the reference schema is not a wire-format change and no
deployed instance exists, but flagging rather than assuming.

### E4 — §4.1 does not say what to do with `v` ≠ 1

`v` is in the envelope and in the signing input as one byte. §10 says the `v`
field pins the format. A directory receiving `v: 2` on a `/v1/` path — reject, or
ignore-unknown per §10? Covered by my item A patch (`400`), but §4.1 should say
so too. Low risk; nobody is shipping v2.

### E5 — `/v1/meta` does not say which members are mandatory

If `record_count` may be omitted, a client cannot size its prefix. Recommend
stating that all seven members are REQUIRED. Note that `DECISIONS.md` still-open
item 3 contemplates removing `record_count` in favour of `recommended_bits`, so
this may be worth deciding together with that rather than pinning it now.

---

## 4. Judgement calls made without asking

Structural only, recorded per the brief rather than raised.

- Report filed as `phase-2-preflight.md` rather than `phase-2.md`, so the phase 2
  report can be what it says it is.
- The spec patches above are drafted against `spec/DIRECTORY-SPEC.md` in place. I
  have applied none of them.
- Nothing else. No phase 2 code exists to have made calls about.

---

## 5. Proposed sub-agent breakdown for phase 2

Eight tasks. Tasks 1–5 are independent of each other and can run concurrently
once the rulings land; 6 depends on all of them; 7 depends on 6; 8 is optional.

Every brief will carry, verbatim: the governing spec sections; the four standing
constraints (no logging code, `CGO_ENABLED=0`, standard library only beyond
`modernc.org/sqlite`, no fifth endpoint); the SPDX header requirement; NZ/British
spelling; and the instruction to **stop and report rather than resolve** anything
the spec does not settle.

### 1. SQLite storage layer
**Spec:** §9 schema, §5.2 (expiry-as-absent, recency, verbatim storage), §4.3.
**Scope:** open/create, `Put`, `GetByPrefixRange`, `Sweep`, `Count`. No HTTP.
**Done:** tests over a temp DB covering — insert and read back byte-identical;
recency rule accepts strictly-newer and rejects equal and older; an expired
record is absent from lookups *and* does not set a recency floor; sweep removes
only expired rows and changes no observable behaviour either side of running;
prefix range scan at `bits` = 0, 1, 4, 10, 12, 32 and above 32; `prefix` column
values above 2³¹ round-trip correctly. `CGO_ENABLED=0 go build` clean with
`modernc.org/sqlite` as the sole new requirement, and the driver name is
`sqlite`, not `sqlite3`.
**Blocked on:** B.

### 2. Envelope acceptance pipeline
**Spec:** §4.1, §5.2, §6.1, §4.3.
**Scope:** one pure function, raw bytes + clock + instance limits → accept or a
rejection code. No HTTP, no storage, no I/O.
**Done:** table test with at least one case per row of the §5.2 status table, a
case violating three conditions at once asserting the first-in-order code, and a
case at each boundary of the TTL grace. No error value produced by this package
may contain a `lookup_id`, `wk_pub`, `ct` or address — asserted by a test, not by
inspection.
**Blocked on:** A, G.

### 3. Prefix query parsing and bit maths
**Spec:** §5.3, §5.1.
**Scope:** parse and validate `prefix`/`bits`, mask the unused low bits, compute
the cap, produce the inclusive range for the index scan. No HTTP.
**Done:** table test covering — non-multiple-of-four `bits` with non-zero padding
accepted and masked; wrong hex length rejected; uppercase accepted; missing
`bits` rejected; both spellings of the empty prefix at `bits=0` accepted;
over-precise rejected; cap at record counts 0, 1, 19, 20, 39, 40, 100000; and an
assertion that a client following §5.3 with `k=50` never exceeds the cap, across
a sweep of counts.
**Blocked on:** D.

### 4. Signal channel store
**Spec:** §5.4, §4.3, `PAIRING-SPEC.md` §6.3.
**Scope:** in-memory store, first-write-wins, 300 s TTL, 64 KB cap, long-poll
with `context` cancellation, delete-on-read, bounded concurrent waiters, drain on
shutdown. No HTTP.
**Done:** tests for — first write wins and second returns conflict; TTL expiry
frees the channel; a long-poll receives a blob posted after it began; a long-poll
returns empty at the deadline; cancelling the caller's context releases the
waiter promptly; two concurrent `GET`s on one blob deliver to exactly one;
goroutine count returns to baseline after all cases; shutdown completes while a
long-poll is open. Waiter cap enforced.
**Blocked on:** C.

### 5. Rate limiter
**Spec:** §6.2 and the proposed §6.4.
**Scope:** in-memory, truncated-key, window-evicting limiter. Standard library
only — explicitly no third-party limiter, since the common ones log.
**Done:** tests for limit enforcement, window rollover, eviction of idle keys,
IPv4 `/24` and IPv6 `/64` truncation including the mapped-IPv4 case; plus a test
that greps the package's own source for `log`, `slog` and `%v`-of-key patterns
and fails on a hit. Limit values are my call and will be recorded in the phase 2
report, not asked about.
**Blocked on:** F.

### 6. HTTP handlers, server, config
**Spec:** all of §5, plus proposed §5.5.
**Scope:** the four operations, CORS, config via flags and environment, graceful
shutdown that drains long-polls, plain HTTP with TLS terminated upstream.
**Done:** `httptest` end-to-end coverage of every row of both status tables;
`GET /v1/record` returns stored bytes byte-identically; `/v1/meta` carries
`source_url` populated and non-empty, asserted by a test that fails on empty;
shutdown completes within a bounded time with a long-poll open; a test asserting
the router exposes exactly four paths plus `OPTIONS`. Full-tree audit for logging
re-run.
**Blocked on:** 1–5, and A–H.

### 7. Deployment
**Spec:** §9's "set a domain, get a certificate, run".
**Scope:** Dockerfile (static binary, scratch or distroless), `docker-compose.yml`
with Caddy terminating TLS, `README.md` deployment section.
**Done:** `docker build` succeeds and the image runs; `docker compose config`
validates; the image contains no shell and no CA bundle it does not need;
documented as three commands.
**Blocked on:** 6.

### 8. API-level conformance vectors — optional
**Scope:** request/response fixtures for the §5.2 and §5.4 status tables, so a
second implementation can check its handler against the spec rather than against
this codebase, in the same spirit as `testdata/vectors.json`.
**Done:** committed JSON, self-checking in a test, README section on consuming
them.
**Blocked on:** 6.

---

## 6. Dependencies added

None yet. `modernc.org/sqlite` will be the first and only, in task 1.

---

## 7. Not done

- All of phase 2. Nothing started, by instruction.
- No spec patch applied. All eight are drafted above and await a ruling.
- Git repository not initialised, so nothing is committed. See §1.
- `LICENSE` still a stub.
