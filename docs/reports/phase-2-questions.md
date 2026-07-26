# Phase 2 — accumulated spec questions

Status: **six packages built and committed. Eighteen spec questions need a
ruling before the handler is written.**

This is a mid-phase stop, not a phase boundary. Tasks 1–5 are done and committed; task 6 (the
HTTP handlers) is the one that cannot start, because several of the questions
below decide what it returns — and Q14 decides whether its rate limiting works
at all in the configuration we ship.

None of these were resolved in code. Where an implementation had to do
*something* to compile, it is flagged as provisional and the cost of changing it
is stated.

---

## 1. What landed

| Package | What it owns |
|---|---|
| `internal/reject` | The §5.2 and §5.4 status tables, and the normative evaluation order |
| `internal/query` | §5.3 prefix parsing, masking, the bit-length cap |
| `internal/accept` | The §5.2 acceptance pipeline, minus the recency rule |
| `internal/store` | SQLite against the §9 schema, verbatim envelopes, recency, sweep |
| `internal/signal` | In-memory rendezvous, first-write-wins, long-poll |
| `internal/ratelimit` | Truncated-key limits, no address retained |

### Verification, actually run

```
$ CGO_ENABLED=0 go build ./...          exit 0
$ CGO_ENABLED=0 go vet ./...            exit 0
$ CGO_ENABLED=0 go test ./... -count=1
ok  .../internal/accept    1.461s
ok  .../internal/b64       0.991s
ok  .../internal/derive    1.013s
ok  .../internal/pow       0.976s
ok  .../internal/query     1.437s
ok  .../internal/ratelimit 1.164s
ok  .../internal/record    1.146s
ok  .../internal/reject    1.317s
ok  .../internal/signal    4.239s
ok  .../internal/store     2.426s
ok  .../internal/vectors   1.127s
                                        exit 0
$ gofmt -l .                            (empty)
```

Static build verified rather than assumed, because the toolchain floor moved:

```
$ CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o trigd-linux ./...
cross-compile ok: 9270746 bytes
$ CGO_ENABLED=0 go run ./tmpstatic
sqlite works under CGO_ENABLED=0
```

---

## 2. The eighteen questions

Grouped, because several share a root cause. **Q14 is the one to read first** — it makes
§6.2 inoperative in the deployment we ship. **Q6 and Q8** bite hardest on
interoperability; **Q1 and Q4** are consequences of ruling B (verbatim storage)
that neither of us saw when ruling on it.

---

### Cluster A — base64url strictness

Ruling B made the directory the only choke point in the system. Anything it
tolerates it now propagates verbatim to every client, so "be liberal in what you
accept" has a cost it did not have before.

#### Q1. Is padded base64url a `400`, or must it be accepted? (§4.4 vs §5.2)

§4.4 says only: *"Implementations MUST accept unpadded input and MUST NOT emit
padding."* That is a requirement to accept unpadded and a prohibition on
emitting padding. It never says a receiver must **reject** padded input. The
§5.2 table I drafted says a value that "is not valid unpadded base64url" is
`400`, which implies it must.

The repo currently holds both answers: `internal/b64.Decode` deliberately
tolerates trailing `=`, while `internal/accept` rejects it.

**What breaks.** Java's `Base64.getUrlEncoder()` and Python's
`base64.urlsafe_b64encode` both pad **by default** — the exact platforms §4.4
names as targets. A publisher on either works against every tolerant directory
and gets a hard, undiagnosable `400` from every strict one.

**Recommendation: reject, and say so explicitly.** Three reasons.

1. A publisher emitting padding is *already* violating §4.4's "MUST NOT emit
   padding". Rejecting enforces an existing MUST rather than adding a new one.
2. Under ruling B a tolerant directory stores the padded bytes and serves them
   unchanged, so tolerance does not contain the problem — it spreads it to every
   client, including strict ones. The directory is the only place it can be
   stopped.
3. The failure lands at publish time, immediately, deterministically, on the
   party who can fix it with one call to `.withoutPadding()`. The alternative is
   a client-side mystery weeks later.

If you rule the other way, `internal/accept.unpadded` and its test are deleted
and nothing else changes.

```diff
 **Base64url encoding is unpadded** (RFC 4648 §5, without `=`). Implementations
-MUST accept unpadded input and MUST NOT emit padding.
+MUST NOT emit padding, and MUST reject padded input as malformed rather than
+stripping it.
+
+Rejecting rather than tolerating is deliberate. Java's `Base64.getUrlEncoder()`
+and Python's `base64.urlsafe_b64encode` pad by default, so this will be the
+first thing an implementer on those platforms gets wrong — which is the reason
+to fail loudly at the point of publication, on the party able to fix it, rather
+than to accept the bytes and propagate them. Because a directory stores and
+returns envelopes verbatim (§5.2), anything it tolerates it hands unchanged to
+every client that queries, so tolerance here does not contain a malformed
+encoding, it distributes one.
```

#### Q2. Must a base64url value be canonically encoded? (§4.4, RFC 4648 §3.5)

A 32-byte value spelled in 43 base64url characters carries 258 bits, so the
final character has two bits that decode to nothing. Go's decoder accepts
non-zero trailing bits, giving two textual spellings of one value.

Signatures are over raw bytes, so both spellings verify — but under ruling B
both are storable and both are served as received.

**Recommendation: require canonical encoding.** Same argument as Q1 and the same
one-line cost.

#### Q3. Is a signal `channel_id` identified by its text or its decoded bytes? (§5.4)

The same non-canonical spelling problem, with a sharper consequence: an
implementation keying its channel map on the **text** treats two spellings as
two channels and accepts a POST where an implementation keying on the **decoded
bytes** returns `409`. First-write-wins is a security property, and this is a way
around it.

`internal/signal` keys on the decoded bytes, which is provisional.

**Recommendation: state that the channel is identified by the decoded 32 bytes,
*and* require canonical encoding per Q2.** Either alone closes it; both together
mean an implementation that gets one wrong is still safe.

```diff
 `channel_id` is 32 bytes, base64url.
+A channel is identified by those **decoded bytes**, not by the text that spelled
+them. An implementation keying on the text would treat two spellings of one
+identifier as two channels, and would accept a second write where a conforming
+directory returns `409` — which is a way around first-write-wins, not a
+cosmetic difference.
```

---

### Cluster B — JSON parsing ambiguities

#### Q4. Duplicate JSON members in an envelope (§4.1, §5.2)

Unspecified. Go's `encoding/json` takes the last occurrence; other parsers take
the first.

**What breaks, and it is worse than it looks.** Take a valid envelope and append
a second `"expires_at"` with a later value. A last-wins directory computes a
different signing input, `sig` fails, `403`. A first-wins directory verifies
against the original, **accepts, and stores the bytes verbatim** — then §5.3
serves those bytes to a client that may parse them the other way and act on an
`expires_at` the directory never validated. Ruling B turns a parser disagreement
into a record validated under one meaning and served under another.

**Recommendation: reject duplicate members as malformed (`400`).** Specifying
last-wins would require every implementation to control its JSON library's
duplicate handling, which many cannot do without writing a parser. Rejecting is
a single scan, fails closed, and no honest publisher ever emits one.

```diff
+**Duplicate members are malformed.** An envelope containing the same member name
+more than once MUST be rejected with `400`. JSON parsers disagree about which
+occurrence wins, and because a directory verifies a signature over fields it
+parsed and then stores the bytes verbatim (§5.2), a first-wins directory and a
+last-wins client can end up disagreeing about an `expires_at` that the directory
+never validated. Rejecting closes that without requiring implementations to
+control their JSON library's behaviour.
```

#### Q5. Is an explicit `null` for a required member absent or present? (§5.2)

"A required member is absent" is `400`. The spec does not say whether
`"expires_at": null` counts. It has a wire consequence: as a present zero it
clears the TTL bound and falls out later as `403`; as absent it is `400`.

`internal/accept` treats `null` as absent. **Recommendation: confirm that** —
one sentence, `null` is not a value.

---

### Cluster C — boundary determinism

#### Q6. Is a record whose `expires_at` equals the clock present or absent? (§5.2, §5.3)

**This is the one I would settle first.** §5.2 says a record whose `expires_at`
"has passed" is absent; §5.3 returns every "non-expired" envelope. Neither
settles equality.

**What breaks.** §5.2 explicitly requires that *"two conforming directories given
identical input and an identical clock MUST return identical results"*. At the
boundary second they do not. There is a one-second window in which directory X
returns the envelope and directory Y returns an empty array — precisely the
failure that sentence exists to forbid. The client symptom is a lookup that
intermittently misses. It also shifts the recency floor by one second.

**Recommendation: live ⟺ `expires_at > now`.** It is the only reading consistent
with §5.2's own publish condition, which already rejects `expires_at` not
*strictly* greater than the directory's clock — so under the other reading a
record could be simultaneously too stale to publish and still live to serve.

`internal/store` implements this, as one predicate in three places; a ruling the
other way is a three-character change plus one test row.

```diff
 **A record whose `expires_at` has passed is treated as absent for every purpose
 in this specification**, whether or not the directory has physically removed it.
+A record is live if and only if `expires_at` is **strictly greater** than the
+directory's current time; at equality it is absent. This matches the publish
+condition below, which requires `expires_at` to be strictly greater than the
+current time — so a record can never be simultaneously too stale to publish and
+still live to serve.
```

#### Q7. Is the order of the `records` array specified? (§5.3)

Same "identical results" sentence. If order is part of "results", it is
unspecified. Nothing breaks functionally — the client trials AEAD decryption on
each — so this is the lowest-stakes item here.

**Recommendation: state that order is not significant and clients MUST NOT depend
on it, and RECOMMEND ordering by `lookup_id`.** Not for determinism but for
privacy: the natural index or insertion order discloses the relative publish
times of the records in a bucket to whoever queried it, which is a small
correlation channel the design otherwise closes. `internal/store` already orders
by `lookup_id` for exactly this reason.

---

### Cluster D — query syntax

#### Q8. `k_min = 20` is RECOMMENDED, but §5.1's guarantee is stated unconditionally

§5.3 requires *a* maximum `bits` and only **recommends** `k_min = 20`. But §5.1
states as fact: *"a client following the advertised figure can never exceed it."*

That holds only if `k_min ≤ 50`. A directory choosing `k_min = 100` rejects a
conforming client with `400` for following the spec exactly, and the client
cannot predict it because nothing advertises the instance's `k_min`.

**Recommendation: make `k_min = 20` normative (MUST), not RECOMMENDED.** The
guarantee in §5.1 is worth more than a directory's discretion over its own
anonymity floor, and an unconditional promise in one section that another
section permits an instance to break is a defect either way. The alternative —
weakening §5.1 to a conditional — makes the client's position strictly worse for
no gain.

```diff
-Directories MUST enforce a maximum `bits` and reject over-precise queries with
-`400`. ... RECOMMENDED, with `k_min = 20`:
+Directories MUST enforce a maximum `bits` and reject over-precise queries with
+`400`, computed with `k_min = 20`:
...
+`k_min` is fixed at 20 rather than left to the instance. §5.1 promises
+unconditionally that a client following the advertised `record_count` can never
+be rejected as over-precise, and that promise holds only while every directory's
+`k_min` is at or below the client's `k` of 50. A directory free to raise it could
+reject a conforming client with `400` for following this specification exactly,
+with nothing advertised that would let the client predict it.
```

#### Q9. Repeated query parameters — `?bits=1&bits=2` (§5.3)

Unspecified. `url.Values.Get` silently takes the first; other stacks take the
last. Same shape as Q4.

**Recommendation: reject with `400`.** Fail closed on ambiguity rather than
picking a winner, for the same reason as Q4 and at the same cost.

#### Q10. The lexical form of `bits` (§5.3)

Unspecified. `internal/query` accepts plain non-negative decimal, so `"010"`
parses as 10 while `"+12"` and `"-1"` are rejected.

**Recommendation: "one or more ASCII digits, no sign, no leading zeros, no
whitespace."** Very low stakes — no realistic client emits any other form — but
it is free to pin and it is the kind of thing that is annoying to discover later.

#### Q11. Should §5.3 bound `bits` independent of the cap?

A prefix wider than a `lookup_id` cannot match anything, and a naive
implementation might size a buffer from the parameter. `internal/query` rejects
`bits > 256` as a structural guard; it is unreachable through the cap, so it
cannot cause divergence.

**Recommendation: one defensive sentence** — `bits` MUST NOT exceed 256 and a
directory MUST reject beyond it with `400`.

---

### Cluster E — signal channel capacity

Neither has a row in §5.4's table, and both are provisional in `internal/signal`.

#### Q12. What does a directory return when it refuses a long-poll at capacity?

Implemented as `429`. The alternative is an immediate `204`, which §5.4 permits
("Clients MUST tolerate an earlier `204`") but which tells the client to poll
again **immediately**, hot-looping against the instance that just said it was
full.

**Recommendation: `429`.** Its remedy — back off, retry, or move on — is the
correct client behaviour, and it is the only code in the table that means that.

#### Q13. What does a draining instance return to a POST?

Implemented as `429`. Returning `204` is a lie: the blob can never be delivered.
`404` is arguably better advice during a rolling restart, but §5.4 reserves it
for an instance advertising `"signal": false`, and a client told that will stop
trying this directory for signal entirely.

**Recommendation: `429`**, and add both rows to §5.4's table.

```diff
 | either | Rate limited | `429` |
+| either | Instance at capacity, or shutting down | `429` |
 | either | Instance advertises `"signal": false` | `404` |
+
+An instance that is full or draining answers `429` rather than `204` or `404`.
+`204` would tell the client to poll again immediately, hot-looping against an
+instance that just declined; `404` would tell it this directory does not broker
+signal channels at all, which is wrong and sticky. `429` means back off or move
+on, which is what a client should do in both cases.
```

---

### Cluster F — rate limiting in the deployment we actually ship

#### Q14. What address is the limiter fed, given TLS is terminated in front of it? (§6.2, §6.4, §9)

**This is the most serious item in this report and it is my omission, not a
sub-agent's.** §6.4 says limits are keyed on "the source address". §9's
deployment story is "set a domain, get a certificate, run", and the compose file
in task 7 puts Caddy in front terminating TLS.

**A directory behind a reverse proxy sees the proxy's address on every single
request.** Every client collapses into one `/24` bucket — `127.0.0.1`. The
limiter counts to 120 and then refuses the entire internet. §6.2's abuse
resistance is not merely weakened in the shipped configuration, it is
inoperative, and it fails closed in the worst possible way.

The fix is to trust a forwarded address, and that has its own edge: an
attacker-supplied `X-Forwarded-For` evades the limiter entirely, and the
directory is now parsing an address a hostile party chose. It also puts a client
address into a request header, which is exactly the shape of thing §6.4 is
written to keep out of the process.

**Recommendation.** Both halves are needed and neither is optional:

1. The directory reads a forwarded address **only** from a configured, explicitly
   enabled trusted-proxy list, defaulting to disabled. Not "trust `X-Forwarded-For`
   if present" — that is the evasion.
2. When the immediate peer is not on that list, the header is ignored entirely
   and the peer address is used. An operator who deploys behind a proxy without
   configuring it gets a limiter that is useless-but-safe rather than one that is
   bypassable.
3. The forwarded address is subject to §6.4 in full — truncated on arrival,
   never logged, never retained beyond the window. It is more sensitive than the
   peer address, not less.

This needs a paragraph in §6.4 and a line in the compose file. `internal/ratelimit`
takes an already-parsed `netip.Addr` and expresses no opinion, which is the right
boundary — the decision belongs to the handler, in task 6.

#### Q15. What happens at the key bound? (§6.4)

§6.4 mandates a truncated key and in-memory state but says nothing about a table
cap, which every conforming implementation must have — an unbounded map keyed by
attacker-chosen networks is itself the memory exhaustion vector.

Implemented as fail-closed: at the bound a new key is refused, an already-tracked
one is served. **Recommendation: state fail-closed.** Admitting new keys at the
bound lets an adversary holding enough distinct networks switch the limiter off
for everyone, which is precisely the scenario it exists for.

#### Q16. Are limits per class, or one budget per source? (§6.2, §5.4)

§6.2 names `PUT` and `GET` separately and §5.4 gives signal its own `429` row,
which implies three classes, but it is never stated. Client-visible: under a
single budget a client that exhausts lookups also loses the ability to publish.
**Recommendation: three independent classes**, as implemented, and say so.

#### Q17. Nothing drives expiry on an idle instance (§6.4)

§6.4 requires state discarded when its window elapses. On an instance receiving
no requests, nothing triggers that, so the last few keys before traffic stopped
are retained indefinitely. Small, but it is a literal breach of the sentence.
**Recommendation:** one clause permitting reclamation to be driven by a timer,
and requiring it on an otherwise idle instance.

#### Q18. §6.4's closing sentence is ambiguous — and it is my wording

> "Abuse resistance is a defence; the inability to produce records is the
> property the service exists to have."

I meant "produce" in the legal-discovery sense: an operator who cannot be
compelled to produce records. It reads equally as "the ability to serve records",
under which the sentence inverts the priority it is setting and would argue for
failing *open* at the key bound — the opposite of Q15.

An ambiguous sentence in a normative section is a defect regardless of which
reading was intended. **Recommendation:**

```diff
 A directory that cannot rate limit under these constraints does not rate limit.
-Abuse resistance is a defence; the inability to produce records is the property
-the service exists to have.
+Abuse resistance is a defence that can be lost and rebuilt. The operator's
+inability to disclose who asked for what — because the records to disclose were
+never created — is the property the service exists to have, and it is not
+recoverable once given up.
```

---

## 3. Judgement calls made without asking

Structural, recorded rather than raised.

- **`internal/query` owns the §5.3 maths; `internal/store` consumes it.** The two
  packages were written concurrently and each implemented masking and prefix
  matching independently. They agreed — cross-checked over 4,000 random prefixes
  at bits 0..64 with zero disagreements — but two copies of one protocol rule is
  the drift this project exists to prevent, and that hazard does not stop at the
  boundary of a single codebase. `ByPrefix` now takes a `query.Query` so the
  masked prefix, the column range and the post-filter travel as one value and
  cannot disagree. Verified by mutation: disabling the mask in `query` fails the
  storage tests, so the dependency is real and not cosmetic.
- **`query.FromBits`** added as the second and only other constructor, so the
  invariant between `Bits`, `Prefix` and `Full` is established in exactly one
  place.
- **`store.ErrShortPrefix` deleted.** A short prefix is now unrepresentable
  rather than merely guarded against — a `Query` cannot be built that way.
- **Rate limits**: `PUT` 120/hour, `GET` 600/hour, signal 600/hour, per truncated
  key. Generous per §6.4's own reasoning: a `/24` bucket is up to 256 hosts, and
  publish volume is around one request per server per day (§9.1).
- **Two clock representations.** `store` takes `int64` Unix seconds, matching
  `expires_at` and §0.1; `signal` takes `time.Time`, matching a 300-second TTL and
  a 30-second poll. The handler will hold both. Defensible on each side and not
  worth churning either package.

## 4. Dependencies

`modernc.org/sqlite v1.54.0`, the first and only direct requirement, per I-2.
Nine indirect requirements came with it, all its transitive closure.

**The toolchain floor moved from Go 1.24 to 1.25.0, and it was forced, not
chosen** — `modernc.org/sqlite`, `modernc.org/libc` and `golang.org/x/sys` all
declare `go 1.25.0`. A consequence of I-2 rather than of anyone reaching for a
language feature. Older driver releases would hold 1.24 if you would rather pin
one; say so and I will.

`CGO_ENABLED=0` cross-compiles a working 9.3 MB static linux/amd64 binary with
SQLite linked in — verified, not assumed, because this is the constraint the
dependency most plausibly threatened.

## 5. Not done

- **Task 6** — HTTP handlers, CORS, config, graceful shutdown. Blocked on the
  questions above.
- **Tasks 7 and 8** — Dockerfile and compose; API-level conformance vectors.
- **`go test -race` cannot run natively here.** The race detector requires cgo,
  and this machine has no working C toolchain for Go. `internal/signal` — the
  only package with interesting concurrency — passes clean under `-race` on
  linux/amd64 in Docker, but there is no repo-level way to run it. **This needs
  to become a CI job**, and I will fold it into task 7 unless you would rather it
  were separate.
- No sweep scheduling. `store.Sweep` and the signal store's reclamation are
  methods; nothing calls them on a timer yet. That belongs with the server.
