# Phase 1b — reconciliation with the amended DIRECTORY-SPEC.md

Status: complete. Build, vet and tests clean under `CGO_ENABLED=0`.

Every ambiguity and error raised in phase 1 was accepted into the spec. Three of
the resolutions matched what was implemented and needed only re-grounded
comments; one (§4.2) replaced a subsystem outright.

---

## 1. SPEC AMBIGUITIES

Five, none of them of the severity of phase 1's set. The first is in phase 1b's
own scope; the middle three are phase 2 blockers raised now because they need
decisions before storage and the query handler are written.

### #1 — §4.2: is the plaintext length exactly `2 + body_len + 64`?

The offset table implies it. Nothing states it, and nothing says what a verifier
should do with bytes after the signature.

Considered: (a) reject any plaintext whose total length is not exactly
`2 + body_len + 64`; (b) ignore trailing bytes, on the §10 principle that
additive change must remain possible.

**Implemented: (a).** `ParsePlaintext` rejects, in
`internal/record/plaintext.go`. A parser that tolerates slack no longer lets the
framing determine what was signed, and "ignore the rest" is how parsers become
attack surfaces.

**Impact if another implementation chooses (b):** security impact is nil — the
plaintext is inside the AEAD, so an attacker cannot append without `RecordKey`,
and the tag would fail first. The real cost is forward compatibility: choice (a)
forecloses ever appending anything to the plaintext without a `/v2/`, which sits
awkwardly beside §10's additive-change policy. If the intent is that the payload
plaintext is a closed format and extension happens inside `body` (where unknown
JSON fields are already ignored), that is coherent — but it should be said,
because it is the opposite of the extension model §10 describes for the
envelope.

### #2 — §5.2: does the recency rule compare against expired-but-unswept records?

The new rule requires `expires_at` strictly greater than "that of any record
already stored under the same `lookup_id`". Storage is a background-swept table,
so at any instant it may hold records that are expired but not yet removed.

Considered: (a) compare against whatever row is physically present, expired or
not; (b) treat an expired record as absent, so it neither blocks a publish nor
sets a floor.

**Not implemented — no storage exists yet.** This is the phase 2 decision I most
need settled.

**Why it matters:** under (a), whether a publish succeeds depends on how recently
the sweep ran. Two conforming directories given identical inputs return different
status codes, and the same directory returns different results before and after
its own timer fires. That is precisely the class of nondeterminism the spec
eliminates elsewhere. Under (b) the behaviour is a pure function of the request
and the wall clock. (b) also reads more naturally against §5.3's requirement that
expired records "must never be returned" — a record that cannot be read is hard
to argue is still "stored".

The counter-argument for (a): it closes a small replay window. A server whose
record lapses entirely could have an old envelope replayed in the gap before it
republishes. But that envelope must itself still be unexpired to be accepted at
all, so the window is bounded by the overlap between the two, and (b) does not
open anything (a) closes for long.

Related, and probably not worth a spec change: a server that restarts mid-epoch
and forgets the last `expires_at` it used has no way to discover the floor, since
the directory does not report it — a `409` is undifferentiated. In practice
`now + ttl` is monotonic unless the clock goes backwards, so this self-heals.

### #3 — §5.3 and §5.1: does the server-side `bits` cap use the true or the advertised `record_count`?

§5.1 permits `record_count` to be "rounded or fuzzed". §5.3 requires the
directory to enforce a maximum `bits` derived from the record count. The client
computes its `bits` from the advertised figure. The spec does not say which
figure the cap uses.

**Not implemented — phase 2.**

**Why it matters:** if the directory fuzzes downward for privacy but caps on the
true count, a well-behaved client's query is accepted; if it fuzzes upward and
caps on the true count, a well-behaved client is rejected with `400` for
following the spec exactly. Either the cap must be computed from the same figure
that was advertised, or the fuzz must be constrained to one direction. My
inclination is the former — cap on the advertised value, so the client and the
directory always agree — and to say so in §5.3. Flagging rather than choosing.

### #4 — §5.3: which bits are significant when `bits` is not a multiple of four?

The worked syntax is `?prefix=a3f&bits=11`. Three hex characters carry twelve
bits; `bits=11` uses eleven of them. The spec does not say whether the unused
low bit must be zero, whether the directory must mask it, or whether a non-zero
unused bit is a `400`.

**Not implemented — phase 2.** My intent is to mask and ignore the unused low
bits, since that cannot reject a well-formed query, and to document it.

**Why it matters:** the amended §5.3 makes `bits = 10` the recommended value at
100,000 records, and 10 is not a multiple of four — so this is now the *common*
case, not an edge case. A directory that rejects non-zero padding bits and a
client that does not zero them fail on every single query. Worth one sentence in
§5.3.

### #5 — §4.2 and §4.3: `body_len` is `uint16`, but no reachable body is close to 64 KB

The length prefix can describe 65,535 bytes. §4.3 caps the envelope at 4096
bytes, and the envelope carries `ct` base64-encoded inside JSON alongside six
other fields, so the largest reachable body is roughly 2.9 KB.

Not a defect, and the implementation bounds buffers from §4.3 rather than from
the prefix width. Raised only because an implementer sizing a read buffer from
`body_len` would allocate 64 KB per record for no reason, and because it is worth
confirming the two-byte prefix is a round number rather than an intent to allow
larger payloads under some future limit.

---

## 2. SPEC ERRORS OR CONTRADICTIONS

Four, all minor and editorial. The substantive ones from phase 1 are fixed.

### E1 — §5.2: the sixth rejection condition is detached from the list

The rejection conditions render as a five-item list, a blank line, then a
separate one-item list:

> - `pow` satisfies the proof-of-work challenge (§6.1)
>
> - `expires_at` is strictly greater than that of any record already stored under
>   the same `lookup_id`

The blank line breaks the markdown list. Since these conditions are normative and
are naturally referred to by count, the recency rule currently reads as an
appendix rather than as the sixth peer of the other five. Purely cosmetic; worth
a one-character fix.

### E2 — §8: the threat model still says the anonymity bucket is ~50

The threat model table reads:

> | Identify which server a client asked for | Reduced to a bucket of ~50 |

The amended §5.3 states that `floor` makes `k` a floor rather than a target and
that "the expected result set is always between `k` and `2k`", with the worked
example at ~98 and the prose describing "a bucket of around a hundred servers".
§8's `~50` is the value from the pre-amendment example. It understates the
guarantee the design now provides, which is an unusual direction for a threat
model to be wrong in, but it is still inconsistent.

### E3 — §5.1 cites `README-LICENSING.md`, which does not exist

> This is how an AGPL-licensed reference implementation discharges its §13
> obligation to network users; see `README-LICENSING.md`.

No such file exists in either the `spec` or `trigstationd` tree. A dangling
cross-reference inside the one clause that discharges a licence obligation is
worth closing, either by writing the document or by pointing at §12.

### E4 — §0.1's `ts` row is now vestigial

The §0.1 width table gives `ts` as 8 bytes. After the §4.2 rewrite there is no
construction anywhere in v1 that concatenates `ts` into a byte string — it
appears only as a JSON number inside `body`, which is signed as transmitted text.
The row is a leftover from the canonical-payload encoding that was just removed.

Harmless, but §0.1 is the one place a reader goes to learn where fixed-width
integers appear, and an entry with no corresponding construction invites someone
to build one.

---

## 3. TEST VECTORS — changed / unchanged diff

Regenerated to `testdata/vectors.json`. Verified field by field against the
phase 1 file rather than by eye.

### Unchanged, as required

| Value | Verdict |
|---|---|
| `s_dir`, `ik_seed`, `ik_pub` | UNCHANGED |
| `write_seed` (all 4 rows) | UNCHANGED |
| `wk_pub` (all 4 rows) | UNCHANGED |
| `wk_priv` (all 4 rows) | UNCHANGED |
| `lookup_id` (all 4 rows) | UNCHANGED |
| `record_key` (all 4 rows) | UNCHANGED |
| `mailbox_id` (all 4 rows) | UNCHANGED |
| `unix_time`, `epoch`, `epoch_start` | UNCHANGED |
| `envelope.lookup_id`, `envelope.wk_pub`, `envelope.expires_at`, `envelope.nonce` | UNCHANGED |
| `envelope.pow`, `pow.input`, `pow.value`, `pow.digest`, `pow.leading_zero_bits` | UNCHANGED |

The entire key schedule surviving byte-for-byte is the confirmation that §0.1
adopted phase 1's inferred encodings verbatim: had the epoch width, endianness,
HKDF construction or seed interpretation moved by even one bit, every one of
these would have changed.

The proof of work is also unchanged, which is the expected consequence of §6.1
binding only `lookup_id` and `expires_at` — neither of which the payload rewrite
touches. It is a useful incidental check that the pow input really does exclude
`ct`.

### Changed, as required

| Value | Verdict | Cause |
|---|---|---|
| `envelope.ct` | CHANGED | plaintext layout changed, so the AES-GCM input changed |
| `envelope.sig` | CHANGED | `ct` is inside the envelope signing input |
| `envelope_signing_input` | CHANGED | contains `ct` |

### Structural changes

Removed from `envelope`: `payload_plaintext_utf8`, `payload_plaintext`,
`payload_signing_input`, `payload_json`.

Added to `envelope`: `body_utf8`, `body`, `body_len`, `payload_sig`, `plaintext`.

`body` is the base64url of the exact bytes the detached signature covers, and it
is the definitive field — `body_utf8` is a convenience for reading. The file
carries a warning saying so, because the obvious way to misuse these vectors is
to re-serialise `body_utf8` through a local JSON encoder and expect
`payload_sig` to verify.

Removed at top level: `_unspecified` — every item it listed is now settled by the
spec, so the file no longer needs to warn that its values might be wrong.

Added at top level: `s_pair`, `pairing` (see §7).

`conventions` was rewritten: each entry now cites the clause that fixes the
encoding (§0.1, §3.3, §4.1, §4.2, §6.1) instead of explaining a choice this
implementation had to make.

### Sample values

```
body_len     287
payload_sig  isoLMFkcEcpnt2BCkhKupfKWPKsF74dHRrg5CTTWWttTLrqBbUOiusaQ0lq0Sk87OCivvmhrxzTcXE-5PtygBQ
plaintext    AR97InYiOjEsInRzIjoxNzUzNDg4MDAwLCJlbmRwb2ludHMiOlt7InR5cGUiOiJsYW4i…
envelope.sig BjQxzEy5-J8BzmyM19MQwwHx0RMTB3vPkYMGUy2lbdQ93HJW0xxvZh7pcLlmPY3JVA_t57_gIPqz6XdMgS8GAA
```

`plaintext` begins `01 1f` — 287 big-endian — followed immediately by `7b`, the
opening brace of `body`. The framing is directly readable from the base64, which
is a small but real aid when debugging another implementation.

---

## 4. JUDGEMENT CALLS

- **`inner.go` deleted, replaced by `plaintext.go`.** A rename rather than an
  edit, so that no reviewer finds a file whose name and history suggest a
  canonicaliser still lives there. `CanonicalPayload`, `Payload.SignInner`,
  `Payload.VerifyInner` and `Payload.SigningBytes` are gone entirely, with no
  deprecated aliases.
- **`record.Payload` renamed to `record.Body`, and its `Sig` field removed.** The
  signature is no longer part of the JSON object, so a struct field for it would
  reintroduce the chicken-and-egg the detached layout exists to remove.
- **`VerifyPayload` takes `body []byte`, and there is deliberately no overload
  taking a `Body`.** Such an overload could only work by re-serialising. The
  doc comment says so explicitly, because it is the single most likely
  regression: Go's `encoding/json` round-trips most inputs unchanged, so the bug
  would pass every test written against bodies this codebase generated and fail
  against every other implementation.
- **`MarshalPlaintext` takes `body []byte`, not a `Body`.** Serialisation is the
  caller's business — "serialised however the implementation likes" is only true
  if the bytes that were signed are the bytes that are sent, so the bytes are
  threaded through from a single `json.Marshal` in the generator.
- **`FixedPrefixLen` exported from the record package.** It gives
  `TestCanonicalEnvelopeInjectivity` something concrete to assert, so the §4.1
  rule that added fields must be fixed-width and precede `ct` fails a test rather
  than being a comment nobody reads.
- **`TestReserialisingBeforeVerifyingFails` asserts its own premise.** It fails
  loudly if the re-serialisation happens to be byte-identical to the original,
  rather than silently proving nothing.
- **Pairing derivations share `derived()` with the S_dir schedule.**
  PAIRING-SPEC §3.1 says they mirror it exactly and inherit every convention, so
  a separate implementation would be a place for the two to drift apart.
  `TestPairingVectors` additionally applies the pairing label to `s_dir` to prove
  the separation comes from the info string and not merely from using a different
  secret.
- **No separate `PairLookupID` function.** It is `SHA-256(PairWK_pub)` — the same
  function. A directory cannot distinguish a pairing record from a normal one,
  and the code should not imply otherwise.
- **The vectors' "is this described as detached" test asserts a positive.** The
  first attempt grepped for the absence of the word "canonical" and failed on my
  own sentence *"there is no canonicalisation rule"*. Asserting the presence of
  "detached" and "literal" tests the property rather than the vocabulary.

---

## 5. DEPENDENCIES ADDED

**None.** `go.mod` still has no `require` block:

```
module github.com/trigstation/trigstationd

go 1.24
```

Standard library only. `crypto/hkdf` is stdlib as of Go 1.24, which is why the
directive names that version. `modernc.org/sqlite` will be the first entry, in
phase 2.

---

## 6. VERIFICATION

```
$ CGO_ENABLED=0 go build ./...
exit: 0

$ CGO_ENABLED=0 go vet ./...
exit: 0

$ CGO_ENABLED=0 go test ./... -count=1
?     github.com/trigstation/trigstationd                  [no test files]
?     github.com/trigstation/trigstationd/cmd/gen-vectors  [no test files]
ok    github.com/trigstation/trigstationd/internal/b64      1.028s
ok    github.com/trigstation/trigstationd/internal/derive   1.015s
ok    github.com/trigstation/trigstationd/internal/pow      1.003s
ok    github.com/trigstation/trigstationd/internal/record   1.117s
ok    github.com/trigstation/trigstationd/internal/vectors  1.190s
exit: 0
```

`gofmt -l .` is empty.

**No logging of identifiers exists.** Re-audited after the rewrite: zero imports
of `log` or `log/slog`, zero `slog.` or `log.` calls anywhere in the tree. The
only output statements remain four `fmt.Fprint*` calls to stderr — three static
lines in `main.go`, one error report in `cmd/gen-vectors` — neither on a request
path. No `fmt.Errorf` interpolates an identifier, ciphertext or address;
`TestDecodeFixedErrorOmitsValue` enforces this at the likeliest breach point.

**Endpoint count: zero.** No HTTP server exists yet.

**No payload canonicaliser remains.** `Canonical*` identifiers exist only for the
envelope. The word appears near the payload solely in negations — "there is no
canonicalisation rule", "verifiers MUST NOT re-serialise" — and in the test that
asserts the vectors describe the signature as detached.

Test count: 48 top-level tests, 149 including subtests.

---

## 7. OPTIONAL WORK COMPLETED — pairing vectors

Added, since it required no restructuring: `derived()` already took a secret and
a label, so the pairing schedule is three thin wrappers.

- `derive.PairWriteSeed`, `derive.PairRecordKey`, `derive.PairWriteKey`.
- A `pairing` array in the vectors, one row per distinct epoch (20294, 20295,
  20296), derived from a new `s_pair` test input — the counting pattern
  `0x40..0x5f`, distinct from `s_dir` so the vectors demonstrate two independent
  secrets.
- `TestPairingVectors` recomputes every value and additionally checks that
  applying `trig-pair-write-v1` to `s_dir` differs from applying
  `trig-write-v1` to it, proving the schedules are separated by the info string
  and not merely by the secret.

A directory needs none of this: PAIRING-SPEC §3.2 introduces no new record type,
and a pairing record is an ordinary envelope under an ordinary `lookup_id`.

---

## 8. NOT DONE

- **Phase 2 in its entirety** — storage, the four operations, Dockerfile,
  compose file, config. Not started.
- **`LICENSE` remains a stub**, as instructed. Full AGPL text is at
  `LICENSE-AGPL-3.0.txt`.
- **`trig-devpair-*` derivations are not implemented.** The three channel
  derivations, the X25519 transfer key and the SAS (PAIRING-SPEC §6.3, §6.4) are
  client-to-client only; the directory sees opaque blobs on signal channels and
  needs none of them. They were not in scope and adding them would mean
  introducing X25519 to a codebase whose whole cryptographic surface is currently
  four standard-library packages. Worth a separate vectors file if
  media-server implementers want one.
- **`README-LICENSING.md` not written** — see error E3. It is cited by §5.1 but
  is a spec-repo artefact, not mine to create unilaterally.
- **No benchmark for the 20-bit proof of work.** §6.1's "roughly 100 ms" remains
  unverified, and this vector's unusually low counter (16,489 attempts against an
  expected ~1,048,576) makes it a poor basis for one.
