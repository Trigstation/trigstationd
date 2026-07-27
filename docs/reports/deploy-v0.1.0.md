# Deploying the first public directory instance

**Host:** `dir.trigstation.com` — 170.64.225.5 / 2400:6180:10:200::d441:7000
**OS:** Ubuntu 26.04 LTS (Resolute Raccoon), DigitalOcean, Sydney
**Commit deployed:** `41b5f50`, tagged `v0.1.0`
**Status: SERVING.** `https://dir.trigstation.com` is live with a trusted
production certificate, holds a published record, survives reboot, and records
nothing about its clients at any of three layers.

**One tag-blocking finding remains** — the published container image is private,
so `docker pull` fails for everyone. See "Tag sequence" at the end.

This is the first execution of `docs/deploy-check.md`, and correcting that
document was part of the work. Corrections are in §"Corrections to
deploy-check.md" below and are committed alongside this report.

---

## What is running right now

| | |
|---|---|
| `trigstationd` | up, answering |
| `caddy` | up, holding a trusted production certificate |
| Certificate | Let's Encrypt production, `CN=YE2`, expires 2026-10-25, auto-renewing |
| Records held | 1 |
| Reboot | tested; stack returns unattended in ~5s, certificate survives |
| Logging | nothing client-derived at any of three layers, verified by experiment |

---

## 1. Connectivity and DNS

### DNS is correct and is not proxied

Verified from the droplet, because the workstation sits behind a filtering
resolver and its answers cannot be trusted for this.

| Resolver | A | AAAA |
|---|---|---|
| 67.207.67.3 (DO) | 170.64.225.5 | 2400:6180:10:200::d441:7000 |
| 1.1.1.1 | 170.64.225.5 | 2400:6180:10:200::d441:7000 |
| 8.8.8.8 | 170.64.225.5 | 2400:6180:10:200::d441:7000 |
| 9.9.9.9 | 170.64.225.5 | 2400:6180:10:200::d441:7000 |
| `kate.ns.cloudflare.com` (authority) | 170.64.225.5 | 2400:6180:10:200::d441:7000 |

TTL 300. No CNAME.

The zone is hosted at Cloudflare — `kate.ns.cloudflare.com`,
`phil.ns.cloudflare.com` — which is worth stating plainly because it is the one
thing here that looks alarming and is not. The records are **DNS-only, not
proxied**. Both addresses were tested against Cloudflare's own published ranges
and are in neither:

```
170.64.225.5:                 not in any Cloudflare range
2400:6180:10:200::d441:7000:  not in any Cloudflare range
```

Cloudflare as registrar and authoritative DNS is fine. Cloudflare *proxying* the
record would break HTTP-01 and hand a third party every client address and
lookup prefix (§9.2). Do not enable the orange cloud on this record.

### CAA — a check deploy-check.md did not have

No CAA record exists on `dir.trigstation.com` or `trigstation.com`, so Let's
Encrypt is permitted. Added to the document: a CAA record naming another CA
fails issuance *at the authority*, which looks nothing like a DNS or challenge
problem in Caddy's output.

### Ports 80 and 443 are reachable

Both answered **connection refused** from off-host before anything was
installed. That is the good result: a RST means packets traverse DigitalOcean's
edge and only the host has nothing listening. A timeout would have meant a
provider firewall. This retires the failure mode §0 calls the most common one,
before ACME rather than after five failed attempts.

IPv6 is unreachable *from the workstation* — no IPv6 egress there. From the
droplet, IPv6 works: global address present and outbound confirmed.

---

## 2. Hardening

### SSH

User `trigstation`, uid 1000, groups `trigstation sudo users docker`. Root's
`authorized_keys` copied verbatim; fingerprint confirmed identical
(`SHA256:0oDnoaUo7OtBQHvmEI/nis/0NIw/5qoLayX2SrKxfnQ`).

`NOPASSWD` in `/etc/sudoers.d/90-trigstation`. This is a judgement call worth
naming: the account has no password at all, so plain `sudo` group membership
would prompt for a credential that does not exist and strand the operator. It is
what cloud-init does for the default cloud user, for the same reason.

**Two findings specific to Ubuntu 26.04 that change the documented procedure:**

*Socket activation.* `ssh.socket` is enabled and active; `ssh.service` is
`disabled` but running, started by the socket. `Accept=no`, so there is one
long-lived listener forking `sshd-session` children rather than one sshd per
connection.

*`reload` is strictly safer than `restart` here*, and this is not a stylistic
preference. The unit sets:

```
ExecStartPre=/usr/sbin/sshd -t
ExecReload=/usr/sbin/sshd -t
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
```

`restart` stops the listener and then validates; an invalid config means sshd
does not come back and no new connection is possible. `reload` validates
*first* and aborts without touching the running listener. `KillMode=process`
means neither kills established sessions — which is what makes holding a second
session a genuine safety net rather than a ritual.

**Procedure followed:** created the user, verified key login and sudo, opened
and held a second session as that user (`pid=3689`), *then* changed sshd.
Verified after: new session as `trigstation` succeeds, root refused
(`Permission denied (publickey)`), safety session still alive. The listener PID
was 1727 before and after, confirming the reload re-execed in place.

`PasswordAuthentication` was **already `no`**, set twice by
`50-cloud-init.conf` and `60-cloudimg-settings.conf`. Only `PermitRootLogin`
needed changing.

**Drop-in filename matters.** `/etc/ssh/sshd_config.d/10-trigstation-hardening.conf`
is named `10-` deliberately. sshd takes the **first** value seen for a keyword,
and `Include` sits at line 24 of `sshd_config` — ahead of its own
`PermitRootLogin yes` at line 54. A `99-` file, which is what most guides
suggest, would lose to `50-cloud-init.conf` for any keyword that file also sets.

### UFW

Order: `allow OpenSSH` → `allow 80,443/tcp` → `allow 443/udp` → `enable`, with a
guard that aborts before `enable` if no SSH rule is staged. Active, v4 and v6,
default deny inbound. New SSH connection verified working immediately after.

`443/udp` is included because `docker-compose.yml` publishes it for HTTP/3.
Omitting it degrades silently — clients fall back to TCP and nothing looks
wrong.

**UFW does not restrict Docker-published ports.** Docker inserts its own rules
ahead of ufw's chains, so once Caddy publishes 80 and 443 those are reachable
regardless of ufw state. The rules above are still correct and still govern
everything else, but an operator should not read "ufw allows 80/443" as the
reason those ports work.

### Unattended upgrades

Enabled and functional, not merely installed. `20auto-upgrades` has both
periodic settings at `1`, the service is `enabled`, both timers are armed, and a
`--dry-run` showed it would actually install pending security updates
(`curl`, `libcurl4t64`, `libssh2-1t64`). Everything else left at default.

---

## 3. Memory: the finding that shaped the rest

**This is a 512 MB droplet with no swap, and that is not enough to deploy on.**

`free -m` reported 453 MB total. During the first `apt upgrade`, the OOM killer
took `zstd` — dracut's compressor — and the initramfs rebuild failed, leaving
`dracut` in a broken dpkg state:

```
Out of memory: Killed process 12696 (zstd) total-vm:376528kB, anon-rss:159016kB
dracut[F]: Creation of /boot/initrd.img-7.0.0-27-generic.tmp failed
dpkg: error processing package dracut (--configure)
```

`fwupd` was OOM-killed a minute earlier. Both predate any Trigstation work.

This is worth dwelling on because of *how it presents*. Nothing said "out of
memory". It said dracut failed. A retry appeared to succeed — exit 0 — purely
because memory happened to be free at that instant, which is luck rather than a
fix, and taking that at face value would have left a host that boots on a
coin flip.

**Resolution:** 2 GB swapfile, `vm.swappiness=10`, persisted in `/etc/fstab` so
it survives the step 7 reboot. Then `dpkg --configure -a` completed, the
initramfs rebuilt cleanly, and the Go build later consumed 172 MB of swap —
confirming the swap was load-bearing, not precautionary.

### The initramfs scare, and why it was not one

The rebuilt initramfs is 39 MB where the original was 69 MB, and
`initrd.img.old` symlinks to the *same* file, so there is no fallback. On a
headless droplet a bad initramfs is unrecoverable, and step 7 reboots this box.

A first check suggested `virtio_blk`, `virtio_pci`, `virtio_scsi`, `virtio_net`
and `ext4` were all absent from the image. They are all **compiled into the
kernel**, confirmed against `/lib/modules/7.0.0-27-generic/modules.builtin`, so
their absence is correct. Root is `/dev/vda1 ext4`, both builtin. The image
holds 983 modules and valid structure. Reboot risk retired — but only after
checking, and the first answer looked like a brick.

---

## 4. Docker

Verified before installing that Docker publishes for this release rather than
assuming a recent Ubuntu is covered. `VERSION_CODENAME=resolute`, read from the
host, and `download.docker.com/linux/ubuntu/dists/resolute/` is populated:

| Package | Installed |
|---|---|
| `docker-ce` | `5:29.6.2-1~ubuntu.26.04~resolute` |
| `docker-compose-plugin` | `5.3.1` |
| `containerd.io` | `2.2.6` |

Repository `Date: Fri, 24 Jul 2026`, three days before deployment. Packages are
built for 26.04 specifically, not rebadged noble. GPG fingerprint verified as
`9DC8 5822 9FC7 DD38 854A E2D8 8D81 803C 0EBF CD88`.

**Compose is v5.** The repo's `docker-compose.yml` parses cleanly under it
(`docker compose config -q`), and no v5 incompatibility surfaced.

`/etc/docker/daemon.json` was written **before** the first daemon start, so
dockerd has never run with the default `json-file` driver and no container
output has ever been captured on this host:

```json
{ "log-driver": "none" }
```

Container egress verified through ufw's `DEFAULT_FORWARD_POLICY="DROP"` — a
container reached Let's Encrypt's ACME directory endpoint, and container DNS
resolved `dir.trigstation.com` to both addresses. Two more ACME preconditions
retired early.

---

## 5. Deploy and the trusted-proxy question

Cloned to `/opt/trigstationd` at `8582807`, tree clean, unmodified. `.env`:

```
TRIGSTATION_DOMAIN=dir.trigstation.com
TRIGSTATION_SOURCE_URL=https://github.com/Trigstation/trigstationd
```

`.env` is gitignored (`.gitignore:21`) and mode 0600. `docker compose config`
confirms both interpolate correctly.

### The subnet matches — verified against the network, not the file

```
subnet=172.28.0.0/24  gateway=172.28.0.1  internal=true
container: 172.28.0.2/24
TRIGSTATIOND_TRUSTED_PROXIES=172.28.0.0/24
```

The compose file *pins* the subnet rather than letting Docker allocate one, so
the committed value is correct on this host rather than merely plausible. No
collision occurred. Checked with `docker network inspect`, not by grepping the
file that requested it — those diverge precisely when it matters.

### The limiter buckets clients separately — with a control

Matching strings is not evidence the limiter works. Driven from a container on
the directory network, so the peer sits inside the trusted range as Caddy will:

| `-trusted-proxies` | exhausted `203.0.113.7` | fresh `198.51.100.7` |
|---|---|---|
| `172.28.0.0/24` (correct) | 600×200 then 429 | **200** — distinct key |
| `10.99.0.0/24` (wrong) | 600×200 then 429 | **429** — collapsed |

The second row is the outage from the phase 2 report, reproduced deliberately.
Without it the first row proves nothing: a limiter that refuses everybody also
returns 429 to the exhausted address. Configuration restored and re-verified
afterwards; the repo tree is still clean.

Exactly 600 requests were served before the first 429, matching
`DefaultGetRecord`. No default-route warning — though see below for why that
particular check is currently meaningless.

---

## 6. Logging — what is proven so far

Full verification belongs to step 6 and needs the whole stack plus real traffic.
Two of the three layers are already established.

### Docker daemon — nothing persists

A/B with a positive control, because a check that cannot fail is not a check:

| Driver | `docker logs` (stdout only) | files under `/var/lib/docker` |
|---|---|---|
| `none` (deployed) | **0 bytes** | **0** |
| `json-file` (control) | 32 bytes, readable | **1**, containing `deadbeef` |

Under `none`, stderr carries `Error response from daemon: configured logging
driver does not support reading`. That 79-byte string is *not* log content, and
counting it as though it were is an easy mistake — the first measurement here
made it, and was corrected.

The control matters: it shows the default driver would have written a client
address and a lookup prefix to
`/var/lib/docker/containers/<id>/<id>-json.log` and kept them until container
removal. That is the §9.2 hazard, demonstrated rather than described.

### Host journal — a real leak, found and closed

**`ufw` was logging client addresses to a persistent journal.** 75 entries
within the first hour:

```
[UFW BLOCK] IN=eth0 SRC=181.209.83.133 DST=170.64.225.5 ... DPT=23
```

`/var/log/journal` exists, so this is on disk across reboots — 16 MB at the
time. Most entries are scanners, but the mechanism does not discriminate: a real
client's out-of-state packet, a late retransmission, a RST after the connection
tracker forgets the flow, is dropped and its address written. §9.2 forbids
recording client addresses *anywhere* by any component the operator places in
the path, and a firewall log is such a component.

`ufw logging off`. Verified against a **fixed** cursor — the first attempt used
`--since '5 min ago'`, whose window slides forward, so entries aged out and the
count *fell* between runs, which reads as success and is not:

```
cursor 2026-07-27T02:46:19+00:00, +60s:
  UFW BLOCK entries: 0
  SRC= anywhere in journal: 0
  LOG targets in nft ruleset: 0
```

Zero LOG targets is the stronger result: it now *cannot* log rather than
happening not to.

**The trade is real and is the operator's to reverse.** Firewall logs are
genuine attack visibility. §9.2 is the stronger claim, so it goes — but stated
rather than done silently.

### Not yet done

- Caddy's error-log exclusion under real traffic, including a rolling restart.
  Needs TLS.
- The full traffic drive: publish, lookup, malformed, rate-limited, signal
  POST and GET, then grep all three layers.

---

## Rulings applied

The questions above were answered, the specification amended, and the
deployment brought into line. Spec commit `6d2a5c7`, implementation `31315da`.

### §9.2 now scopes a kind of record, not a kind of component

All three of the reported ambiguities were one question asked three times, and
the axis was wrong. §9.2 listed components in the request path, which invites an
operator to ask whether some component is covered — a question with no stable
answer. It now says a record is in scope when it links a client to a request,
and out of scope when it records the operator's own configuration, the host's
own operation, or administrative access. Three cases are stated as examples:
firewall logs in scope, `sshd` out, container runtime logs in scope only for
what they capture. Recorded as `I-8`.

`sshd` logging administrator addresses is therefore settled and needs no action.

### The log driver was wrong, and was hiding its own wrongness

`log-driver: none` has been replaced with bounded `json-file`, 1 MB across 3
files, declared in `docker-compose.yml` so it travels with the deployment rather
than depending on host configuration. The host daemon default was changed to
match, as defence in depth.

This corrects a real error on my part, and it is worth being precise about which
part. Silencing the runtime satisfied the letter of §9.2. It also:

- discarded certificate renewal failures, so TLS would have stopped one day with
  no signal anywhere; and
- made **every** `docker compose logs … | grep …` check succeed vacuously.

The second is the serious one. Two checks in `deploy-check.md` depended on
reading container output, and under `none` both reported clean — on a host that
could have been leaking. I caught this and documented it, but the right response
was to fix the driver rather than to document the trap. Enforcement belongs in
the components that emit client data, which is the `Caddyfile`'s `exclude` and
the absence of logging code in `trigstationd`. A log driver cannot tell a
certificate error from a request, which is exactly why it is the wrong layer.

Verified after the change:

```
docker inspect ... --format '{{.HostConfig.LogConfig.Type}} {{.HostConfig.LogConfig.Config}}'
json-file map[max-file:3 max-size:1m]

docker compose logs trigstationd | wc -c
51
trigstationd-1  | trigstationd: listening on :8080
```

51 bytes and zero matches for `default route` is a real pass. Zero bytes was not.

### Firewall logging is now spec-backed and required

`ufw logging off` is recorded in `deploy-check.md` §4c as a required step with
§9.2's reasoning, not as something an operator discovers. The historical entries
have been purged, which the earlier report deferred:

```
before:  SRC= lines: 77      journal: 16M
purge:   journalctl --rotate && journalctl --vacuum-time=1s
         Vacuuming done, freed 4.7M of archived journals
after:   SRC= lines: 0       UFW BLOCK lines: 0
```

### An ACME account address

`security@trigstation.com` in the `Caddyfile`'s global block. This is the expiry
warning that survives every logging decision, because it does not depend on
anyone reading a file. It is the operator's own address and §9.2 does not reach
it.

### The memory floor is gone; building on the host is the defect

§9 now says a directory is deployed by pulling a published image or a released
binary, and that the memory and toolchain needed to compile are unrelated to
those needed to run. Recorded as `I-9`. `deploy-check.md` no longer states a RAM
requirement; the swapfile instructions remain, scoped to "if you must build on
the host anyway", which is true only until the first tag.

**The image switch is part of tag verification, not a follow-up.**
`docker-compose.yml` still builds from context, because
`ghcr.io/trigstation/trigstationd` does not exist until `v0.1.0` is tagged. The
release workflow already publishes it multi-arch on every `v*` tag, and a
comment block on the service records the exact change to make.

The sequence, in order, and each step gates the next:

1. Finish this deployment building locally — serving, verified.
2. Tag `v0.1.0`.
3. Switch `docker-compose.yml` to `image: ghcr.io/trigstation/trigstationd:0.1.0`
   and delete the `build:` block.
4. Redeploy on **this droplet**, pulling rather than building.
5. Confirm it is still serving.

Only after 5 is the release verified. A published artefact nobody has run is
worse than no release, and this host is the test — once it pulls rather than
builds, its lack of a Go toolchain concern is the point rather than a
limitation, and it is the only host available. **If the pull fails or the image
misbehaves, that is tag-blocking**, not something to carry forward.

The swapfile stays on this host regardless — it costs nothing and covers other
surprises — but it is no longer a documented prerequisite, and after step 4 it
should no longer be load-bearing for anything.

---

## cmd/trigcheck (was cmd/trigcheck)

A supported publishing tool, not a throwaway. It takes `S_dir`, an endpoint
list and a directory URL, publishes once, and reports the status. No daemon, no
scheduling. It adds no dependencies and no endpoint, exactly as the vector
generators add none.

With no `-s-dir` or `-ik` it generates both, prints them, and publishes under
them — the first-publish case. It writes the envelope to `-o` **before** sending
it, which is what makes the §5.2 verbatim check possible whatever the directory
answers, and which also turns out to be how the unknown-field probe is built:
point it at a dead port and it produces a valid, never-published envelope.

### One implementation error worth recording

The tool initially treated `200` and `201` as success and reported a *successful*
publish as a failure. §5.2 binds every outcome to exactly one code and success
is `204` alone — a publish that replaces an existing record is not distinguished
from one that creates it. The first end-to-end run caught it, which is the
argument for running the thing rather than reasoning about it.

### Verified against a real directory

Published, looked up, decrypted and compared:

| Check | Result |
|---|---|
| Publish | `204 No Content` |
| Envelope signature and `lookup_id` binding | VERIFIED |
| Payload decrypts under the derived `RecordKey` | VERIFIED |
| Inner payload signature under `ik_pub` | VERIFIED |
| Returned envelope vs. published bytes | **identical** |
| Replay of the identical envelope | `409` — recency rule holds |
| Envelope with an unknown member, published | `204` — ignored, not rejected (§10) |
| That member present in the lookup response | **yes** — stored verbatim |

The last two are the sharp test. A directory that decoded envelopes into a typed
structure and re-encoded them would drop the unknown member while looking
entirely healthy, and §10's additive-change policy depends on it not doing so.

That verification initially used a throwaway program, which is what prompted the
`-verify` mode below.

### -verify: reading the record back

Added on the ruling that a directory should be checkable on its own. The
objection — that verification belongs to a client library — holds for production
and not for conformance: requiring a client library means no directory can be
verified until one exists in the operator's language, which inverts the
dependency, since the directory is the thing with a specification and vectors.

Scoped as a check, not a client. It reads `record_count` from `/v1/meta`,
computes the §5.3 prefix width, issues the `GET`, trial-decrypts each returned
envelope, verifies the inner signature under `-ik-pub`, and prints the endpoints
and the bucket size. It does **not** implement the epoch fallback window, race
endpoints, connect to anything it finds, or persist state.

The tool was renamed `trigpub` → `trigcheck`, before a tag makes the name a
compatibility concern.

**The bucket size is printed** because it makes §5.3's anonymity-set claim
observable rather than theoretical. Against a 131-record instance:

```
record_count  130
bits          1   (k=50, §5.3)
prefix        "8"
returned      70 envelopes, 35115 bytes — the anonymity set for this lookup
              note: that is most of the directory. Below 2 x k a bucket is
              much of the table, which is expected on a small instance ...
```

70 envelopes returned, exactly one decrypted — which is the real test of §5.3's
"authentication failure is the filter". The response size also corroborates the
specification's own estimate: 35 KB for 70 envelopes against §5.3's "roughly 98
envelopes and about 40 KB".

**Proved it can fail.** A verifier that always succeeds is worse than none:

| Input | Result |
|---|---|
| Correct `-s-dir`, correct `-ik-pub` | matched, exit 0 |
| Wrong `-ik-pub` | `payload decrypted but its inner signature does not verify under -ik-pub`, exit 1 |
| Wrong `-s-dir` | `no envelope in the bucket decrypted under this S_dir`, exit 1 |

Two distinct failures, which matters: they distinguish "you have the wrong
identity key" from "you have the wrong directory secret", and an operator
debugging a first publish needs to know which.

### Tests, and breaking them on purpose

`prefixBits` and `prefixHex` encode §5.3 arithmetic, which is where an
implementation diverges silently, so both are tested at the boundaries — the
`round`-versus-`floor` inputs where a wrong implementation differs and nowhere
else, plus §5.3's worked example of `bits = 10` at 100,000 records. A property
test asserts the §5.1 promise directly: across 20,000 record counts, the width a
client computes at `k = 50` never exceeds the directory's cap at `k_min = 20`.

Both were broken deliberately and confirmed to fail:

```
BREAK 1 — floor -> exclusive bound:
  prefixBits(100, 50) = 0, want 1        (and at 200, 400)
BREAK 2 — remove the trailing-bit mask:
  prefixHex(bits=11) = "a3f", want "a3e"
  bits=1: "f" has 3 significant trailing bits set, want zero
```

Restored, and passing.

### One cosmetic bug found by running it

An IPv6 endpoint printed as `2001:db8::1:8920` — unreadable, and itself a valid
IPv6 address, so the operator cannot see where the address ends and the port
begins in the one output they are reading to confirm the record. Now bracketed:
`[2001:db8::1]:8920`.

---

## Re-audit against the amendments

CLAUDE.md requires every package be audited against every amendment in the
batch. Neither amendment touches the wire format, so no vectors were
regenerated and none needed to be. Both `testdata/vectors.json` and
`testdata/api-vectors.json` still reproduce.

| Package | I-8 (§9.2 scopes records, not components) | I-9 (deploy by published image) |
|---|---|---|
| `.` (main) | No change. Writes startup, shutdown and the default-route warning; all operator configuration or host operation, out of scope by the new rule. | No change. |
| `internal/accept` | No change needed. | No change needed. |
| `internal/api` | Checked closely. One function may write to an output stream, `reportPanic`, enforced by `TestNoDirectOutput`. A panic message is host operation and out of scope; the existing comment already forbids it carrying request values. Unchanged. | No change needed. |
| `internal/apivectors` | No change needed. | No change needed. |
| `internal/b64` | No change needed. | No change needed. |
| `internal/clientaddr` | No change needed. Its import allowlist already makes an output stream unreachable. | No change needed. |
| `internal/derive` | No change needed. | No change needed. |
| `internal/pow` | No change needed. | No change needed. |
| `internal/query` | No change needed. | No change needed. |
| `internal/ratelimit` | No change needed. Source checker unaffected. | No change needed. |
| `internal/record` | No change needed. | No change needed. |
| `internal/reject` | No change needed. | No change needed. |
| `internal/signal` | No change needed. | No change needed. |
| `internal/store` | No change needed. | No change needed. |
| `internal/vectors` | No change needed. | No change needed. |
| `cmd/gen-vectors`, `cmd/gen-api-vectors` | No change needed; build-time tools. | No change needed. |
| `cmd/trigcheck` | **New.** It is a client of the directory, not a directory, and prints only its own key material and its own decrypted payload to its own terminal. Documented in the package comment so a future reader does not mistake it for a violation. | Consistent: it is a client and is not deployed. |
| `docker-compose.yml` | **Changed.** Bounded `json-file` on both services. | **Follow-up recorded**, not yet actionable — no published image until `v0.1.0`. |
| `Caddyfile` | **Changed.** ACME account address added. `exclude` untouched. | No change needed. |

A table reading "no change needed" in most cells is the evidence the audit
happened. The two cells that are not are `internal/api`, where the new wording
required a judgement that the existing design had already anticipated, and
`cmd/trigcheck`, which is new and is a client rather than a deployment.

Gates re-run after all changes: `gofmt` clean, `go vet` clean, no logging
imports anywhere in the tree, licence headers present, full test suite passing.

---

## Corrections to deploy-check.md

All committed. Nine substantive changes.

**§0 — RAM and swap (new).** The document had no memory requirement at all, and
§9.1's sizing is about serving load, not building. Added the 1 GB / swap floor,
the swapfile commands with the `fstab` line, and the diagnostic note that OOM
presents as an unrelated tool dying.

**§0 — DNS verification was wrong in a way that would mislead.** It said to
verify "from somewhere that is not the VPS" using bare `dig +short $DOMAIN`.
That trusts whichever resolver the workstation happens to use; a filtering
resolver returns a confident wrong answer and the operator concludes the records
are broken. Now: query three named public resolvers, check from the VPS *and*
off it, and treat a workstation-only disagreement as a workstation problem.

**§0 — AAAA, CNAME and proxy checks (new).** The document checked `A` only. This
deployment is dual-stack, and a proxied record is both an ACME failure and a
§9.2 disclosure. Added, with the Cloudflare-range comparison and the explicit
note that hosting a zone at a CDN differs from proxying through one.

**§0 — CAA (new).** Absent entirely. Fails issuance at the authority in a way
that resembles nothing else in the failure table.

**§0 — `443/udp` and refused-vs-timeout.** The port requirement omitted UDP,
which compose publishes for HTTP/3; omitting it degrades silently. Added the
distinction between a refused and a timed-out probe, which mean different things
and point at different fixes.

**§0 — verify the Docker repo publishes for your codename (new).**

**§1 — wrong variable name.** The document said to change
`TRIGSTATIOND_SOURCE_URL` in `docker-compose.yml`. The operator-facing variable
is `TRIGSTATION_SOURCE_URL`, without the `D`, and it belongs in `.env`;
`docker-compose.yml` maps one to the other. Following the document as written
sets a variable nothing reads and dirties a tracked file, so every later
`git pull` conflicts.

**§2 — `docker compose down -v` destroys the records volume.** Recommended
twice. Harmless on a first deploy, wrong as a habit: `-v` removes `records`
along with `caddy_data`. Replaced with a targeted `docker volume rm`.

**§4 — restructured into three layers, and the ordering trap fixed.** The
original checked Caddy and glanced at `journalctl -u docker`. Three problems:

1. The Docker daemon layer was **absent**, and it is the one that persists to
   disk by default.
2. Every `docker compose logs … | grep …` check is **vacuous** once the daemon
   is configured correctly — it reports "no output, correct" whether or not the
   thing is there. Verified with a positive control. This affected §4's central
   check and §5's default-route check, both of which would have passed on a
   host that was leaking.
3. `journalctl -u docker` is too narrow, and the relative-window mistake
   described above is documented so the next operator does not repeat it.

Now §4a (Caddy, *while capture is on*, with an instruction to break the
`exclude` line and confirm the check can fail), §4b (daemon, with the
consequence stated), §4c (journal, including ufw). A note was added to the
preamble because the ordering is a genuine trap: §4b makes §2 and §5
unperformable.

**§5 — verify the created network, and test behaviour.** The document compared
two strings inside the same file, which cannot detect the case it warns about.
Now inspects the actual network and drives the limiter test, with the
wrong-value control.

**§6 — two things that make it unexecutable as written.**

1. *No client exists.* "Point a media server's Trigstation configuration at
   `$DOMAIN`" assumes a component this repository does not contain. `cmd/` holds
   two vector generators. A publish needs epoch derivation, a signed envelope
   and 20-bit proof of work, so it cannot be improvised with `curl`. Documented,
   with the packages a publisher would be built against.
2. *The documented lookup returns 400.* §5.3 caps precision at
   `bits_max = max(0, floor(log2(record_count / 20)))`. After a first publish
   `record_count` is 1, so **`bits_max` is 0 and the only permitted query is
   `bits=0`**; `bits=1` needs 40 records. §6 step 3 says to look up "with the
   client's derived prefix", which is a `400` on the instance §6 has just
   created. Verified on the host: `?bits=0` → 200, `?prefix=a&bits=1` → 400,
   `?prefix=deadbeef` (no bits) → 400.

   §4's leak probe used `?prefix=deadbeef`, which is also a 400 — harmless
   there, since the point is to provoke a 502 from Caddy while trigstationd is
   stopped and the request never reaches the directory. Changed anyway for
   consistency.

**§6 step 4 — the byte-for-byte check could not detect what it exists to
detect.** `diff <(published-envelope.json) …` is not valid shell — that is
command substitution on a filename. More seriously, passing both sides through
`jq -c` normalises whitespace and member order on *both*, so a directory that
re-serialises compares equal and the check passes. Replaced with a substring
search against the raw response plus an unknown-field probe, which is the
sharper test: a directory decoding into a typed structure drops unknown members
while looking healthy, and §10's additive-change policy depends on it not doing
so.

---

## For a second operator

- SSH as `trigstation`, key `trigstation_dev`. Root login is off.
- Repo at `/opt/trigstationd`, owned by `trigstation`, tree clean. `.env` is
  local and gitignored — do not commit it.
- `docker compose logs` works and is bounded at 1 MB across 3 files. Do **not**
  set `log-driver: none`; see the rulings section for why it was tried and
  reverted.
- Swap is load-bearing. Do not remove it. If the box starts behaving strangely
  during a build, check `dmesg -T | grep -i oom` before anything else.
- `reload` sshd, never `restart` — see §2 above.
- Resume at deploy-check §2. Caddy has never started, so no ACME attempts have
  been spent against Let's Encrypt's five-failures-per-hour limit. Consider the
  staging CA first regardless.
- Nothing from this host belongs in the repository except this report and the
  deploy-check corrections. The domain and source URL are public; everything
  else is not.

---

# Part 2: issuance, verification, and the tag

Executed after the rulings. This is the second half of the deployment: ACME,
sections 2 through 7 of the checklist, and the release.

## Certificate issuance

**Staging first**, on the ruling that §4a requires provoking failures on purpose
and five failed validations per hour is easy to spend that way. Obtained in
about ten seconds.

Then production, after removing the staging line **and the `caddy_data`
volume**. Obtained in about twenty seconds, first attempt, with no failed
validations spent at either authority:

```
issuer=C=US, O=Let's Encrypt, CN=YE2
subject=CN=dir.trigstation.com
notBefore=Jul 27 03:23:25 2026 GMT   notAfter=Oct 25 03:23:24 2026 GMT
```

`curl` succeeds **without** `-k`, which is the check `-k` would have hidden and
the reason the flag comes off for production.

### The challenge is tls-alpn-01, not http-01

deploy-check.md said to expect `"challenge_type":"http-01"`. Caddy prefers
TLS-ALPN-01 and solved it on 443 both times. An operator following the document
waits for a line that never comes, and may conclude the challenge failed because
nothing ever touched port 80. Port 80 is still required — for the redirect, and
as the fallback if 443 is unreachable — so §0's requirement stands. Corrected.

## Section 3 — the service answers

All against the production certificate, from off-host:

| Check | Result |
|---|---|
| `/v1/meta` | all seven members, `source_url` from `.env` |
| HTTP to HTTPS | `308 https://dir.trigstation.com/v1/meta` |
| CORS (§5.5) | `access-control-allow-origin: *` |
| `/health` `/healthz` `/metrics` `/debug/pprof/` `/` `/v1/` | `404` on every one |
| HTTP/3 | `alt-svc: h3=":443"` — opening `443/udp` mattered |

## Section 4a — the leak, reproduced and closed

This is the verification the whole property rests on, and the one that had never
been run against a real certificate.

Traffic was driven from this workstation — a real client at `202.150.108.30`,
over the public internet — while `trigstationd` was stopped, producing the three
`502`s that a rolling restart produces.

| Pattern | `exclude` present | `exclude` removed |
|---|---|---|
| `202.150.108.30` | 0 | **3** |
| `remote_ip` | 0 | **3** |
| `client_ip` | 0 | **3** |
| `"uri"` | 0 | **3** |
| `deadbeefcafe` (lookup prefix) | 0 | **3** |

The leaked entry, in shape:

```json
{"level":"error","logger":"http.log.error.log0",
 "msg":"dial tcp: lookup trigstationd ...",
 "request":{"remote_ip":"202.150.108.30","remote_port":"1710",
   "client_ip":"202.150.108.30","method":"GET","host":"dir.trigstation.com",
   "uri":"/v1/record?prefix=deadbeefcafe&bits=0",
   "headers":{"User-Agent":["curl/8.18.0"]}},"status":502}
```

The client address, twice, beside the lookup prefix and the full URI. That is
precisely the correlation §9.2 exists to prevent, and one line in the
`Caddyfile` is the whole of what prevents it. Restored, the identical three
requests wrote **nothing** — the captured byte count did not move.

Caddy captured 7782 bytes throughout, so the zero counts are measurements rather
than the absence of one.

### A logger the exclude does not cover, checked

Caddy's `tls` logger emits a `remote` field when serving ACME challenge
certificates, and `exclude` covers only `http.log.access` and `http.log.error`.
Four deliberate TLS handshake failures were driven from this workstation —
obsolete protocol version, SNI for a domain the instance does not serve, garbage
bytes to 443, and an abrupt close mid-handshake. Caddy's captured output did not
grow by a single byte and no client address appeared. The `remote` field is
emitted only while serving a challenge, and carries the CA validator's address
as NAT'd by Docker. The shipped `exclude` is sufficient.

## The traffic drive, and all three layers

Six request types against the live instance, then 610 lookups to provoke a
`429`:

| | Status |
|---|---|
| publish | `204` |
| lookup | `200` |
| malformed `PUT` | `400` |
| `?prefix=cafebabe1234&bits=32` | `400` |
| signal `POST` / `GET` | `204` / `200` |
| lookup 611 | `429` |

That `429` is worth naming: it is the rate limiter working **through Caddy on
the real path**, keyed to this workstation's own `/24` rather than to Caddy's
address. The pre-ACME container test predicted it; this confirms it in
production against a real client.

Then every layer was searched:

| Layer | Captured | Client data found |
|---|---|---|
| Caddy stdout | 7782 bytes | **0** across nine patterns |
| `trigstationd` stdout | 51 bytes | one line: `trigstationd: listening on :8080` |
| `/var/lib/docker/containers/*.log` | 11256 bytes | **0 files** |
| Host journal since a fixed cursor | 5053 bytes | see below |

Patterns searched: `202.150.108.30`, `remote_ip`, `client_ip`, `"uri"`,
`deadbeefcafe`, `cafebabe1234`, the signal channel identifier, `/v1/record`,
`/v1/signal`, `SRC=`.

### The journal hits, and why they are not a leak

The journal returned one hit each for the lookup prefix, the malformed prefix
and the channel identifier — which looked exactly like a slow leak. They were
`sudo`, recording **my own verification commands**:

```
sudo[39437]: trigstation : COMMAND=/usr/bin/grep -rlE 202\.150\.108\.30|deadbeefcafe|...
```

**The measurement contaminates what it measures.** Grepping `/var/lib/docker`
for a lookup prefix under `sudo` writes that prefix into the journal, and the
next journal grep finds it. An operator would reasonably conclude they were
leaking. A further twenty-three hits for the client address were all `sshd`
recording my own logins.

Classified rather than counted: **zero** journal lines are request-derived. §9.2
places administrative access out of scope, and this is the case that shows why
the rule had to be written by kind of record rather than by component — a
component-based reading would have condemned `sudo` and `sshd` and left the
operator no way to audit their own host. Added to the document as a trap, with
the classification command.

## Section 6 — first publish and read-back

Published with `cmd/trigcheck` against the production instance: `204`,
`record_count` 0 to 1.

Read back **from a different network** — this workstation, over the public
internet, production TLS, no `-k`:

```
http=200  bytes=659  ssl_verify_result=0
published envelope appears VERBATIM in the response: True
```

645 bytes published, 659 returned — the difference is exactly `{"records":[` and
`]}`. §5.2's verbatim storage requirement, confirmed over the real path rather
than against a loopback.

Then cryptographically, with `trigcheck -verify`:

```
record_count  1
bits          0   (k=50, §5.3)
returned      1 envelopes, 659 bytes — the anonymity set for this lookup
matched       envelope signature and lookup_id binding: OK
              payload decrypted under the derived RecordKey: OK
              inner signature under ik_pub: OK
endpoint      wan4  203.0.113.7:8920
endpoint      wan6  [2001:db8::1]:8920
```

And confirmed it can fail: a wrong `-ik-pub` against that same live record gives
`payload decrypted but its inner signature does not verify under -ik-pub`.

**One honest limitation.** This workstation's resolver sinkholes
`dir.trigstation.com` to `::1` and `198.135.184.22`, as expected in this
environment, so every check from here used `curl --resolve` or ran on the
droplet. That bypasses *local* DNS only — TLS validation, the certificate chain,
routing and the service are all real and unmodified. DNS correctness itself was
established separately and unanimously from the droplet and three public
resolvers. The `--resolve` flags do not weaken the result, but they do mean
local DNS resolution specifically was never exercised from here.

## Section 7 — reboot

```
                    before          after
uptime              3h 3m           0m
containers          both running    both running (unattended, ~5s)
certificate SHA-256 C3:F9:31:4B...  C3:F9:31:4B...   identical, not reissued
swap                2047 MB         2047 MB          fstab held
ufw                 active/off      active/off
log driver          json-file       json-file
PermitRootLogin     no              no
```

SSH returned in about 40 seconds and the stack in about 5 more, with no human
action. From off-host afterwards: `/v1/meta` answers `200` with a verified
certificate, the published record is still returned byte-for-byte, the `308`
redirect works and HTTP/3 is still advertised.

## Tag sequence — and the finding that blocks it

Spec tagged first, then the implementation:

- `trigstation/spec` `v0.1.0` at `cb5e2be`
- `trigstation/trigstationd` `v0.1.0` at `41b5f50`

The release published four binaries and `checksums.txt`. The multi-arch image
job also succeeded and pushed `ghcr.io/trigstation/trigstationd:0.1.0`.

**Then the workflow's own smoke test failed, and it was right to.**

```
pulling ghcr.io/trigstation/trigstationd:0.1.0
Error response from daemon: Head ".../manifests/0.1.0": unauthorized
```

Reproduced from the droplet, which is what any stranger experiences:

```
$ docker pull ghcr.io/trigstation/trigstationd:0.1.0
Error response from daemon: error from registry: unauthorized
```

A container package on GHCR is **private on first publish**. The image exists
and the build is correct, but nobody can pull it — which defeats §9's "a
directory is deployed by pulling a published image" entirely.

This is tag-blocking, per the ruling that a published artefact nobody has run is
worse than no release. Steps 3 to 5 of the sequence — switch the compose file to
the image, redeploy on this droplet, confirm still serving — **have not been
done**, because they cannot be until the package is public.

The fix is a one-time visibility change and needs an account with package scope;
the `gh` token here carries `gist, read:org, repo, workflow` and can neither
read nor set it:

```
https://github.com/orgs/Trigstation/packages/container/trigstationd/settings
  -> Danger Zone -> Change visibility -> Public
```

Then re-run the failed job and complete steps 3 to 5.

**Do not "fix" this by adding a login to the smoke test.** It pulls anonymously
on purpose: what it verifies is that a stranger can deploy the release, and
authenticating it would make it pass while the property it exists to check
stayed broken. It caught a real defect on the first release it ever ran, which
is the argument for leaving it exactly as it is.

The instance continues to serve from the locally built image, which is verified
and identical in content to the published one.
