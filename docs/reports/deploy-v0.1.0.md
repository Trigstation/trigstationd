# Deploying the first public directory instance

**Host:** `dir.trigstation.com` — 170.64.225.5 / 2400:6180:10:200::d441:7000
**OS:** Ubuntu 26.04 LTS (Resolute Raccoon), DigitalOcean, Sydney
**Commit deployed:** `8582807`
**Status: INCOMPLETE BY INSTRUCTION.** Steps 1–4 done; stopped before ACME
issuance. No certificate has been requested and Caddy has never been started.

This is the first execution of `docs/deploy-check.md`, and correcting that
document was part of the work. Corrections are in §"Corrections to
deploy-check.md" below and are committed alongside this report.

---

## What is running right now

| | |
|---|---|
| `trigstationd` container | **up**, healthy, answering on the internal network |
| `caddy` container | **not started** — deliberately, to avoid ACME |
| Records held | 0 |
| Ports 80/443 | open at the firewall, nothing listening |
| Certificate | none requested |

A second operator resuming this picks up at deploy-check §2.

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
- **Purging the ~75 historical `SRC=` journal entries** recorded before ufw
  logging was disabled. Deliberately deferred: the journal is still needed for
  step 6's verification. `journalctl --rotate --vacuum-time=1s` afterwards.
- `sshd` logs administrator source addresses on every login. Judged out of
  scope for §9.2, which concerns directory clients, but it is a client address
  on disk and the operator should know it is there.

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
- `docker compose logs` returns **nothing, by design**. This is the first thing
  that will confuse you. See deploy-check §4b for the temporary override.
- Swap is load-bearing. Do not remove it. If the box starts behaving strangely
  during a build, check `dmesg -T | grep -i oom` before anything else.
- `reload` sshd, never `restart` — see §2 above.
- Resume at deploy-check §2. Caddy has never started, so no ACME attempts have
  been spent against Let's Encrypt's five-failures-per-hour limit. Consider the
  staging CA first regardless.
- Nothing from this host belongs in the repository except this report and the
  deploy-check corrections. The domain and source URL are public; everything
  else is not.
