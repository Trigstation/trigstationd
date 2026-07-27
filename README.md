<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Simon Wright
-->

# trigstationd

> **This project is archived.** It is a complete, tested implementation of the
> Trigstation directory protocol — it built, deployed, served under a production
> certificate, and passed its own conformance vectors. It stopped for reasons of
> premise rather than execution.
>
> The directory is a locator, not a transport. It coordinates connections that
> the participants' networks already permit, and relay was an explicit non-goal.
> So the case where the alternatives fail hardest — CGNAT — is the case this does
> not solve either. Cloudflare Tunnel and Tailscale cover the intended use case
> at no cost, with clients that already exist.
>
> The design was also scaled for a public service at 100,000 servers. Every hard
> constraint here — zero-knowledge storage, blinded lookups, replaceable
> instances, a wire format frozen for a decade — follows from that. At the scale
> actually needed, a host you control and a domain you own is the whole answer.
>
> The specification, decision log and conformance vectors remain accurate and are
> free to reuse under their respective licences.


Trigstation is a zero-knowledge coordination service that lets a self-hosted
media server be located by its paired clients over the internet. It stores
encrypted address records and brokers short-lived rendezvous channels so that
two devices which already know each other can find each other again after an
address change. It never carries media, holds no accounts, and cannot read what
it stores: records are encrypted to the paired clients, the server holds no
decryption key, and authorisation is a signature on the record rather than a
credential presented to the service. `trigstationd` is the reference
implementation.

`DIRECTORY-SPEC.md`, in the `spec` repository, is authoritative. Where this code
and the spec disagree, the spec is right and the code is a bug.

## Running an instance

A directory is meant to be replaceable, which means running one has to be
uninteresting. It is one static binary, one SQLite file and a certificate.

Anyone may run one. Instances never talk to each other, hold no shared state,
and need no permission from anybody — a server publishes to every directory it
knows about, independently, and a client queries all of them in parallel.
Expected load is modest: at 100,000 registered servers, about six publishes and
twenty lookups a second, roughly 400 MB of storage and 150 GB of egress a month
(§9.1). That is a small VPS, on the order of NZ$10–25 a month.

## Getting it

Three ways, in increasing order of effort. Building from source is last, and it
is not the expected path — invariant 6 says any instance is replaceable, and
that only means something if getting one does not begin with installing a Go
toolchain.

### A published image

```sh
docker run -p 8080:8080 -v trigstation:/data ghcr.io/trigstation/trigstationd:latest
```

Multi-arch, `linux/amd64` and `linux/arm64`. This is plain HTTP with no
certificate — enough to look at `GET /v1/meta` and decide whether you want to
run one properly. For that, see the compose stack below.

### A release binary

Every release attaches static binaries for `linux/amd64`, `linux/arm64`,
`darwin/arm64` and `windows/amd64`, plus a `checksums.txt`. No runtime
dependencies, no libc requirement, nothing to install:

```sh
curl -LO https://github.com/Trigstation/trigstationd/releases/latest/download/checksums.txt
curl -LO https://github.com/Trigstation/trigstationd/releases/latest/download/trigstationd_vX.Y.Z_linux_amd64
sha256sum -c checksums.txt --ignore-missing
chmod +x trigstationd_*_linux_amd64
./trigstationd_*_linux_amd64 -h
```

Verify the checksum. It costs one command, and the whole argument for running
your own directory is that you do not have to trust somebody else's.

### From source

```sh
git clone https://github.com/Trigstation/trigstationd
cd trigstationd
CGO_ENABLED=0 go build -o trigstationd .
```

`CGO_ENABLED=0` matters: it is what makes the result a single static file that
cross-compiles from one machine to any target. See [Building](#building).

## Deploying with Docker

Three steps: set a domain, get a certificate, run. The second one happens by
itself.

Point your domain's `A` (and `AAAA`) records at the host first — Caddy proves
control of the domain over ports 80 and 443 to obtain a certificate, and cannot
do that before DNS resolves.

```sh
git clone https://github.com/trigstation/trigstationd
cd trigstationd
cp .env.example .env        # then set TRIGSTATION_DOMAIN in it
docker compose up -d
```

Confirm it is answering:

```sh
curl https://directory.example.com/v1/meta
```

```json
{"v":1,"record_count":0,"max_ttl":172800,"max_record_bytes":4096,
 "pow_bits":20,"signal":true,"source_url":"https://github.com/trigstation/trigstationd"}
```

That is the whole deployment. The stack is two containers: Caddy, which holds
the certificate and terminates TLS, and `trigstationd`, which is not published
to the host at all and is reachable only from Caddy.

### Things worth knowing before you edit the compose file

**`TRIGSTATIOND_TRUSTED_PROXIES` is not boilerplate.** It is set to the
directory network's subnet, and the network's subnet is pinned rather than
allocated by Docker so that the two can be written down and match on every
machine. They are one setting written twice; change one and you must change the
other.

Deleting it causes an outage, not a degradation. The directory rate limits per
source address (§6.2), and behind a proxy it sees *Caddy's* address on every
request. Without this setting every client in the world shares one limiter key,
the hourly allowance is spent in seconds, and the instance then refuses
everybody. It is also not simply "trust the header": §6.4 requires a forwarded
address to be believed only when the immediate peer is on the configured list,
or any client could choose its own limiter key by sending its own
`X-Forwarded-For`.

**Caddy's access log is off, and its error log is off with it.** Caddy writes no
access log unless asked, but its *error* log is on by default and records
`remote_ip`, `client_ip` and the full URI for every failed request — so a
restart of the directory would be enough to dump every current client address
into the host's journal. The `Caddyfile` turns both off and explains how. A
directory whose proxy logs client addresses has given up the property the
service exists to have.

**The certificate volume matters.** `caddy_data` holds the certificate and the
ACME account key. Losing it means re-issuing on every start, which will hit the
certificate authority's rate limits and leave the instance without TLS.

### Without Docker

The binary needs no runtime dependencies and does not terminate TLS; put any
reverse proxy in front of it and pass `-trusted-proxies` the network that proxy
reaches it on.

```sh
CGO_ENABLED=0 go build -o trigstationd .
./trigstationd -db /var/lib/trigstation/trigstation.db \
               -listen 127.0.0.1:8080 \
               -trusted-proxies 127.0.0.1/32
```

## Configuration

Every setting is a flag with an environment variable behind it, so the same
binary suits a systemd unit and a container without a config file. The flag wins
where both are given. `trigstationd -h` prints this list.

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `-listen` | `TRIGSTATIOND_LISTEN` | `:8080` | Address to listen on. Plain HTTP; TLS is terminated upstream (§9). |
| `-db` | `TRIGSTATIOND_DB` | `trigstation.db` | SQLite database path, or `:memory:`. The container image defaults it to `/data/trigstation.db`. |
| `-source-url` | `TRIGSTATIOND_SOURCE_URL` | the upstream repository | Where this instance's source can be obtained. Published as `source_url`. May not be empty — see below. |
| `-trusted-proxies` | `TRIGSTATIOND_TRUSTED_PROXIES` | *(empty)* | CIDR blocks whose `X-Forwarded-For` may be believed. Empty ignores the header. **Set this when running behind a proxy** (§6.4). |
| `-pow-bits` | `TRIGSTATIOND_POW_BITS` | `20` | Proof-of-work difficulty on publish, in leading zero bits. Advertised in `/v1/meta`; may be raised under load (§6.1). |
| `-max-ttl` | `TRIGSTATIOND_MAX_TTL` | `172800` | Maximum record lifetime, in seconds. |
| `-max-record-bytes` | `TRIGSTATIOND_MAX_RECORD_BYTES` | `4096` | Maximum envelope size as transmitted. |
| `-signal` | `TRIGSTATIOND_SIGNAL` | `true` | Broker signal channels. When off, `/v1/meta` reports `signal: false` and `/v1/signal/{id}` answers 404. |
| `-rate-put` | `TRIGSTATIOND_RATE_PUT` | `600` | `PUT /v1/record` allowance per source per hour. See the note below. |
| `-rate-get` | `TRIGSTATIOND_RATE_GET` | `600` | `GET /v1/record` allowance per source per hour. |
| `-rate-signal` | `TRIGSTATIOND_RATE_SIGNAL` | `600` | Signal channel allowance per source per hour. |

Rate limits are counted per class and keyed by a truncated address — IPv4 to
`/24`, IPv6 to `/64` — held in memory and discarded when the window elapses. A
`/24` key means up to 256 hosts share a bucket, so §6.4 says to set the
allowances well above honest use rather than tightly. Honest publish volume is
about one request per server per day.

> **Deploying publicly for the first time?** Work through
> [docs/deploy-check.md](docs/deploy-check.md) instead of this section alone. It
> covers certificate issuance and its failure modes, the logging verification
> below, the trusted-proxy setting, and a first publish-and-lookup against the
> live instance — which is the only check that exercises real DNS, a real
> certificate and a real client together.

### Verifying that your deployment logs nothing

`DIRECTORY-SPEC.md` §9.2 makes this a property of the **deployment**, not of the
binary, and requires an operator to verify it rather than assume it. The
directory contains no code to log a request; that is worth nothing if something
else in the path does it for you.

Three things see your clients, and all three need checking:

**1. The directory.** Should emit one line ever — the startup banner.

```
docker compose logs trigstationd
# trigstationd: listening on :8080
```

Anything else is a bug; please report it. A panic report is the one exception,
and it deliberately carries the fault and the stack but no request context.

**2. The proxy.** Caddy's access log is off by default, **but its error log is
on**, and that one records `remote_ip`, `client_ip` and the full request URI —
including the lookup prefix — on any per-request failure. A rolling restart of
the directory is enough to write every current client's address to your journal.

Disabling the access log does **not** stop it: they are different loggers. The
shipped `Caddyfile` excludes both. To verify on your own deployment, provoke a
failure and check:

```
docker compose stop trigstationd
curl -sk https://your.domain/v1/record?prefix=deadbeef -o /dev/null   # 502
docker compose start trigstationd
docker compose logs caddy | grep -iE 'remote_ip|client_ip|deadbeef|"uri"'
# must print nothing
```

If that grep prints anything, your proxy is logging your users and the property
this service claims is not one you have.

**3. The container runtime and the host journal.** Docker captures whatever the
containers write to stdout and stderr. With both silenced there is nothing to
capture, which is why steps 1 and 2 are the whole of it — but if you add a
logging driver, a sidecar, or a log shipper, you have added a fourth thing that
sees everything and you need to check it too.

If you put a CDN in front for DDoS protection, understand that it sees every
client address and every lookup prefix in the clear. That is the correlation
data this design exists to remove, handed to a third party. It is a moved trust
boundary, not a hardened one.

### If publishers report intermittent 429s, raise the limits

Rate limiting keys on a **truncated** source address — IPv4 to `/24`, IPv6 to
`/64` — because §6.4 forbids retaining the full one. A `/24` sounds like 256
hosts, and behind carrier-grade NAT it can be thousands of subscribers sharing
one key.

So a 429 on publish is more likely to mean "a lot of honest servers share one
carrier" than "somebody is flooding us". §5.2 response bodies carry no
diagnostic detail, so it reaches the operator of the *publishing* server as a
directory that intermittently refuses them for no visible reason — the least
diagnosable failure this service can produce.

The defaults sit far above honest use: at roughly ten publishes per server per
day, 600 per hour is about six thousand honest servers behind one key. If you
see 429s on publish anyway, **raise `-rate-put` rather than assume abuse.**
Proof of work (§6.1) is the primary defence against flooding regardless of what
the limiter is set to; the limiter is the second line, not the first.

## What this service will not grow

- **No request logging.** Not a setting that defaults to off: the code to log
  request paths, client addresses, lookup prefixes or channel identifiers does
  not exist in this program. An operator who cannot log is one who cannot be
  compelled to produce logs, and that is the point.
- **No fifth endpoint.** The API is `GET /v1/meta`, `PUT /v1/record`,
  `GET /v1/record` and the signal channel, and it stays at four operations
  (§10). There is no `/health`, no metrics endpoint and no admin route.
  `GET /v1/meta` is unauthenticated, cheap and always present; use it.
- **No accounts.** No users, no API keys, no allowlist, no CAPTCHA.

## Building

```sh
CGO_ENABLED=0 go build ./... && CGO_ENABLED=0 go vet ./...
CGO_ENABLED=0 go test ./...
```

`CGO_ENABLED=0` is a constraint, not a preference. The deployment story is a
single static binary that cross-compiles from one machine to any target, and
that is what makes directories genuinely replaceable. The SQLite driver is
`modernc.org/sqlite`, which is pure Go, for the same reason — note that the
driver name in `sql.Open` is `sqlite`, not `sqlite3`.

`testdata/vectors.json` is a shipped deliverable, not a by-product: a known
`S_dir` and epoch with the expected `WriteSeed`, `WK_pub`, `LookupID`,
`RecordKey` and a fully formed envelope, so that an independent implementation
can verify itself against the spec rather than against this codebase. Regenerate
with `go run ./cmd/gen-vectors`; CI fails if the committed file drifts.

`testdata/api-vectors.json` is the second half of that deliverable, and covers
the handler rather than the cryptography: every row of the §5.2 and §5.4 status
tables, the evaluation order §5.2 mandates, and the verbatim-storage
requirement. Each fixture is a method, path, query, headers and body against an
expected status and body, driven against a fixed clock and a declared initial
state, so an implementation in any language can run them from its own harness.
Regenerate with `go run ./cmd/gen-api-vectors`. See `testdata/README.md`.

`docker build .` produces a roughly 12 MB image: a distroless static base, the
binary, and a copy of the licence. There is no shell in it, no package manager
and no busybox — the only executable is `trigstationd` itself. It runs as uid
65532 with a read-only root filesystem and writes only to the database volume.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions are under the Developer
Certificate of Origin — sign off with `git commit -s`. Protocol questions belong
in the [spec repository](https://github.com/trigstation/spec), not here: where
the code and the specification disagree, the specification is right.

## Licence and the AGPL network clause

`trigstationd` is licensed **AGPL-3.0-or-later**. See `LICENSE`. The
specification itself is CC0-1.0, and client libraries are MIT, so implementing
the protocol carries no copyleft obligation at all.

AGPL obligations attach only to someone who **both modifies this software and
offers it over a network**. Running an unmodified instance carries none.

If you have modified it and are running it publicly, section 13 requires you to
give your users a way to obtain your modified source. That is discharged here by
the `source_url` field in `GET /v1/meta`:

```json
{"v": 1, "record_count": 104233, "source_url": "https://github.com/trigstation/trigstationd"}
```

**If you are running a modified version, you must change `source_url` to point
at your own source.** Set `TRIGSTATION_SOURCE_URL` in `.env`, or pass
`-source-url`. It ships populated and documented so that compliance is the
default rather than something to discover, and the binary refuses to start if it
is empty. Do not remove the field and do not make it optional: it is a licence
obligation expressed as code.

Contributions are accepted under the Developer Certificate of Origin. There is
no contributor licence agreement, and consequently no unilateral relicensing.
