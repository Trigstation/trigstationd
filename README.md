<!--
SPDX-License-Identifier: AGPL-3.0-or-later
Copyright (C) 2026 Simon Wright
-->

# trigstationd

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
| `-rate-put` | `TRIGSTATIOND_RATE_PUT` | `120` | `PUT /v1/record` allowance per source per hour. |
| `-rate-get` | `TRIGSTATIOND_RATE_GET` | `600` | `GET /v1/record` allowance per source per hour. |
| `-rate-signal` | `TRIGSTATIOND_RATE_SIGNAL` | `600` | Signal channel allowance per source per hour. |

Rate limits are counted per class and keyed by a truncated address — IPv4 to
`/24`, IPv6 to `/64` — held in memory and discarded when the window elapses. A
`/24` key means up to 256 hosts share a bucket, so §6.4 says to set the
allowances well above honest use rather than tightly. Honest publish volume is
about one request per server per day.

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

`docker build .` produces a roughly 12 MB image: a distroless static base, the
binary, and a copy of the licence. There is no shell in it, no package manager
and no busybox — the only executable is `trigstationd` itself. It runs as uid
65532 with a read-only root filesystem and writes only to the database volume.

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
