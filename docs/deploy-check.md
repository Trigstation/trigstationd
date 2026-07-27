# First deployment: what to verify, and what goes wrong

A checklist for standing up a public instance for the first time.

Budget an evening. Most of it is DNS propagation and waiting.

Throughout, `$DOMAIN` is the hostname you are deploying, e.g.
`dir.trigstation.com`.

**Read §4 before you begin.** The sections are otherwise in the order you should
work through them, but §4b configures the Docker daemon to stop capturing
container output, and once it has, §2's "watch the certificate" and §5's
default-route check can no longer be performed at all. Both read as passing.
Either do them first, or re-enable capture for one service temporarily using the
override shown in §4a. This ordering constraint is the single easiest way to
come away from this document believing you verified something you did not.

Sections 0, 1, 4b, 4c and 5 have been executed against a real public instance.
Sections 2, 3, 4a and 6 depend on a certificate and are corrected from the
implementation and the specification rather than from a run — treat those as
carefully reasoned rather than as observed, and correct them as you go.

---

## 0. Before you start

You need:

- A VPS with a public IPv4 address. §9.1 puts the *running* load at a small
  instance — NZ$10–25/month is the right order — but note that figure is about
  serving traffic, not about building. See the memory note below.
- **At least 1 GB of RAM, or swap.** `docker compose up` builds the image from
  source, and the Go toolchain is the memory peak of the whole deployment — far
  above anything the service does once running. On a 512 MB instance with no
  swap this fails, and it fails *indirectly*: the kernel's OOM killer takes
  whichever process is largest at that moment, so what you see is an unrelated
  package or tool dying rather than an obvious out-of-memory error. Confirm with
  `dmesg -T | grep -i oom` before believing any other diagnosis. Two gigabytes of
  swap is enough and costs nothing:

  ```
  fallocate -l 2G /swapfile && chmod 0600 /swapfile
  mkswap /swapfile && swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab   # or it is gone after a reboot
  ```

- **Ports 80, 443/tcp and 443/udp reachable from the internet.** ACME's HTTP-01
  challenge needs port 80, and it is the thing most often blocked by a
  provider's default firewall. Check before you start, not after Caddy has
  failed five times and been rate limited. 443/udp is HTTP/3, which
  `docker-compose.yml` publishes; omitting it costs you HTTP/3 silently rather
  than loudly, because clients fall back to TCP and nothing appears wrong.

  A refused connection and a timed-out one mean different things here. `nc -vz
  $HOST 80` answering *refused* proves packets reach the host and only that
  nothing is listening yet — which is what you want before Caddy starts. A
  *timeout* is the provider's firewall, and no amount of host configuration will
  fix it.

- DNS `A` **and** `AAAA` records for `$DOMAIN` pointing at that host, **already
  propagated**, and **not proxied**.

  Verify from the VPS *and* from somewhere that is not the VPS, and name a
  resolver explicitly rather than trusting whichever one the machine is
  configured with — a filtering or sinkholing resolver on your workstation will
  otherwise produce a confident wrong answer that looks like a DNS problem you
  do not have:

  ```
  for r in 1.1.1.1 8.8.8.8 9.9.9.9; do
    echo "$r A    $(dig +short @$r $DOMAIN A    | tr '\n' ' ')"
    echo "$r AAAA $(dig +short @$r $DOMAIN AAAA | tr '\n' ' ')"
  done
  ```

  All three must agree, and must match the host. If they disagree, the record is
  still propagating. If only your workstation disagrees, it is your resolver and
  the deployment is fine.

  **Then confirm the record is not behind a CDN proxy.** A proxied record — an
  orange cloud in Cloudflare's terms — breaks the HTTP-01 challenge, and §9.2 is
  the more important reason not to use one: the CDN would see every client
  address and every lookup prefix in the clear. Hosting the *zone* at a CDN
  provider is fine; having it *proxy* the record is not, and the two look
  identical in the control panel until you check what the record resolves to:

  ```
  dig +short $DOMAIN CNAME                     # expect: empty
  curl -s https://www.cloudflare.com/ips-v4    # your answer must not be in these
  ```

- **No CAA record that excludes your certificate authority.** A CAA record on
  `$DOMAIN` or any parent naming some other CA makes issuance fail at the
  authority rather than at the challenge, which looks nothing like a DNS problem
  in Caddy's logs. Empty output is fine and is the common case:

  ```
  dig +short $DOMAIN CAA; dig +short $(echo $DOMAIN | cut -d. -f2-) CAA
  ```

- Docker and the compose plugin on the VPS, **from Docker's own apt repository
  rather than the distribution's**. Check that the repository actually publishes
  for your release codename before you start, rather than assuming a recent
  distribution is covered:

  ```
  curl -s https://download.docker.com/linux/ubuntu/dists/ | grep "$(. /etc/os-release && echo $VERSION_CODENAME)"
  ```

  If it is absent, stop and wait for it rather than substituting the
  distribution's `docker.io`, whose compose plugin version is not the one this
  file is tested against.

---

## 1. Configure

```
git clone https://github.com/trigstation/trigstationd
cd trigstationd
cp .env.example .env
$EDITOR .env          # set TRIGSTATION_DOMAIN=$DOMAIN
```

**If you have modified the source**, set `TRIGSTATION_SOURCE_URL` in `.env` to
point at *your* repository. This is an AGPL §13 obligation, not a nicety, and
the binary refuses to start if it is empty.

Note the two spellings, which are easy to confuse and are not
interchangeable. `.env` carries **`TRIGSTATION_SOURCE_URL`**, without the `D`;
`docker-compose.yml` reads that and passes it to the container as
**`TRIGSTATIOND_SOURCE_URL`**, with it. Only the first is yours to set. Editing
`docker-compose.yml` directly works but is the wrong place: it dirties a tracked
file, so every later `git pull` conflicts, and `.env.example` already documents
the setting. Confirm it took effect from the outside rather than from the file:

```
docker compose config | grep SOURCE_URL
```

Confirm the compose file parses and the domain is picked up:

```
docker compose config -q && echo OK
```

An error naming `TRIGSTATION_DOMAIN` means `.env` is missing or unset. That
failure is deliberate — a default domain would be worse than no domain.

---

## 2. Start, and watch the certificate

```
docker compose up -d
docker compose logs -f caddy
```

**Expected**, within a minute or so:

```
{"level":"info","logger":"tls.obtain","msg":"acquiring lock","identifier":"$DOMAIN"}
{"level":"info","logger":"tls.issuance.acme","msg":"waiting on internal rate limiter",...}
{"level":"info","logger":"tls.issuance.acme.acme_client","msg":"trying to solve challenge","challenge_type":"http-01"...}
{"level":"info","logger":"tls.obtain","msg":"certificate obtained successfully","identifier":"$DOMAIN"}
```

### Failure modes, in the order you are likely to hit them

| Symptom | Cause | Fix |
|---|---|---|
| `no such host` / challenge never attempted | DNS not propagated | Wait; re-check `dig +short $DOMAIN` from off-host |
| `timeout during connect` on the challenge | Port 80 blocked upstream | Open it at the provider's firewall, not just the host's |
| `connection refused` on the challenge | Something else already bound to 80/443 | `ss -lntp \| grep -E ':(80\|443)'` and stop it |
| `urn:ietf:params:acme:error:rateLimited` | Too many failed attempts | **Stop.** See below |
| Certificate obtained but browser warns | You tested earlier with `localhost` | `docker compose down -v` to clear `caddy_data`, then up again |

**On rate limiting:** Let's Encrypt allows five failed validations per account,
per hostname, per hour. It is easy to burn through that by restarting while DNS
is still wrong. If you hit it, fix the underlying problem and wait the hour —
restarting faster makes it worse. To iterate without spending attempts, point
Caddy at the staging CA first by adding to the global block of the `Caddyfile`:

```
acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
```

Staging issues untrusted certificates with far higher limits. **Remove that line
and clear the certificate volume before going live**, or you will serve a
certificate no client accepts.

**On `docker compose down -v`:** both places above reach for it, and on a first
deployment it is harmless because there is nothing yet to lose. It is worth
knowing what it actually does before it becomes a habit: `-v` removes *every*
named volume in the file, which is `caddy_data`, `caddy_config` **and
`records`** — the published records of every server using the directory, not
just the certificate you meant to discard. §7's "back up nothing" is not licence
to discard casually; an instance that drops its records makes every server
using it unreachable until each republishes, up to a keepalive interval away.
When the certificate is what you want gone, say so:

```
docker compose down
docker volume rm trigstationd_caddy_data
docker compose up -d
```

---

## 3. Confirm the service answers

```
curl -s https://$DOMAIN/v1/meta | jq .
```

Expected — all seven members, and `source_url` populated:

```json
{
  "v": 1,
  "record_count": 0,
  "max_ttl": 172800,
  "max_record_bytes": 4096,
  "pow_bits": 20,
  "signal": true,
  "source_url": "https://github.com/trigstation/trigstationd"
}
```

Then the things that are easy to get wrong and silent when they are:

```
# HTTP redirects to HTTPS
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' http://$DOMAIN/v1/meta
# expect: 308 https://$DOMAIN/v1/meta

# CORS is present — browsers cannot use the directory without it (§5.5)
curl -sI https://$DOMAIN/v1/meta | grep -i access-control-allow-origin
# expect: Access-Control-Allow-Origin: *

# There are four operations and no more (invariant 7)
for p in /health /healthz /metrics /debug/pprof/ / /v1/; do
  printf '%-16s %s\n' "$p" "$(curl -s -o /dev/null -w '%{http_code}' https://$DOMAIN$p)"
done
# expect: 404 for every one
```

---

## 4. Confirm the deployment logs nothing

**Do this on the real host.** §9.2 makes no-logging a property of the
deployment, not of the binary, and the compose file getting it right locally is
not evidence that your host does. A log shipper, a modified `Caddyfile`, or a
Docker logging driver you added will all defeat it.

There are **three** layers, and the `Caddyfile` only covers the first. Check all
three, in this order — the order matters, and getting it wrong is how this
section produces a false pass.

### 4a. Caddy — verify the exclusion *while you can still see output*

Caddy's **access** log is off by default; its **error** log is not, and that one
records `remote_ip`, `client_ip` and the full request URI — **including the
lookup prefix**. Disabling the access log does not stop it; they are different
loggers. The shipped `Caddyfile` excludes both.

Do this step **before** 4b turns off log capture. Once the daemon is not
capturing container output, this grep returns nothing whether Caddy is silent or
screaming, and you will have proved nothing at all:

```
# Temporarily capture Caddy's output, so that "no output" is a real result.
cat > /tmp/logcheck.yml <<'YML'
services:
  caddy:
    logging:
      driver: json-file
YML
docker compose -f docker-compose.yml -f /tmp/logcheck.yml up -d --force-recreate caddy

# Provoke the failure that leaks: a 502 while trigstationd is away.
docker compose stop trigstationd
curl -sk "https://$DOMAIN/v1/record?bits=0" -o /dev/null    # 502
docker compose start trigstationd

docker compose logs caddy | grep -icE 'remote_ip|client_ip|"uri"'
# expect: 0
```

**Prove the check can fail before you trust it.** Comment the `exclude` line out
of the `Caddyfile`'s `log default` block, repeat the three commands above, and
confirm the same grep now counts more than zero. Restore the line. A silent
result from a check that cannot speak is the most expensive kind of evidence:

```
docker compose -f docker-compose.yml -f /tmp/logcheck.yml down
rm /tmp/logcheck.yml
```

### 4b. The Docker daemon — configure it so nothing persists, then prove it

**This layer is not covered by anything in this repository**, because it is host
configuration rather than deployment configuration. Docker's default `json-file`
driver writes every container's stdout and stderr to
`/var/lib/docker/containers/<id>/<id>-json.log` and keeps it until the container
is removed. If layer 4a ever regresses, that file is where client addresses and
lookup prefixes come to rest.

```
cat > /etc/docker/daemon.json <<'JSON'
{
  "log-driver": "none"
}
JSON
systemctl restart docker
docker info --format 'Logging Driver: {{.LoggingDriver}}'
# expect: Logging Driver: none
```

Then drive real traffic — a publish, a lookup, a malformed request, a signal
POST and GET — and confirm both that nothing is retrievable and that nothing is
on disk:

```
docker compose logs 2>/dev/null | wc -c
# expect: 0
#   note: stderr carries "configured logging driver does not support reading".
#   Redirect it away or you will measure the refusal instead of the content.

find /var/lib/docker/containers -name '*-json.log' | wc -l
# expect: 0
```

**Consequence to accept deliberately, not discover later:** with this driver
`docker compose logs` is empty for every service, forever. §2's "watch the
certificate" and §5's default-route check both depend on reading container
output, so do those *before* setting this, or re-enable capture for one service
temporarily using the `/tmp/logcheck.yml` override shown in 4a. Any instruction
anywhere that reads `docker compose logs … | grep …` and expects no output is
**vacuously true** on a correctly configured host and proves nothing.

### 4c. The host journal — the layer nobody remembers

Two things write client addresses here, and neither is Docker.

**The firewall.** `ufw` logs blocked packets with their source address, at `low`
by default, into a journal that on most distributions is persistent. Scanners
are the bulk of it, but the mechanism does not discriminate: a real client's
out-of-state packet — a late retransmission, a RST after the connection tracker
has forgotten the flow — is dropped and its address written to disk. That is a
client address recorded by a component the operator placed in the path, which is
exactly what §9.2 forbids:

```
journalctl -k --since '1 hour ago' | grep -c 'UFW BLOCK'
ufw logging off
nft list ruleset | grep -c LOG        # expect: 0 — it now cannot log, rather than happens not to
```

Losing firewall logs is a real cost. §9.2 is a stronger claim than the
visibility it buys, so it goes; note the trade rather than making it silently.

**Everything else.** Check the whole journal, not just Docker's unit — a log
shipper, `rsyslog`, or an agent the provider installed will not be under
`-u docker`. Use a fixed timestamp, never a relative window: `--since '5 min
ago'` slides forward as you work, so entries age out of it and a count can *fall*
between two runs, which reads as success and is not:

```
MARK=$(date -Is)
# ... drive traffic here ...
journalctl --since "$MARK" | grep -icE 'deadbeef|/v1/record|SRC='
# expect: 0
```

Report what you searched for and the byte counts you got. "No logging found" is
not a result; it is the absence of one.

---

## 5. Configure the trusted proxy — or rate limiting does not work

The compose file already sets `-trusted-proxies` to the pinned directory
network. **If you changed the network subnet, change both**, or every client in
the world shares one rate-limiter key and the instance refuses them all.

Verify the two agree — but check the network Docker **actually created**, not
the file that asked for it. Those differ whenever the pinned subnet collided
with something already on the host, which is the case where this matters:

```
docker network inspect $(docker network ls --format '{{.Name}}' | grep directory) \
  --format 'subnet={{range .IPAM.Config}}{{.Subnet}}{{end}}'
docker compose config | grep TRUSTED_PROXIES
# the two must name the same block
```

Then test the behaviour rather than the strings, because a value can match the
network and still be wrong. Exhaust the hourly `GET` allowance for one forwarded
address and confirm a *different* `/24` is unaffected. Run it from a container on
the directory network, so the peer address is inside the trusted range as it
would be for Caddy:

```
NET=$(docker network ls --format '{{.Name}}' | grep directory)
URL='http://trigstationd:8080/v1/record?bits=0'

docker run --rm --network $NET --entrypoint sh curlimages/curl -c '
  args=""; i=0; while [ $i -lt 610 ]; do args="$args '"$URL"'"; i=$((i+1)); done
  curl -s -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-For: 203.0.113.7" $args' \
  | sort | uniq -c
# expect: 600 x 200, then 429s

docker run --rm --network $NET curlimages/curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'X-Forwarded-For: 198.51.100.7' "$URL"
# expect: 200 — a different /24 has its own allowance
```

**Prove this one can fail too.** Re-run it with `TRIGSTATIOND_TRUSTED_PROXIES`
set to a block that does *not* contain the directory network, via a throwaway
override file. The second address should then also answer `429`, because every
client has collapsed into the peer's single key. That is the outage §6.4
describes, and seeing it once is worth more than reading about it.

Also confirm you have **not** put a default route in the list. `0.0.0.0/0`
trusts every source, which makes the mechanism inoperative — safe, but not what
you meant. The binary warns at startup if you have — but see §4b: under a
`none` log driver the check below reads empty no matter what, so capture Caddy's
and the directory's output temporarily, or read the warning at first start
before configuring the driver:

```
docker compose logs trigstationd | grep -i 'default route'
# expect: no output — MEANINGLESS unless log capture is on. See §4b.
```

If you put a CDN in front of Caddy, read §6.4 first. Two things change: Caddy
needs its own `trusted_proxies` set to the CDN, and — more importantly — the
CDN then sees every client address and every lookup prefix in the clear. That is
the correlation data this design exists to remove, handed to a third party. It
is a moved trust boundary, not a hardened one.

---

## 6. First publish, from a real server on a different network

This is the check nothing else covers: real DNS, a real certificate, a real
client, and the whole path end to end. Everything before this point tested the
instance against itself.

You need a real client to do this, and **this repository does not contain one** —
`cmd/` holds only the two vector generators, which are build-time tools. A
publish requires an epoch-derived `LookupID`, a signed envelope and a 20-bit
proof of work, so it cannot be improvised with `curl`. Either point a real media
server at the instance, or write a small publisher against `internal/derive`,
`internal/record` and `internal/pow`. Budget for that before starting this
section rather than discovering it here.

1. Point a media server's Trigstation configuration at `https://$DOMAIN`.
2. Let it publish. On the instance:

   ```
   curl -s https://$DOMAIN/v1/meta | jq .record_count
   # expect: 1
   ```

3. **From a different network** — not the VPS, not the server's LAN; a phone on
   mobile data is ideal — perform a lookup and confirm the envelope decrypts and
   its inner signature verifies.

   **On a new directory the only prefix you may ask for is `bits=0`.** §5.3 caps
   precision at `bits_max = max(0, floor(log2(record_count / 20)))` against the
   true record count, so an instance holding one record — which is exactly what
   this section has just created — permits `bits=0` and nothing else. `bits=1`
   needs 40 records. A lookup with the client's full derived prefix is a `400`
   here, and it is the *directory* being correct rather than the client being
   wrong:

   ```
   curl -s "https://$DOMAIN/v1/record?bits=0" | jq '.records | length'
   # expect: 1
   curl -s -o /dev/null -w '%{http_code}\n' "https://$DOMAIN/v1/record?prefix=a&bits=1"
   # expect: 400 — over-precise while record_count < 40
   ```

   This is a property of a directory that has just been stood up, not a
   permanent one. It resolves itself as servers publish, and until it does, an
   empty-prefix query returns everything the instance holds, which for a first
   publish is the record you are looking for.

4. **Confirm the envelope comes back byte-for-byte.** Capture what the server
   published and compare it against what the lookup returned:

   Capture the envelope exactly as the client transmitted it — the raw request
   body — into `published-envelope.json`. The stored bytes are reproduced inside
   the `records` array of the response, so a true byte-for-byte comparison means
   locating that substring in the raw body rather than parsing and re-printing
   it:

   ```
   curl -s "https://$DOMAIN/v1/record?bits=0" > lookup.json
   grep -c -F -f <(tr -d '\n' < published-envelope.json) lookup.json
   # expect: 1 — the published bytes appear verbatim inside the response
   ```

   **Do not compare `jq -c` output on both sides.** Passing each through `jq`
   normalises whitespace and member order on *both*, so two texts differing in
   exactly the way §5.2 forbids compare equal, and the check passes on a
   directory that re-serialises — the one thing it exists to detect.

   The sharper test is a field the directory does not know. §10 requires unknown
   fields to be ignored and preserved, and a directory that decodes into a typed
   structure and re-encodes will silently drop them while looking entirely
   healthy. Publish an envelope carrying an extra member, then confirm it comes
   back:

   ```
   curl -s "https://$DOMAIN/v1/record?bits=0" | grep -c 'x-unknown-probe'
   # expect: 1 — if 0, the directory is re-serialising. See §5.2 on json.RawMessage.
   ```

   They must be identical, byte for byte, including whitespace and member order.
   §5.2 requires verbatim storage and §10's additive-change policy depends on it:
   a directory that re-serialises silently strips any field it does not know,
   and both ends see a working system that quietly cannot carry new fields.

   If they differ, the directory is re-serialising. See §5.2's note on
   `json.RawMessage`.

5. Publish a second time and confirm the address change propagates. Then confirm
   a replay of the **first** envelope is refused with `409` — that is the recency
   rule, and it is a replay defence rather than a formality.

---

## 7. After it is up

- **Watch for `429` reports from publishers.** Rate limiting keys on a truncated
  address (`/24`, `/64`), and a carrier-grade NAT `/24` can front thousands of
  subscribers. A publisher seeing intermittent `429`s is far more likely to be
  sharing a carrier than attacking you. Raise `-rate-put` rather than assume
  abuse; proof of work is the primary defence against flooding regardless.
- **Certificate renewal is automatic** and needs no action. Caddy renews at
  roughly two-thirds of the lifetime. It will not email you if it fails, because
  the shipped `Caddyfile` sets no ACME account address — if you want expiry
  warnings, add `email you@example.com` to the global block.
- **Back up nothing, and mean it.** A directory holds no data worth preserving.
  Records are ciphertext the operator cannot read, they expire within 48 hours
  (§4.3), and signal channels are memory-only and never persisted. An instance
  that loses its database recovers as servers republish — worst case one
  keepalive interval, around six hours — and during that window it is simply the
  directory that did not answer first, which §7 already treats as normal
  operation rather than an outage.

  Backups are not merely unnecessary here, they are **contrary to invariant 5**.
  The property that nothing accumulates is one an operator can give up
  accidentally, and a nightly snapshot of a table designed to expire is the most
  likely way to do it: it turns 48 hours of ciphertext into an indefinite
  archive of it, on a host that may be backed up somewhere else again. Nothing
  in the service can prevent this, which is precisely why it is worth saying.
- **Publish your instance** so servers can find it, and note that servers SHOULD
  publish to at least two directories (§7). A second instance run by somebody
  else is worth more to the network than a second region of yours.
