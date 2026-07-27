# First deployment: what to verify, and what goes wrong

A checklist for standing up a public instance for the first time.

Budget an evening. Most of it is DNS propagation and waiting.

Throughout, `$DOMAIN` is the hostname you are deploying, e.g.
`dir.trigstation.com`.

**A note on what "no output" proves.** Several checks below pass when a `grep`
finds nothing. That is only evidence if the command could have found something.
Silencing a log source makes every such check succeed while proving nothing, and
the first deployment of this document did exactly that before catching it. Where
a check greps captured output, confirm the output is non-empty first, and where
a check guards something that matters, break the thing deliberately once and
confirm the check notices. Each such point is marked below.

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
  There is **no memory requirement beyond what §9.1 implies**, and if you find
  yourself needing one, you are compiling on the deployment host — see the note
  immediately below. A directory serves comfortably in well under the smallest
  instance any provider sells.

- **Deploy a published image; do not build on the host.** §9 is explicit that a
  directory is deployed by pulling a published image or a released binary, and
  that the memory and toolchain needed to compile are unrelated to those needed
  to run. A compose file that builds from context makes the Go toolchain's peak
  into the deployment's requirement, and a correctly sized instance then fails
  before it has served a single request.

  It fails *indirectly*, which is what makes it expensive: the kernel's OOM
  killer takes whichever process is largest at that moment, so what you see is
  an unrelated package or tool dying — on the first deployment it was `dracut`,
  leaving a broken initramfs and no mention of memory anywhere. If anything on a
  small instance behaves inexplicably, check this before believing any other
  diagnosis:

  ```
  dmesg -T | grep -i 'out of memory'
  ```

  If you must build on the host anyway — before the first tagged release there
  is no published image — give it swap first. Two gigabytes is enough:

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
{"level":"info","logger":"http","msg":"waiting on internal rate limiter","identifiers":["$DOMAIN"]}
{"level":"info","logger":"http.acme_client","msg":"trying to solve challenge","identifier":"$DOMAIN","challenge_type":"tls-alpn-01"}
{"level":"info","logger":"tls","msg":"served key authentication certificate","challenge":"tls-alpn-01"}
{"level":"info","logger":"http.acme_client","msg":"authorization finalized","authz_status":"valid"}
{"level":"info","logger":"tls.obtain","msg":"certificate obtained successfully","identifier":"$DOMAIN"}
```

**The challenge is `tls-alpn-01`, not `http-01`.** Caddy prefers TLS-ALPN-01 and
solves it on 443 whenever it can; HTTP-01 on port 80 is the fallback. Port 80 is
still needed — for the HTTP-to-HTTPS redirect, and for the fallback if 443 is
unreachable — so the requirement in §0 stands, but do not wait for an `http-01`
line that will never come, and do not conclude the challenge failed because
nothing touched port 80.

### Failure modes, in the order you are likely to hit them

| Symptom | Cause | Fix |
|---|---|---|
| `no such host` / challenge never attempted | DNS not propagated | Wait; re-check `dig +short $DOMAIN` from off-host |
| `timeout during connect` on the challenge | Port 80 blocked upstream | Open it at the provider's firewall, not just the host's |
| `connection refused` on the challenge | Something else already bound to 80/443 | `ss -lntp \| grep -E ':(80\|443)'` and stop it |
| `urn:ietf:params:acme:error:rateLimited` | Too many failed attempts | **Stop.** See below |
| Certificate obtained but browser warns | Still on the staging CA, or a stale account in `caddy_data` | Remove the volume, not just the container — see below |

### Issue against staging first. This is a step, not an optimisation.

Let's Encrypt allows five failed validations per account, per hostname, per
hour. That is easy to exhaust by accident while DNS settles — and easy to
exhaust *on purpose*, because §4a below requires provoking a failure and
restarting repeatedly to prove its check can fail. Exhausting it means waiting
an hour rather than finishing tonight, and the risk is asymmetric: staging costs
one extra teardown, the alternative costs an evening.

Add to the global block of the `Caddyfile`:

```
acme_ca https://acme-staging-v02.api.letsencrypt.org/directory
```

Staging issues from a root nothing trusts, with far higher limits. Work through
§3, §4 and §5 against it, then switch to production for §6.

**Staging certificates are untrusted, so staging checks need `-k`.** `curl`
and every browser reject them, and that is the certificate working as intended
rather than a fault. Every `curl` in §3 and §4 needs `-k` while you are on
staging.

**Take `-k` off again for production.** Carrying the flag over is the expensive
mistake: `-k` suppresses exactly the trust failure that production issuance
exists to demonstrate, so a misissued or wrongly-chained production certificate
passes every check silently. The point of §3 against production is that it
succeeds *without* `-k`.

### Switching to production — remove the volume, not just the container

```
# 1. remove the staging line from the Caddyfile
# 2. then, and this is the part that catches people:
docker compose down
docker volume rm trigstationd_caddy_data
docker compose up -d
```

**Deleting the container is not enough.** Caddy caches the ACME account key and
the issued certificate in the `caddy_data` volume, and that volume outlives
`docker compose down`. A leftover staging account keeps the instance pointed at
staging after the configuration says otherwise, and the symptom is the
confusing one: issuance *succeeds*, the logs look correct, and the certificate
is still untrusted. If a production certificate comes back untrusted and the
`Caddyfile` is right, this is why.

Confirm which authority actually issued it, rather than trusting that the
config changed:

```
echo | openssl s_client -connect $DOMAIN:443 -servername $DOMAIN 2>/dev/null \
  | openssl x509 -noout -issuer
```

Staging intermediates carry a literal `(STAGING)` in the common name — the
adjective-fruit names rotate, so match on that marker rather than on any
particular one:

```
issuer=C=US, O=Let's Encrypt, CN=(STAGING) Baloney Bulgur YE2   <- staging
issuer=C=US, O=Let's Encrypt, CN=YE2                            <- production
```

The definitive check is simply that `curl` succeeds **without** `-k`.

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

Provoke the failure that leaks — a 502 while trigstationd is away, which is what
a rolling restart produces:

```
docker compose stop trigstationd
curl -sk "https://$DOMAIN/v1/record?bits=0" -o /dev/null    # 502
docker compose start trigstationd

docker compose logs caddy | wc -c
# expect: non-zero. If this is 0 the next command proves nothing — see §4b.

docker compose logs caddy | grep -icE 'remote_ip|client_ip|"uri"'
# expect: 0
```

**Prove the check can fail before you trust it.** Comment the `exclude` line out
of the `Caddyfile`'s `log default` block, `docker compose up -d
--force-recreate caddy`, repeat the three commands above, and confirm the same
grep now counts more than zero. Then restore the line and recreate again. A
silent result from a check that cannot speak is the most expensive kind of
evidence, and this is the one place in the deployment where that mistake is
invisible.

### 4b. The container runtime — bounded, not silenced

Docker's default `json-file` driver is **unbounded**: it writes every
container's stdout and stderr to
`/var/lib/docker/containers/<id>/<id>-json.log` and keeps it until the container
is removed. If layer 4a ever regresses, that file is where client addresses and
lookup prefixes come to rest, indefinitely.

`docker-compose.yml` now bounds both services at 1 MB across 3 files. Confirm it
took effect, since a host-level daemon default can be overridden and a
`daemon.json` you inherited may say something else:

```
docker inspect $(docker compose ps -q caddy) \
  --format '{{.HostConfig.LogConfig.Type}} {{.HostConfig.LogConfig.Config}}'
# expect: json-file map[max-file:3 max-size:1m]

du -sh /var/lib/docker/containers/*/*.log | sort -h | tail -3
# expect: kilobytes, and never growing past the bound
```

**Do not set `log-driver: none`.** It was tried on the first deployment and is
wrong twice over. It discards certificate renewal failures, so TLS stops one day
with no signal and nothing anywhere records why. And it makes every check of the
form `docker compose logs … | grep …` succeed **vacuously** — including the one
in 4a above and the default-route check in §5 — reporting a clean result on a
deployment that is leaking. §9.2 puts runtime logs in scope *for what they
capture*; the enforcement belongs in the components that emit, which is 4a, not
in a driver that cannot tell a certificate error from a request.

Now drive real traffic — a publish, a lookup, a malformed request, a
rate-limited request, a signal POST and GET — and search what was captured:

```
docker compose logs | wc -c                       # a few hundred bytes, not zero
docker compose logs | grep -icE 'remote_ip|client_ip|"uri"|deadbeef|203\.0\.113'
# expect: 0

grep -rlic 'deadbeef' /var/lib/docker/containers/*/*.log
# expect: 0 matches in every file
```

A non-zero byte count with a zero match count is the result you want. Zero bytes
would mean the check could not have failed.

### 4c. The host journal — the layer nobody remembers

Two things write client addresses here, and neither is Docker.

**The firewall — a required step, not a judgement call.** `ufw` logs blocked
packets with their source address, at `low` by default, into a journal that on
most distributions is persistent. Scanners are the bulk of it, but the mechanism
does not discriminate: a real client's out-of-state packet — a late
retransmission, a RST after the connection tracker has forgotten the flow — is
dropped and its address written to disk.

§9.2 settles this rather than leaving it to the operator. A dropped-packet log
associates a client address with the time it tried to reach the service, and
rejection does not make the source less identifying, so it is a record in scope.
Directory operators SHOULD disable connection logging and accept the reduced
attack visibility, which the specification considers a cost worth paying. **Do
this on every deployment**, not only when a check catches it:

```
journalctl -k --since '1 hour ago' | grep -c 'UFW BLOCK'   # before: typically dozens within the hour
ufw logging off
nft list ruleset | grep -c LOG
# expect: 0 — the ruleset now cannot log, rather than happening not to
```

Then purge what was recorded before you turned it off, or the deployment
carries an archive of client addresses it has just promised not to keep:

```
journalctl --rotate && journalctl --vacuum-time=1s
```

Verify with a **fixed** cursor, never a relative window — see below.

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

**The measurement contaminates what it measures, and it will alarm you.** `sudo`
writes the command it ran to the journal, so the moment you run

```
sudo grep -r 'deadbeefcafe' /var/lib/docker/containers/
```

the string `deadbeefcafe` is *in the journal* — placed there by your own audit
trail, not by the service. The next journal grep then finds exactly one hit per
search you performed, which looks precisely like a slow leak. Two ways out, and
the first is better:

```
# classify the hits rather than counting them
journalctl --since "$MARK" | grep 'deadbeefcafe' | grep -vcE 'sudo|sshd|session'
# expect: 0 — every remaining hit is your own administrative access
```

Administrative access is out of scope by §9.2's rule: `sudo` and `sshd` record
the operator's own commands and logins, not a directory client's request. A
count that does not separate the two is not a measurement. Expect `sshd` to
contribute a dozen or more lines carrying **your** address for the same reason,
and do not mistake them for client records.

Report what you searched for, the byte counts captured at each layer, and how
many hits you classified away. "No logging found" is not a result; it is the
absence of one — and a zero from a layer that captured zero bytes is worth
nothing at all.

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

A publish requires an epoch-derived `LookupID`, a signed inner payload, a sealed
ciphertext and a 20-bit proof of work, so it cannot be improvised with `curl`.
Use `cmd/trigcheck`, which does exactly one publish and reports the status:

```
go run ./cmd/trigcheck \
  -url https://$DOMAIN \
  -endpoint wan4:203.0.113.7:8920 \
  -o published-envelope.json
```

With no `-s-dir` or `-ik` it generates both, prints them, and publishes under
them — which is what you want against a new instance. **Keep what it prints**:
`s_dir` is needed to derive the `RecordKey` that decrypts the record, and
`ik_pub` to verify the inner signature. It writes the envelope to `-o` *before*
sending it, so those are the bytes to compare against in step 4 whatever the
directory answers.

1. Publish, either with `trigcheck` or by pointing a real media server at
   `https://$DOMAIN`. Expect `status 204` — §5.2 makes `204` the sole success
   code, and a publish that replaces an existing record is not distinguished
   from one that creates it.
2. On the instance:

   ```
   curl -s https://$DOMAIN/v1/meta | jq .record_count
   # expect: 1
   ```

3. **From a different network** — not the VPS, not the server's LAN; a phone on
   mobile data or any other host is ideal — read the record back and confirm it
   decrypts and its inner signature verifies:

   ```
   go run ./cmd/trigcheck -verify -url https://$DOMAIN \
     -s-dir <what it printed> -ik-pub <what it printed>
   ```

   Expect the endpoints you published, and these three lines:

   ```
   matched       envelope signature and lookup_id binding: OK
                 payload decrypted under the derived RecordKey: OK
                 inner signature under ik_pub: OK
   ```

   It also prints the bucket size, which is §5.3's anonymity set made
   observable: the directory learned that somebody asked about that many
   servers and no more. On a new instance the bucket is most of the table,
   which is expected and resolves itself as the instance grows.

   **Confirm this check can fail**, since a verifier that always succeeds is
   worse than none. Repeat it with one byte changed in `-ik-pub`, and again with
   `-s-dir` changed. The two failures are different and both should appear:

   ```
   # wrong -ik-pub: the payload decrypts, the inner signature does not verify
   trigcheck: payload decrypted but its inner signature does not verify under -ik-pub

   # wrong -s-dir: nothing in the bucket decrypts at all
   trigcheck: no envelope in the bucket decrypted under this S_dir
   ```

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
   healthy.

   Build an envelope without publishing it — point `trigcheck` at a dead port, so
   it writes the file and then fails at the `PUT` — add a member, and send that:

   ```
   go run ./cmd/trigcheck -url http://127.0.0.1:1 \
     -endpoint wan4:203.0.113.7:8920 -o probe.json      # exits non-zero, as intended
   jq -c '. + {"x-unknown-probe":"survives"}' probe.json > probe-sent.json
   curl -s -o /dev/null -w '%{http_code}\n' -X PUT \
     -H 'Content-Type: application/json' --data-binary @probe-sent.json \
     "https://$DOMAIN/v1/record"
   # expect: 204 — an unknown member is ignored, never rejected (§10)

   curl -s "https://$DOMAIN/v1/record?bits=0" | grep -c 'x-unknown-probe'
   # expect: 1 — if 0, the directory is re-serialising. See §5.2 on json.RawMessage.
   ```

   It must be an envelope that has never been published: adding a member to one
   already stored changes nothing about its `lookup_id` or `expires_at`, so the
   recency rule answers `409` and the probe is never stored at all. That is
   correct behaviour reading as a failed test.

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
