# First deployment: what to verify, and what goes wrong

A checklist for standing up a public instance for the first time. Everything
here has been verified locally **except** real certificate issuance, which
cannot be tested without a public domain — so the ACME section is the one most
likely to surprise you, and it is first.

Budget an evening. Most of it is DNS propagation and waiting.

Throughout, `$DOMAIN` is the hostname you are deploying, e.g.
`dir.trigstation.com`.

---

## 0. Before you start

You need:

- A VPS with a public IPv4 address. §9.1 puts the load at a small instance —
  NZ$10–25/month is the right order.
- **Ports 80 and 443 reachable from the internet.** ACME's HTTP-01 challenge
  needs port 80, and it is the thing most often blocked by a provider's default
  firewall. Check before you start, not after Caddy has failed five times and
  been rate limited.
- A DNS `A` record for `$DOMAIN` pointing at that address, **already
  propagated**. Verify from somewhere that is not the VPS:

  ```
  dig +short $DOMAIN
  ```

  If that returns nothing, or the wrong address, stop. Everything below will
  fail in ways that look like Caddy's fault.

- Docker and the compose plugin on the VPS.

---

## 1. Configure

```
git clone https://github.com/trigstation/trigstationd
cd trigstationd
cp .env.example .env
$EDITOR .env          # set TRIGSTATION_DOMAIN=$DOMAIN
```

**If you have modified the source**, change `TRIGSTATIOND_SOURCE_URL` in
`docker-compose.yml` to point at *your* repository. This is an AGPL §13
obligation, not a nicety, and the binary refuses to start if it is empty.

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
and run `docker compose down -v` before going live**, or you will serve a
certificate no client accepts.

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

```
# The directory should have written exactly one line, ever.
docker compose logs trigstationd
# expect: trigstationd: listening on :8080
```

Now provoke the failure that leaks. Caddy's **access** log is off by default;
its **error** log is not, and that one records `remote_ip`, `client_ip` and the
full request URI — **including the lookup prefix**. Disabling the access log
does not stop it; they are different loggers. The shipped `Caddyfile` excludes
both, and this is how you confirm yours still does:

```
docker compose stop trigstationd
curl -sk https://$DOMAIN/v1/record?prefix=deadbeef -o /dev/null    # 502
docker compose start trigstationd

docker compose logs caddy | grep -iE 'remote_ip|client_ip|deadbeef|"uri"'
# expect: no output at all
```

**If that grep prints anything, your proxy is logging your users** and the
property this service claims is not one you have. Do not go live until it is
silent.

Finally, check nothing outside the containers is collecting it:

```
journalctl -u docker --since '10 min ago' | grep -iE 'deadbeef|/v1/record'
# expect: no output
```

---

## 5. Configure the trusted proxy — or rate limiting does not work

The compose file already sets `-trusted-proxies` to the pinned directory
network. **If you changed the network subnet, change both**, or every client in
the world shares one rate-limiter key and the instance refuses them all.

Verify the two agree:

```
grep -A2 'TRIGSTATIOND_TRUSTED_PROXIES' docker-compose.yml
grep -A3 'ipam' docker-compose.yml
```

Also confirm you have **not** put a default route in the list. `0.0.0.0/0`
trusts every source, which makes the mechanism inoperative — safe, but not what
you meant. The binary warns at startup if you have:

```
docker compose logs trigstationd | grep -i 'default route'
# expect: no output
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

1. Point a media server's Trigstation configuration at `https://$DOMAIN`.
2. Let it publish. On the instance:

   ```
   curl -s https://$DOMAIN/v1/meta | jq .record_count
   # expect: 1
   ```

3. **From a different network** — not the VPS, not the server's LAN; a phone on
   mobile data is ideal — perform a lookup with the client's derived prefix and
   confirm the envelope decrypts and its inner signature verifies.

4. **Confirm the envelope comes back byte-for-byte.** Capture what the server
   published and compare it against what the lookup returned:

   ```
   diff <(published-envelope.json) <(curl -s "https://$DOMAIN/v1/record?prefix=<p>&bits=<b>" | jq -c '.records[0]')
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
