# Production Deployment

This guide covers a practical single-VM deployment of Transponder using Docker Compose.

## Recommended Machine Size

Transponder is stateless and does not run a database, so it is relatively light. The main costs are:

- Nostr relay connections
- token decryption and verification
- outbound TLS connections to APNs and FCM
- optional Tor relay support through the Cargo `tor` feature
- optional Prometheus and Grafana

Reasonable starting points:

- Small production, clearnet relays only, no monitoring on-box: `2 vCPU`, `2 GB RAM`, `20 GB disk`
- Recommended production, clearnet relays plus local Prometheus/Grafana: `2 vCPU`, `4 GB RAM`, `40 GB disk`
- If you enable onion relays/Tor: start at `2 vCPU`, `4 GB RAM`, and prefer `4 vCPU` if traffic is non-trivial
- Very small test node: `1 vCPU`, `1 GB RAM` can work for evaluation, but it leaves little room for spikes

Why these numbers make sense today:

- the dispatcher allows up to 100 concurrent outbound push requests
- the push queue is bounded at 10,000 pending notifications
- the event deduplication and rate-limit caches default to 100,000 entries each
- Tor adds noticeable memory and connection-management overhead, which is why the default build leaves it disabled

If you need to run on a smaller VM, lower the cache sizes in `config/production.toml`.

## Host Recommendations

- Use a modern Linux host such as Ubuntu 24.04 LTS or Debian 12
- Prefer rootless Docker if it fits your ops model
- Keep SSH key-only and disable password auth
- Use a host firewall; do not expose Prometheus or Grafana publicly
- Keep Transponder bound to localhost unless an external health endpoint is genuinely required
- Put APNs and FCM credential files in a directory readable only by your deploy user

## Firewall Guidance

Recommended inbound posture:

- Always allow `22/tcp` for SSH
- If you are publishing Grafana through Caddy, also allow `80/tcp` and `443/tcp`
- Allow `443/udp` if you want HTTP/3 support through Caddy
- Do not expose `8080`, `9090`, or `3000` publicly

If you are not using Caddy or another reverse proxy, keep inbound access limited to SSH only.

Example `ufw` policy for a host that exposes Grafana through Caddy:

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp
ufw enable
```

Outbound requirements depend on how you deploy:

- Clearnet-only baseline: outbound `443/tcp` to your configured Nostr relay hosts, `api.push.apple.com`, `api.sandbox.push.apple.com` if you use APNs sandbox, `fcm.googleapis.com`, and `oauth2.googleapis.com`
- If your relays use non-standard ports, allow those ports too
- If you enable onion relays, do not assume a strict `443/tcp`-only egress policy will work; Tor circuit building requires broader outbound access to the Tor network

In practice, most teams use a tight inbound firewall and leave outbound open unless they have a tested egress-filtering requirement.

## Files Included

- `compose.prod.yml`: hardened production Compose stack
- `config/production.toml.example`: production-oriented app config
- `deploy/production.env.example`: variable file for Compose

## First-Time Setup

1. Create the runtime files:

```bash
cp config/production.toml.example config/production.toml
cp deploy/production.env.example deploy/production.env
mkdir -p credentials secrets
chmod 700 credentials secrets
```

2. Create the server private key secret file:

```bash
printf '%s\n' 'YOUR_64_CHAR_HEX_PRIVATE_KEY' > secrets/server_private_key
chmod 600 secrets/server_private_key
```

3. Place push credentials in `credentials/`:

- APNs: `credentials/AuthKey_XXXXXXXXXX.p8`
- FCM: `credentials/service-account.json`

4. Edit `config/production.toml`:

- set relay URLs
- enable APNs and/or FCM
- set APNs identifiers and bundle ID
- set FCM project ID if you want to override the service-account value
- if you add any `relays.onion` entries, plan to build a Tor-enabled image

5. Edit `deploy/production.env`:

- confirm paths
- set a strong Grafana password if you plan to enable monitoring

## Build the Image

The Dockerfile uses Docker Hardened Images and requires authentication to `dhi.io`.

```bash
docker login dhi.io
docker build -t transponder:local .
```

If you need onion relay support, build a Tor-enabled image instead:

```bash
docker login dhi.io
docker build --build-arg CARGO_FEATURES='--features tor' -t transponder:tor .
```

The Dockerfile pins the DHI base images by digest, and [compose.prod.yml](/Users/jeff/.codex/worktrees/c05d/transponder/compose.prod.yml) pins Prometheus, Grafana, and Caddy by digest as well.

## Start Transponder

```bash
docker compose -f compose.prod.yml --env-file deploy/production.env up -d
```

If you built a Tor-enabled image, set `TRANSPONDER_IMAGE=transponder:tor` in `deploy/production.env` before starting the stack.

## Start with Monitoring

```bash
docker compose -f compose.prod.yml --env-file deploy/production.env --profile monitoring up -d
```

## Start with Monitoring Behind Caddy

Set `GRAFANA_PUBLIC_HOST`, `GRAFANA_ROOT_URL`, and `CADDY_EMAIL` in `deploy/production.env`, make sure DNS for that hostname points at the VM, then run:

```bash
docker compose -f compose.prod.yml --env-file deploy/production.env --profile monitoring --profile proxy up -d
```

Monitoring binds to localhost only:

- Transponder: `127.0.0.1:8080`
- Prometheus: `127.0.0.1:9090`
- Grafana: `127.0.0.1:3000`

With the `proxy` profile enabled:

- Caddy listens on `:80` and `:443`
- Grafana remains internal to Docker and is served at `https://$GRAFANA_PUBLIC_HOST`

If you need remote access, put those behind a reverse proxy or VPN rather than publishing them broadly.

## Verify the Deployment

```bash
docker compose -f compose.prod.yml --env-file deploy/production.env ps
docker compose -f compose.prod.yml --env-file deploy/production.env logs -f transponder
curl http://127.0.0.1:8080/health
curl http://127.0.0.1:8080/ready
```

`/ready` should return HTTP 200 only when at least one relay is connected and at least one push provider is configured.

## Upgrade Procedure

```bash
docker login dhi.io
docker build -t transponder:local .
docker compose -f compose.prod.yml --env-file deploy/production.env up -d
```

If monitoring is enabled, include `--profile monitoring`.

## Operational Notes

- Treat Tor relay support as optional and somewhat experimental from an ops perspective:
  - the default build leaves it disabled
  - the Tor-enabled build currently carries documented upstream audit exceptions in `scripts/cargo-audit.sh`
  - only enable it if you specifically need onion relays
- Back up only what matters:
  - `config/production.toml`
  - `deploy/production.env`
  - `secrets/server_private_key`
  - `credentials/`
  - optionally the Grafana and Prometheus named volumes
- Rotate the Transponder private key carefully because clients need the new public key
- Keep logging at `info` unless debugging an issue
- Review unusual growth in queue size, token decryption failures, relay disconnects, or push failure rates
- If you do not need onion relays, keep the default non-Tor build to reduce dependency and attack surface
