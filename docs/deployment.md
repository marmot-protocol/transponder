# Production Deployment

This guide covers practical single-VM deployments of Transponder using either Docker Compose or a native `systemd` service.

## Recommended Machine Size

Transponder is stateless and does not run a database, so it is relatively light. The main costs are:

- Nostr relay connections
- token decryption and verification
- outbound TLS connections to APNs and FCM
- optional Tor relay support through the Cargo `tor` feature

Reasonable starting points:

- Small production, clearnet relays only: `2 vCPU`, `2 GB RAM`, `20 GB disk`
- Recommended production, especially if you enable onion relays: `2 vCPU`, `4 GB RAM`, `40 GB disk`
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
- Use a host firewall; do not expose the health or metrics port publicly unless you explicitly need it
- Keep Transponder bound to localhost unless an external health endpoint is genuinely required
- Put APNs and FCM credential files in a directory readable only by your deploy user

## Firewall Guidance

Recommended inbound posture:

- Always allow `22/tcp` for SSH
- Do not expose `8080` publicly unless you deliberately want remote access to `/health`, `/ready`, or `/metrics`

Example `ufw` policy for a host that keeps Transponder internal:

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
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
- `deploy/transponder.service.example`: example `systemd` unit for non-Docker deployments

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
- if you add any `relays.onion` entries, plan to build a Tor-enabled image or binary
- keep `health.bind_address` on `127.0.0.1:8080` for native deployments unless an internal proxy, VPN, or load balancer needs it

5. Edit `deploy/production.env`:

- confirm paths
- set a different image tag if you build a Tor-enabled image

## Docker Compose Deployment

The Dockerfile uses Docker Hardened Images and requires authentication to `dhi.io`.

Build the default image:

```bash
docker login dhi.io
docker build -t transponder:local .
```

If you need onion relay support, build a Tor-enabled image instead:

```bash
docker login dhi.io
docker build --build-arg CARGO_FEATURES='--features tor' -t transponder:tor .
```

The Dockerfile pins the DHI base images by digest, and `compose.prod.yml` runs only the Transponder container.

Start the service:

```bash
docker compose -f compose.prod.yml --env-file deploy/production.env up -d
```

If you built a Tor-enabled image, set `TRANSPONDER_IMAGE=transponder:tor` in `deploy/production.env` before starting the stack.

The Compose stack publishes Transponder on `127.0.0.1:${TRANSPONDER_PUBLISHED_PORT}` by default and sets `TRANSPONDER_HEALTH_BIND_ADDRESS=0.0.0.0:8080` inside the container so Docker port publishing can reach it. If you need remote access to `/health`, `/ready`, or `/metrics`, put it behind your existing proxy, VPN, or SSH tunnel rather than publishing it broadly.

## Native systemd Deployment

For operators who do not want Docker at all, a native `systemd` deployment is a good fit. Transponder is a single stateless binary with a config file and a small set of credential files.

Example host layout:

- `/usr/local/bin/transponder`
- `/etc/transponder/config.toml`
- `/etc/transponder/secrets/server_private_key`
- `/etc/transponder/credentials/AuthKey_XXXXXXXXXX.p8`
- `/etc/transponder/credentials/service-account.json`

Build and install the binary:

```bash
cargo build --release
install -m 0755 target/release/transponder /usr/local/bin/transponder
install -d -m 0750 /etc/transponder /etc/transponder/secrets /etc/transponder/credentials
install -m 0640 config/production.toml /etc/transponder/config.toml
install -m 0640 secrets/server_private_key /etc/transponder/secrets/server_private_key
```

If you need onion relay support, build with:

```bash
cargo build --release --features tor
```

Copy `deploy/transponder.service.example` to `/etc/systemd/system/transponder.service`, adjust paths if needed, then enable it:

```bash
systemctl daemon-reload
systemctl enable --now transponder
systemctl status transponder
journalctl -u transponder -f
```

If you need OpenRC or BSD jails, the same binary/config/credentials layout applies, but this repository currently provides a first-class example only for `systemd`.

## Verify the Deployment

Docker:

```bash
docker compose -f compose.prod.yml --env-file deploy/production.env ps
docker compose -f compose.prod.yml --env-file deploy/production.env logs -f transponder
curl http://127.0.0.1:${TRANSPONDER_PUBLISHED_PORT:-8080}/health
curl http://127.0.0.1:${TRANSPONDER_PUBLISHED_PORT:-8080}/ready
curl http://127.0.0.1:${TRANSPONDER_PUBLISHED_PORT:-8080}/metrics
```

systemd:

```bash
systemctl status transponder
journalctl -u transponder -f
curl http://127.0.0.1:<HEALTH_PORT>/health
curl http://127.0.0.1:<HEALTH_PORT>/ready
curl http://127.0.0.1:<HEALTH_PORT>/metrics
```

For Docker, `TRANSPONDER_PUBLISHED_PORT` defaults to `8080` if unset. For native deployments, use the port from `health.bind_address`; the production example defaults to `127.0.0.1:8080`.

`/ready` should return HTTP 200 only when at least one relay is connected and at least one push provider is configured.

## Upgrade Procedure

Docker:

```bash
docker login dhi.io

# Default deployment
docker build -t transponder:local .

# Tor-enabled deployment for onion relays
docker build --build-arg CARGO_FEATURES='--features tor' -t transponder:tor .

docker compose -f compose.prod.yml --env-file deploy/production.env up -d
```

Build `transponder:local` for the default deployment path, or `transponder:tor` when `TRANSPONDER_IMAGE` points at a Tor-enabled image for onion relays.

systemd:

```bash
cargo build --release
install -m 0755 target/release/transponder /usr/local/bin/transponder
systemctl restart transponder
```

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
- Rotate the Transponder private key carefully because clients need the new public key
- Keep logging at `info` unless debugging an issue
- Review unusual growth in queue size, token decryption failures, relay disconnects, or push failure rates
- If you do not need onion relays, keep the default non-Tor build to reduce dependency and attack surface
- Bring your own monitoring:
  - scrape `/metrics` with the Prometheus-compatible stack you already operate
  - keep that endpoint private unless you have an explicit access-control layer
