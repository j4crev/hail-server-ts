# Public POC Deployment

This deployment runs both Hail providers, a private PLC directory, three
PostgreSQL databases, and Caddy on one VPS. Only Caddy ports 80 and 443 are
published.

The sibling checkout layout must be preserved:

```text
<deployment-root>/
|-- hailproto/
|-- hail-server-ts/
`-- did-method-plc/
```

## VPS Baseline

Use Ubuntu 24.04 or a newer supported release with at least 2 vCPU, 4 GB RAM,
40 GB storage, and one static public IPv4 address. Permit inbound TCP 80 and 443 from anywhere. Permit TCP 22
only from trusted administrator addresses when practical. UDP 443 is optional
and enables HTTP/3. Do not open PostgreSQL or PLC ports.

On Ubuntu 26.04, install the distribution-maintained Docker Engine and Compose
plugin, then verify:

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-v2
sudo systemctl enable --now docker
docker version
docker compose version
```

On Ubuntu 24.04, Docker's official Ubuntu repository can instead be used:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${UBUNTU_CODENAME:-$VERSION_CODENAME} stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER"
newgrp docker
docker version
docker compose version
```

Configure both the Hostinger network firewall and the VPS firewall. Confirm the
SSH allow rule works before enabling UFW so the administrator is not locked
out:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 443/udp
sudo ufw enable
sudo ufw status verbose
```

Create the deployment directory on the VPS:

```bash
sudo mkdir -p /opt/hail-poc
sudo chown "$USER":"$USER" /opt/hail-poc
```

Transfer or clone `hailproto`, `hail-server-ts`, and `did-method-plc` into that
directory with the sibling layout shown above. If cloning PLC independently,
verify the required revision:

```bash
cd /opt/hail-poc/did-method-plc
git checkout 996e23b5ced9c15b32bcc612dd304880342ca4ab
test "$(git rev-parse HEAD)" = 996e23b5ced9c15b32bcc612dd304880342ca4ab
```

Before continuing, this command must list all three directories:

```bash
ls -d /opt/hail-poc/{hailproto,hail-server-ts,did-method-plc}
```

## Secrets

From `/opt/hail-poc/hail-server-ts/deploy/poc`:

```bash
cp .env.example .env
chmod 600 .env
```

Generate independent values. The database passwords use base64url so they are
safe in PostgreSQL URLs:

```bash
openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
```

Run that command separately for `APP_DB_PASSWORD`, `DEV_DB_PASSWORD`,
`PLC_DB_PASSWORD`, `PLC_ADMIN_SECRET`, `APP_KEY_ENCRYPTION_KEY`, and
`DEV_KEY_ENCRYPTION_KEY`. Never reuse a value. Set `ACME_EMAIL` to the operator
email used for certificate-expiration notices.

## Cloudflare DNS

Create one apex record in each Cloudflare zone:

```text
Type: A
Name: @
Content: <VPS public IPv4>
Proxy status: DNS only
TTL: Auto
```

Leave the orange-cloud proxy disabled for the initial POC. Do not create an
`AAAA` record until IPv6 is configured on the VPS and tested end to end.

Verify from outside the VPS:

```bash
dig +short A hailproto.app
dig +short A hailproto.dev
```

Both results must equal the VPS address before starting Caddy.

## Start

Validate and build:

```bash
docker compose --env-file .env -f compose.yaml config --quiet
docker compose --env-file .env -f compose.yaml build
```

Start the private services first:

```bash
docker compose --env-file .env -f compose.yaml up -d \
  app-db dev-db plc-db plc plc-sequencer hail-app hail-dev
docker compose --env-file .env -f compose.yaml ps
```

Both providers, PLC, and all three databases must become healthy, and the PLC
sequencer must remain running. Then start Caddy:

```bash
docker compose --env-file .env -f compose.yaml up -d caddy
docker compose --env-file .env -f compose.yaml logs --no-log-prefix caddy
```

Confirm that the sequencer has acquired leadership:

```bash
docker compose --env-file .env -f compose.yaml logs --no-log-prefix plc-sequencer
```

Verify HTTPS from another network:

```bash
curl --fail --silent --show-error https://hailproto.app/health/ready
curl --fail --silent --show-error https://hailproto.dev/health/ready
```

## Create Test Identities

```bash
docker compose --env-file .env -f compose.yaml exec hail-app \
  bun run onboard -- alice@hailproto.app
docker compose --env-file .env -f compose.yaml exec hail-dev \
  bun run onboard -- bob@hailproto.dev
```

Each command must reach `address-staged`. Then perform real public activation:

```bash
docker compose --env-file .env -f compose.yaml exec hail-app \
  bun run activate:public -- alice@hailproto.app
docker compose --env-file .env -f compose.yaml exec hail-dev \
  bun run activate:public -- bob@hailproto.dev
```

The result must be `active` with `activationVerificationMode` equal to
`public`. This command fails closed and withdraws WebFinger selection if DNS,
TLS, public reachability, PLC, binding, messaging key, or service verification
does not match the staged account.

Publish Alice's signed Sender Profile and verify it from the other provider:

```bash
docker compose --env-file .env -f compose.yaml exec hail-app \
  bun run profile:create -- alice@hailproto.app examples/alice-profile.json
docker compose --env-file .env -f compose.yaml exec hail-dev \
  bun run profile:verify -- did:plc:rewawq7tylmrzaaprd27sdhb
```

Profile creation is idempotent for unchanged authoring content and the current
messaging key. Changed content or a key rotation creates the next immutable
revision.

Create Bob's `updates` Grant for Alice from Bob's provider:

```bash
docker compose --env-file .env -f compose.yaml exec hail-dev \
  bun run grant:create -- \
  bob@hailproto.dev alice@hailproto.app examples/bob-to-alice-grant.json
```

The command prints the canonical UUIDv7 Grant ID and revision digest. Creation,
consent evidence retention, and the publication outbox entry commit atomically.
The `hail-dev` server worker claims due entries every five seconds, resolves
Alice's current PLC service, and conditionally publishes the exact signed bytes
to `PUT /hail/grants/{grant_id}`. To request one immediate due attempt:

```bash
docker compose --env-file .env -f compose.yaml exec hail-dev \
  bun run grant:publish -- --once
```

Inspect both databases without printing private key material:

```bash
docker compose --env-file .env -f compose.yaml exec dev-db \
  psql -U hail -d hail -c \
  'SELECT grant_id, local_role, current_revision, current_status FROM grant_lineages;'
docker compose --env-file .env -f compose.yaml exec app-db \
  psql -U hail -d hail -c \
  'SELECT grant_id, local_role, current_revision, current_status FROM grant_lineages;'
```

Both sides should show revision `1` and status `active`. The dev row has local
role `grantor`; the app row has local role `grantee`. Publication retries remain
durable across process and host restarts.

To demonstrate terminal revocation, run on Bob's provider:

```bash
docker compose --env-file .env -f compose.yaml exec hail-dev \
  bun run grant:revoke -- bob@hailproto.dev <grant-id>
```

The local row becomes revoked before notification. After publication, both
providers show revision `2` and status `revoked`. Repeating the revoke command
returns the existing tombstone without creating another revision.

## IPv6

After IPv4 activation succeeds, configure the VPS's static IPv6 address and
firewall. Verify Docker-published HTTPS over IPv6 before adding DNS:

```bash
curl -6 --resolve hailproto.app:443:[<VPS IPv6>] https://hailproto.app/health/ready
curl -6 --resolve hailproto.dev:443:[<VPS IPv6>] https://hailproto.dev/health/ready
```

Only then add DNS-only apex `AAAA` records in Cloudflare. Remove them
immediately if either external IPv6 health check fails.

## Operations

Inspect status and logs:

```bash
docker compose --env-file .env -f compose.yaml ps
docker compose --env-file .env -f compose.yaml logs --since 10m
```

Stop containers without deleting data:

```bash
docker compose --env-file .env -f compose.yaml down
```

Never use `down --volumes` on the deployed POC. The named volumes contain the
PLC operation log, provider identities, encrypted private keys, bindings, and
protocol state, including Grant tombstones and publication attempts. Migration
7 is append-only and has no destructive down migration. Rollback after applying
it means restoring a tested pre-migration logical backup or continuing with the
new schema; do not edit an applied migration or delete Grant rows. VPS snapshots
are useful but do not replace tested PostgreSQL
logical backups or an independent encrypted copy of `.env`.

## Current POC

The first public POC was deployed on 2026-09-27:

```text
VPS: 2.25.253.153
OS: Ubuntu 26.04
Alice: alice@hailproto.app -> did:plc:rewawq7tylmrzaaprd27sdhb
Bob: bob@hailproto.dev -> did:plc:ih42yibclij7lv6264hoaodo
Activation evidence: public
```

Both domains use DNS-only Cloudflare apex `A` records. No `AAAA` records are
published. Let's Encrypt certificates are managed by Caddy. The deployment
secrets exist only at `/opt/hail-poc/hail-server-ts/deploy/poc/.env` with mode
`0600` on the VPS.
