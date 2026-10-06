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

## Detached-Body And Delivery Rollout

The envelope and status slice adds forward-only provider migrations 8 through
11. Back up **both** provider databases before replacing either provider. From
`/opt/hail-poc/hail-server-ts/deploy/poc` on the VPS, as the administrator:

```bash
backup=/var/backups/hail-poc/pre-delivery-$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 0700 "$backup"
docker compose --env-file .env -f compose.yaml exec -T app-db \
  pg_dump -U hail -d hail -Fc > "$backup/app.dump"
docker compose --env-file .env -f compose.yaml exec -T dev-db \
  pg_dump -U hail -d hail -Fc > "$backup/dev.dump"
chmod 0600 "$backup"/*.dump
docker compose --env-file .env -f compose.yaml exec -T app-db \
  pg_restore --list < "$backup/app.dump" >/dev/null
docker compose --env-file .env -f compose.yaml exec -T dev-db \
  pg_restore --list < "$backup/dev.dump" >/dev/null
```

Confirm both nonempty dumps and a clean `pg_restore --list` result before the
rollout. The provider startup migrates under a PostgreSQL advisory lock. Build
the single shared provider image, replace both instances, and verify both
report healthy. Do not edit migrations that have already been applied.

```bash
docker compose --env-file .env -f compose.yaml config --quiet
docker compose --env-file .env -f compose.yaml build hail-app
docker compose --env-file .env -f compose.yaml up -d --no-deps hail-app hail-dev
docker compose --env-file .env -f compose.yaml ps
docker compose --env-file .env -f compose.yaml exec -T app-db \
  psql -U hail -d hail -Atc 'SELECT max(version) FROM schema_migrations;'
docker compose --env-file .env -f compose.yaml exec -T dev-db \
  psql -U hail -d hail -Atc 'SELECT max(version) FROM schema_migrations;'
```

Both migration queries must print `11`. Check HTTPS readiness from outside the
VPS and examine provider logs for startup or publisher errors before sending.
Migration rollback requires restoration from the pre-rollout dumps; merely
replacing the image does not undo committed schema or messages.

For the end-to-end demonstration, create a **new** Bob-to-Alice Grant, because
the earlier example Grant is terminally revoked. Use the Grant creation and
publication commands above and wait until both provider databases show the
same new Grant ID with revision 1 and `active`. Set `grant_id` to that new
UUIDv7, `body_digest` to the digest printed by the first command below, and
`message_id` to the UUIDv7 printed by the second command. Use Alice's provider:

```bash
docker compose --env-file .env -f compose.yaml exec hail-app \
  bun run body:publish -- did:plc:rewawq7tylmrzaaprd27sdhb examples/alice-body.txt
docker compose --env-file .env -f compose.yaml exec hail-app \
  bun run envelope:create -- did:plc:rewawq7tylmrzaaprd27sdhb \
  "$grant_id" "$body_digest" updates
docker compose --env-file .env -f compose.yaml exec hail-app \
  bun run envelope:submit -- did:plc:rewawq7tylmrzaaprd27sdhb "$message_id"
```

The envelope command atomically persists the signed bytes and a hashed bearer
authorization before submission. No separate `body:authorize` command is
needed. A `200` signed `accepted` status confirms Bob's durable acceptance;
`202 received` is indeterminate. Retry `envelope:submit` with the **same**
message ID after an ambiguous result, never create a replacement envelope
merely because the transport response was lost. Bob's in-process delivery and
terminal-status workers run every five seconds; the single-claim commands
`bun run delivery:once` and `bun run status:publish` are available for an
immediate due attempt.

Inspect status without printing stored COSE bytes or bearer credentials:

```bash
docker compose --env-file .env -f compose.yaml exec -T dev-db \
  psql -U hail -d hail -c \
  'SELECT sender_did, message_id, state, reason, status_revision FROM delivery_work;'
docker compose --env-file .env -f compose.yaml exec -T dev-db \
  psql -U hail -d hail -c \
  'SELECT message_id, delivered_at FROM delivered_messages;'
docker compose --env-file .env -f compose.yaml exec -T dev-db \
  psql -U hail -d hail -c \
  'SELECT message_id, state, attempt_count, last_http_status FROM terminal_status_publications;'
docker compose --env-file .env -f compose.yaml exec -T app-db \
  psql -U hail -d hail -c \
  'SELECT message_id, current_state, current_revision, revision_gap FROM sent_delivery_status;'
```

Expected: Bob stores one delivered message, his delivery state reaches
`delivered`, terminal publication is `acknowledged` with HTTP `204`, and Alice
retains the matching signed `delivered` snapshot. Repeating the same envelope
submission must not create another delivery. Test an out-of-scope category and
invalid signature without exposing other tenants' relationship state; a
revocation-first submission must not enter `accepted`, while a previously
accepted envelope keeps delivery responsibility. Record actual results and
commit IDs in the protocol implementation log.

## Reply-Capability Rollout

Migration 12 adds single-use reply invitations and explicit authorization
lineage to sent and received envelopes. Before replacing either provider,
repeat the two `pg_dump -Fc` and `pg_restore --list` backup commands above
using a fresh `pre-reply-<UTC timestamp>` directory; keep both dumps and the
current provider image. Rebuild the shared provider image, replace `hail-app`
and `hail-dev`, check that **both** databases report schema version `12`, and
confirm both public readiness endpoints and provider logs are healthy.
Existing Grant envelopes and messages remain valid.

The prior demonstration Grant is terminally revoked, and the original message
did not invite a reply. Create and publish a **new active Bob-to-Alice Grant**
with the commands above. Record its new `grant_id`. Alice publishes a body:

```bash
docker compose --env-file .env -f compose.yaml exec -T hail-app \
  bun run body:publish -- did:plc:rewawq7tylmrzaaprd27sdhb examples/alice-body.txt
```

Set `body_digest` to its printed digest. Choose a future reply deadline (here,
30 days), then create the original envelope:

```bash
reply_until=$(($(date -u +%s) + 2592000))
docker compose --env-file .env -f compose.yaml exec -T hail-app \
  bun run envelope:create -- did:plc:rewawq7tylmrzaaprd27sdhb \
  "$grant_id" "$body_digest" updates --reply-until "$reply_until"
```

Set `original_message_id` to the UUIDv7 printed by `envelope:create`, then
submit it:

```bash
docker compose --env-file .env -f compose.yaml exec -T hail-app \
  bun run envelope:submit -- did:plc:rewawq7tylmrzaaprd27sdhb "$original_message_id"
```

Wait until Bob has accepted and durably delivered that message. On **Bob's**
provider, publish a reply body:

```bash
docker compose --env-file .env -f compose.yaml exec -T hail-dev \
  bun run body:publish -- did:plc:ih42yibclij7lv6264hoaodo examples/alice-body.txt
```

Set `reply_body_digest` to the printed digest, then create the reply:

```bash
docker compose --env-file .env -f compose.yaml exec -T hail-dev \
  bun run envelope:reply -- did:plc:ih42yibclij7lv6264hoaodo \
  "$original_message_id" "$reply_body_digest"
```

Set `reply_message_id` to the new UUIDv7 printed by `envelope:reply`, then
submit it:

```bash
docker compose --env-file .env -f compose.yaml exec -T hail-dev \
  bun run envelope:submit -- did:plc:ih42yibclij7lv6264hoaodo "$reply_message_id"
```

Bob needs no Grant from Alice for this reply. Check Alice's `delivery_work` and
`delivered_messages`, Bob's `sent_delivery_status`, and the terminal
publication outbox using the same SQL queries above with provider roles
reversed. Alice should accept exactly one reply, consume her original
`reply_capabilities` row, push signed `delivered` status, and receive a `204`
acknowledgement from Bob. An exact retry of Bob's reply returns current status
without creating another delivery. A second distinct reply referring to the
same original message must not be accepted. Unknown, expired, or wrong-party
invitations must receive the privacy-preserving generic outcome.

An outgoing reply defaults to `reply.allowed: false`. To invite one further
reply, add `--reply-until <future-unix-seconds>` to `envelope:reply`; see the
protocol's reply authorization and terminal transition rules before extending
a conversation. The old production image has no reply processing, so image
rollback after migration 12 requires reconciliation of any reply records
created since the upgrade; restore from the pre-reply dumps for a full
rollback.

## Protected-Response And PLC-Read Hardening Rollout

This slice makes **no schema change**: both databases should remain at
migration 12. It shares one bounded work budget across envelope and status
receivers and replaces unbounded private PLC reads with a five-second
cancellable request/stream deadline, a 1 MiB decoded response limit, strict
JSON parsing, and no redirects. The pinned official client still performs
exact PLC operation submission. The 750 ms protected response floor is
provisional; the implementation and measurement limits are documented in
Phase 12 of the sibling POC guide.

Before replacing either provider, save fresh custom-format dumps of **both**
provider databases and verify them with `pg_restore --list` using the backup
commands above, choosing a new `pre-hardening-<UTC timestamp>` directory. Tag
the currently deployed provider image for rollback. Build the single shared
image, replace `hail-app` and `hail-dev`, and confirm both become healthy with
zero restarts. Verify both HTTPS readiness URLs, the private PLC health and
read-back of Alice's and Bob's DIDs, and unchanged migration version `12`.

Retry an existing signed Alice-to-Bob envelope and the accepted Bob-to-Alice
reply by their **original message IDs** using `envelope:submit`. Each should
return the previously signed `delivered` snapshot with no additional delivered
message or status revision. Repeat protected malformed/missing-relationship
requests with fixed, bounded sample counts; compare exact generic `202`
status, headers, JSON body, and response times. Do not print or store signed
representations, bearer credentials, or provider `.env` values in timing logs.
The local test suite covers stalled PLC headers and streams, oversized and
ambiguous JSON responses, and late validation after the processing deadline;
the private PLC server is not intentionally stalled during the public smoke
test. Compare measured timing distributions to the recorded pre-rollout
baseline, then inspect provider logs and work-queue state.

Because this slice adds no migration, restoring the tagged prior provider
image is an image-only runtime rollback. Keep the pre-rollout logical backups
as independent recovery evidence. A complete response-floor calibration under
sustained load, source-network limits, write timeout policy, and fenced
provider migration remain separate hardening work.

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

Migration 7 and the signed Grant slice were deployed on 2026-09-28. Bob created
Grant `01a0e5c0-8657-7496-928b-a598cc79d0d0` for Alice's `updates` category.
Revision 1 converged in one `201` publication attempt; an unchanged authoring
retry reused the same signed representation. Bob then committed terminal
revision 2, which converged in one `204` publication attempt. Both providers
retain the two-revision chain and report the Grant as revoked. Pre-migration
logical backups are in
`/var/backups/hail-poc/pre-grant-20260928T020119Z`.

Migrations 8–11 and the detached-body, envelope, durable-delivery, and signed
status slices were deployed on 2026-09-28 from provider source `0dd5860` and
protocol guide `58b25fe`. Both pre-rollout provider dumps were verified at
`/var/backups/hail-poc/pre-delivery-20260928T123933Z`. The deployed provider
image is `sha256:7f8d8bea504d42d12feee077bccc02a2cde0cab1a1cb3d46f9ac715941553f74`;
the previous provider image is tagged
`hail-server-ts:pre-delivery-20260928T123933Z` on the VPS.

Bob's new Grant `01a0e809-cf1c-7fa5-99f3-c783aa1bfd28` converged at Alice
with HTTP `201`. Alice published a 120-byte body and submitted message
`01a0e80a-6718-741b-a7ba-c2eae2481ba7`; Bob returned signed `accepted`
revision 1, durably delivered the verified body, and pushed terminal revision
2. Alice acknowledged it with HTTP `204` and retained `delivered` revision 2.
An exact retry returned the delivered snapshot without another delivery. An
invalid signature received a generic `202`, and an out-of-scope category was
rejected before signing. Bob then revoked the Grant, published the tombstone
to Alice, and rejected a previously signed second envelope without accepting
new work; the first message remained delivered. The Grant is now terminally
revoked. Both provider containers remained healthy with zero restarts.

Migration 12 and single-use reply capabilities were deployed on 2026-09-28
from provider source `63d3188` and protocol guide `1d3253d`. Both provider
databases were backed up and the custom-format dumps checked at
`/var/backups/hail-poc/pre-reply-20260928T171842Z`; the prior provider image
was tagged `hail-server-ts:pre-reply-20260928T171842Z`. The deployed provider
image is `sha256:18a415d5ce77f97308643a427b8c2cf31f7af89012ea699a58d550ae594b7db3`.

Bob's fresh Grant `01a0e908-a1ae-77ab-802d-052ef09727f5` converged with
HTTP `201` and remains active. Alice's new signed original envelope
`01a0e909-54d0-70df-959c-fc5b4201ac09` invited Bob's DID to reply until
Unix second `1793208073`; Bob accepted and delivered the original. Bob then
prepared and concurrently submitted two distinct replies without an Alice-to-
Bob Grant. Alice accepted and delivered only
`01a0e90a-a0d8-7a21-bfe1-3a4487024d47`; the competing
`01a0e90a-79c8-75e0-83a1-83b63b487dca` received generic `202` and was
durably rejected with no delivery work. Alice consumed the invitation for the
accepted reply, pushed signed terminal revision 2 to Bob, and received HTTP
`204` in one attempt. Bob retained `delivered` revision 2; repeating the exact
reply returned that status without a second delivery. Alice could not reply
again because Bob's reply did not invite further continuation. Both providers
are healthy with zero restarts, and their databases are at migration 12.

The first backend-hardening slice was deployed on 2026-09-28 from provider
source `021dced` and protocol guide `e3f5f54`. No migration was added; both
provider databases remained at version 12. Both custom-format dumps were
validated under `/var/backups/hail-poc/pre-hardening-20260928T222933Z`, and the
prior runtime was tagged `hail-server-ts:pre-hardening-20260928T222933Z`.
The new shared provider image is
`sha256:76e04125b365a2b59dac2a36d8dba81629005deb9f58335694a5625922b8cb0a`.

Both public readiness URLs returned `200`. The bounded PLC read adapter
resolved Alice and Bob, validating their one-operation logs and retrieving
one audit entry each; a syntactically valid unknown DID retained the expected
`404`. An exact terminal-status PUT was acknowledged with bodyless `204`.
Eight-way Hono route measurements for eight protected cases had observed
95th-percentile samples of 750–757 ms. After restarting each provider in
turn, resubmitting the previously delivered Alice envelope and Bob reply
returned their signed `delivered` revision-2 snapshots; each message still
had exactly one delivered row and one body-retrieval attempt. Both providers
were healthy with zero unexpected restarts and no application errors.

Eight external HTTPS samples per protected generic path showed medians of
782 ms for both malformed envelope submission and unknown status push;
95th-percentile samples were 857 and 859 ms including network variance.
The provisional 750 ms server floor still needs sustained-load calibration.

### Portable-Custody Development Boundary

The runtime can now rehearse portable transfer **only** for new DIDs created
with user-held keys in this POC's private PLC directory. The original Alice
and Bob DIDs remain custodial and cannot be passed off as portable: their
provider-held `#hail-identity` key fails that precondition. The `private-poc`
mode pins `http://plc:2582`, permits only the two POC Hail service bases,
checks one validated private PLC history, and records `poc-local` monitoring
evidence. It does not use `plc.directory` or establish independent mirrors,
monitoring, or production portable-custody guarantees.

The new separate public reference projects are
<https://github.com/j4crev/hail-user-client-ts> (local user keys and encrypted
backup) and <https://github.com/j4crev/hail-plc-monitor-ts> (user-run PLC
monitor). No independently hosted monitor, verified public PLC export
checkpoint, or public `plc.directory` portable DID has been deployed. The
new provider-to-provider transfer below remains private-PLC POC evidence;
the full trust and rollout boundary is recorded in
`/opt/hail-poc/hailproto/docs/production-portable-custody.md` when that guide
is installed. Separate user-controlled monitor hosting remains deferred.

The private-PLC POC profile can rehearse **new** user-key-held identities on
this internal registry, using one canonical validated reader explicitly
labeled `private-poc`/`poc-local`. It cannot convert existing custodial DIDs
or establish independent public-registry finality. On 2026-10-01 both live
provider databases were backed up under
`/var/backups/hail-poc/pre-private-poc-20261001T215237Z` and restored to
isolated `hail_private_stage` copies. Migrations 13–30 applied successfully
to both copies. Two read-only schema-rehearsal provider containers returned
`200` readiness and served Alice's/Bob's cloned WebFinger records with HTTP
`200`; the **live** databases and runtime remained at migration 12 and
`021dced` after that first rehearsal. The temporary staging containers had
no public ports or background workers and were removed after verification.

### 2026-10-01: Private-PLC POC Runtime Rollout

Verified new custom-format backups at
`/var/backups/hail-poc/pre-private-poc-roll-20261001T220212Z` before updating
either live provider. The pre-rollout image was tagged
`hail-server-ts:pre-private-poc-20261001T220026Z` (image
`sha256:76e04125b365a2b59dac2a36d8dba81629005deb9f58335694a5625922b8cb0a`).
Both providers were rolled one at a time to source `3495ff5`, image
`sha256:3989adda60af3901c6e69959e56663733cacff28c576f218826bb74e3e6ab7b3`.
Their databases applied migrations 13–30; Alice's and Bob's original
WebFinger records and both public readiness endpoints still returned `200`.
No existing DID was reclassified as portable. The private PLC service and
its schema were not changed by the runtime rollout.

### 2026-10-05: First New-DID Provider Transfer

Before creating a new POC identity, backed up the app, dev, and private PLC
databases in custom format at
`/var/backups/hail-poc/pre-portable-did-20261005T203828Z`; all three dumps
passed PostgreSQL restore-list checks. A disposable encrypted user vault and
separate recovery material remain **only on the user machine**, outside all
provider checkouts. The local vault copy was restored and both keys verified;
this is not independent-device production backup evidence.

The user-held keys signed a new genesis on the private PLC for
`did:plc:eafyy6xd2mv4aj5kvtkhecnf`, initially at
`poc-move-20261005@hailproto.app`. The app provider stored only its own PLC
rotation/messaging keys and activated the address using public HTTPS
WebFinger/Binding verification. It published Sender Profile revision 1.
The signed user grant named `hailproto.dev`; the destination reserved
`poc-move-20261005@hailproto.dev` and pushed the final request. The app source
fenced and exported the signed state, after which the local user client
signed the exact private-PLC cutover, snapshot consent, and target binding.
The private PLC accepted the operation, and its two-operation log resolved
the new dev service/key. The dev provider staged and published the binding,
activated the import under a `private-poc` assessment, and signed the
activation receipt. The app source verified the receipt and retired its
permanent fence. Dev now serves Sender Profile revision 2 with its *own*
messaging key. Both providers stayed healthy without unexpected restarts.

The source initially still served WebFinger for the old demo address after
retirement. Provider fix `9448310` prevents retired DIDs from appearing in
address discovery without mutating their historical signed binding. The
fix was rolled one provider at a time to both containers (image
`sha256:e87d954d9af5a65dc149eeb551a68854d54ba0288c4bd9107dfd18210eef3ef9`);
`hail-server-ts:pre-retired-webfinger-20261005` retains the previous
migration-30 image. Afterwards the old demo address returned `404`, while
the new dev address, its Sender Profile and both older custodial addresses
returned `200`. Both live databases remain at migration 30, and both
containers are healthy with zero restarts.

## October 6, 2026: pending-message continuity and recovery

New user-held DID `did:plc:wmw2k7etmemhq3kw5tcjkj7n` moved dev → app in
transfer `b52605c3-a472-4a7a-94c1-8fa967b887f2`. Alice's message
`01a10f3b-f108-766a-b99f-647cc384fd1a` was accepted at dev before the fence.
Its signed delivery deadline was October 13, 03:27:29 UTC (envelope expiry
plus the 300-second delivery allowance); body/access availability extended
past that deadline. The temporary hold trigger was removed before cutover.

The initial activation failed transactionally because app already held Alice's
grantee copy of Grant `01a10f3a-c34c-79b4-b56b-96554579f160`. Migration 31
preserves one immutable revision chain with authoritative grantor ownership
and a second `collocated_grant_receivers` reference. The importing transaction
requires matching roles/DIDs/current metadata and exact revision bytes.
Do not delete the sender's Grant copy to bypass this collision.

Before rollout, restored app/dev/PLC dumps from
`/var/backups/hail-poc/pre-collocated-grant-fix-20261006T033731Z` into separate
`collocated_restore_{app,dev,plc}_20261006` databases. Applied migration 31 to
the provider copies and activated the actual failed staged transfer in the
app copy, using read-only live PLC/HTTPS verification. No restored server or
delivery worker was started. Both Grant roles and the unattempted accepted
message survived. The first candidate build exposed an incomplete VPS source
checkout (missing older migration files); synchronized full source/migrations
and rebuilt before either running provider was replaced.

Rolled app and dev separately, checking readiness between replacements. The
live exact staged transfer then activated, and its signed activation receipt
retired dev. Verified:

- app: `delivered`, revision `2`, one attempt, one `delivered_messages` row;
- app terminal publication: `acknowledged`, one attempt;
- dev: retained `accepted`, revision `1`, zero attempts, fence `retired`;
- old WebFinger: `404`; new WebFinger: `200`; both readiness endpoints: `200`.

The continuity DID had no Sender Profile in its snapshot; no profile was
invented during import. Use the required `rel=https://hailproto.com/rel/address-binding`
query when checking WebFinger.

Activation now recovers an already committed active transfer after current
PLC/key revalidation. Retirement accepts the exact authenticated retained
receipt on retry. Private signed-record writes accept identical bytes and
reject conflicts or files with permissions broader than `0600`. Tests cover
lost PLC responses after commit, exact-operation retries, unavailable
destination HTTPS, refusal to release an exported fence, and restart after
activation/retirement. The live CLIs were retried twice after provider restart;
the recovered receipt SHA-256 matched the archived original:
`2be991aeccf8d066e8523d19125fac7da89f88af7456dce07e7ed800498b37ba`.

Post-delivery backups are at
`/var/backups/hail-poc/post-continuity-20261006T034900Z`. Restored all three to
separate `continuity_restore_{app,dev,plc}_20261006` databases with
`pg_restore --exit-on-error`, without starting servers/workers or exposing
ports. Counts and sorted JSON-row fingerprints matched live accounts, keys,
Grant lineages/revisions, accepted envelopes, delivered messages and sender
statuses; PLC DID/operation fingerprints also matched. Both provider copies
passed migration checksum validation, and all seven operational keys per
provider decrypted successfully with the existing KEK, without printing key
material. This is a same-host logical restoration drill, not a host-loss or
independent-device recovery demonstration.

Migration 31 is additive. Retain the migration-30 image `hail-server-ts:poc-66acf0c`
and backups, but after collocation do not roll runtime back to code that ignores
the grantee reference. Prefer the tested compatible image or forward repair.
Restoring pre-cutover data requires reconciling PLC and both providers; it is
not a standalone rollback. See the protocol repository's
`docs/production-portable-custody.md` for the checkpoint-based recovery guide.

Local verification: typecheck/build, 107 ordinary tests and 45 sequential
PostgreSQL integration tests passed. The POC remains `private-poc` / `poc-local`.
Final tested image: `hail-server-ts:poc-continuity-20261006`, image ID
`sha256:35e2da4770f5b514829efd0554386790090289c10f17220fe3744852b5a8552d`.
It was built from the verified continuity and restart-recovery changes on
top of provider `66acf0c`. Both live databases are at
migration 31. Disposable restore databases were removed after verification;
the backups and archived signed activation receipt were retained.
