# Hail Server TypeScript

Reusable Bun and Hono provider implementation for Hail Protocol.

This repository is under active development. The implementation method,
security limitations, and deployment procedure are documented in the sibling
Hail Protocol checkout at
[`../hailproto/docs/typescript-backend-poc.md`](../hailproto/docs/typescript-backend-poc.md).

## Current POC and guides

The deployed private-PLC POC supports Grant-authorized detached-body delivery,
signed terminal status, revocation, single-use replies and user-authorized
provider transfer with pending-message continuity. Provider databases are at
migration 31. A separate same-VPS monitor proves signed-alert functionality,
but is not independent production monitoring.

- [Provider deployment and delivery runbook](deploy/poc/README.md).
- [User-device vault/signing client](https://github.com/j4crev/hail-user-client-ts#readme).
- [Transfer/recovery checkpoints](https://github.com/j4crev/hailproto/blob/main/docs/production-portable-custody.md#resuming-a-private-plc-poc-ceremony).
- [Same-VPS monitor deployment](https://github.com/j4crev/hail-plc-monitor-ts/blob/main/deploy/poc/README.md).

Original Alice/Bob identities are custodial; only fresh user-key-held POC DIDs
use the portable ceremony. Public HTTPS activation is not public PLC registration.

## hailp Account API

Migration 32 adds the first authenticated account-management slice used by
`hailp` in `hail-user-client-ts`. It is separate from federation and supports
existing active accounts, account details, current signed Grant retrieval and
user-signed Grant creation/revocation import. It reuses the existing Grant
service and transactional publication outbox. This is local implementation
work; the recorded deployed POC remains at migration 31 until a separate rollout.

### Bootstrap credentials (provider operator)

```bash
bun run account:credential-create -- "$active_address" /secure/api.credential.json
# Add --write-grants for signed Grant submission/revocation:
bun run account:credential-create -- "$active_address" /secure/writer.credential.json --write-grants
bun run account:credential-revoke -- "$credential_id"
```

The issuance command writes the secret only to a new mode-`0600` file and
prints credential ID/account/scopes/expiry, not the token. Transfer the file
privately to the owner for CLI use. The database stores SHA-256 of a random
256-bit token; credentials have a fixed 30-day expiry and can be revoked.
Default scopes are `account:read` and `grants:read`; the write option adds
`grants:write`. No credential is issued for an inactive or fenced account.
Authentication is checked against current credential/account state for each
request; revocation prevents new authentication, rather than cancelling an
already admitted in-flight request. Credentials are provider-local and are
not exported in portable DID snapshots. Provision a fresh credential at the
destination after transfer.

### HTTP contract

Use `Authorization: Bearer <token>` over the configured provider HTTPS origin.
These paths are the reference provider's client API, not standardized Hail
federation operations:

| Operation | Scope | Result |
| --- | --- | --- |
| `GET /api/v1/account` | `account:read` | Own account/DID/address, custody classification, public identity/recovery metadata, migration state and scopes |
| `GET /api/v1/account/grants/{grant_id}` | `grants:read` | Own authoritative or received Grant, local role, exact base64url COSE bytes, digest and ETag; the CLI renders diagnostic JSON locally |
| `PUT /api/v1/account/grants/{grant_id}` | `grants:write` | Verify/store an initial or terminal user-signed Grant; JSON acknowledgement of revision/status/digest and durable publication responsibility |

PUT uses `application/cose; cose-type="cose-sign1"`, no content coding, and a
256 KiB body limit. The signature/predecessor supplies update authority; this
account endpoint does not reuse the peer receiver's HTTP precondition contract.
Successful PUT returns `200` only after persistence. `publication: "durable"`
does not imply sender acknowledgement; exact retries do not create a new job.
Other accounts' Grant IDs return `404`; insufficient scope `403`; missing,
expired, revoked or inactive-account credentials `401`. Invalid signed input
returns `400`, state/fence/revision conflicts `409`, transport violations
`413`/`415`, and temporary dependency/storage failure `503`.

Responses use `Cache-Control: no-store` and `Vary: Authorization`; private keys,
credential values and hashes are never included. Custody classification is
reported from existing stored evidence/key roles, not proof of physical key
custody or an implementation of the planned managed profile. Fenced reads
can show retained history; writes remain blocked. The first process-wide
limit is 120 account API requests per minute, returning `429`/`Retry-After`;
distributed limits and production load calibration remain future hardening.

### Verification

The opt-in test exercises actual `hailp` processes against a local TLS Hono
server using a temporary CA trusted through `NODE_EXTRA_CA_CERTS` (never
disabled certificate verification). It requires OpenSSL and a disposable
PostgreSQL database:

```bash
DATABASE_URL=postgresql://hail:password@127.0.0.1:5432/hail_api_test \
  bun --bun vitest run test/account-api.integration.test.ts
```

It covers credential bootstrap/hashing, signed import, account/scope isolation,
collocated read-only ownership, invalid signatures, resource bounds, fences,
lost-response revocation retry, expired/revoked credentials and rejection of
redirects/insecure credential files. The user signer and vault remain outside
the provider; no user identity private key is stored there.

## API-first account management direction

The selected product architecture is an authenticated account API used by
human apps, agents and provider-native/Hail-provided CLI clients. Normal users
and agents should not need SSH, database credentials or administrator CLI
access. Owner-controlled accounts submit identity-signed objects; the approved
managed profile lets the provider sign authorized identity operations while
the account owner retains the top PLC recovery key. Both profiles are intended
for people and agents.

The current implementation has the authenticated account/Grant slice above,
federation/transfer routes and operator CLI building blocks, not the full
management API or the preferred managed onboarding profile. Extend the account boundary over existing services and
transactions rather than treating administrator CLIs as client APIs. The
[API and custody plan](https://github.com/j4crev/hailproto/blob/main/docs/production-portable-custody.md#api-first-provider-and-cli-clients)
defines the first authenticated slice, profile-specific signing, isolation,
renewal and managed-migration acceptance conditions.

## Development

Build the sibling codec first, install dependencies, and create local
configuration:

```bash
bun run --cwd ../hailproto/packages/hail-codec-ts build
pnpm --dir ../did-method-plc build
bun install
cp .env.example .env
```

Replace every placeholder secret and database credential before starting the
server.

```bash
bun run db:migrate
bun run typecheck
bun run test
bun run dev
```

The server also runs pending migrations before binding its HTTP listener.

With PostgreSQL and the configured private PLC directory running, create or
resume a custodial POC identity with:

```bash
bun run onboard -- alice@hailproto.app
```

The command is restart-safe and returns the same account and DID when repeated.
It stops at `address-staged`; WebFinger publication and activation are separate
steps.

Exercise WebFinger publication and the complete semantic verification path
locally with:

```bash
bun run activate:local -- alice@hailproto.app
```

This command deliberately routes HTTPS-shaped requests through Hono in memory.
It records `activationVerificationMode: "local"` and is not evidence of public
DNS, TLS, reachability, certificate, redirect, or DNS-rebinding behavior. Public
activation requires the later deployment verifier and records mode `public`.

The public VPS deployment and activation procedure is in
[`deploy/poc/README.md`](deploy/poc/README.md). After DNS and TLS are live, run:

```bash
bun run activate:public -- alice@hailproto.app
```

Initial health endpoints:

```text
GET /health/live
GET /health/ready
```

After an account is active, create or idempotently reuse its signed Sender
Profile from a closed JSON authoring document:

```bash
bun run profile:create -- alice@hailproto.app examples/alice-profile.json
```

Retrieve and verify a profile through current PLC state and hardened public
HTTPS transport with:

```bash
bun run profile:verify -- did:plc:aaaaaaaaaaaaaaaaaaaaaaaa
```

After both accounts have public activation evidence and the grantee's Sender
Profile verifies, create or idempotently reuse a signed Grant:

```bash
bun run grant:create -- \
  bob@hailproto.dev \
  alice@hailproto.app \
  examples/bob-to-alice-grant.json
```

Grant creation retains the exact verified Address Binding, Sender Profile, and
PLC evidence in the same transaction as immutable revision 1. It also creates a
durable publication outbox entry. The server checks that outbox every five
seconds; an operator can trigger one due attempt directly with:

```bash
bun run grant:publish -- --once
```

Revoke an authoritative Grant with a terminal signed revision:

```bash
bun run grant:revoke -- bob@hailproto.dev <grant-id>
```

Local revocation commits before publication and immediately remains
authoritative even if the remote notification needs retries. A revoked Grant ID
cannot become active again.

## Single-Use Replies (Private-PLC POC)

Reply authorization follows
[`../hailproto/spec/envelopes.md`](../hailproto/spec/envelopes.md#reply-authorization):
it is an invitation signed in a prior envelope, not a reverse-direction Grant.
After migration 12, the original sender can opt in when signing its
Grant-authorized envelope:

```bash
bun run envelope:create -- "$sender_did" "$grant_id" "$body_digest" updates \
  --reply-until "$reply_until_unix_seconds"
bun run envelope:submit -- "$sender_did" "$original_message_id"
```

Once that envelope has been accepted, the other provider publishes its own
body and signs one reply using the original message ID:

```bash
bun run body:publish -- "$reply_sender_did" examples/alice-body.txt
bun run envelope:reply -- "$reply_sender_did" "$original_message_id" "$reply_body_digest"
bun run envelope:submit -- "$reply_sender_did" "$reply_message_id"
```

Set the shell variables from the earlier commands' printed values. A reply
does not include a category and defaults to `reply.allowed: false`. Add
`--reply-until "$next_reply_until_unix_seconds"` to `envelope:reply` to
explicitly invite one further reply. The original sender serializes the
single-use claim before accepting a reply, consumes it on delivery, and
releases it after terminal failure or cancellation. The full phase and its
limitations are in the sibling POC guide. The already-demonstrated public
Grant is revoked and its signed envelope did not invite replies; the current
public reply demonstration and new Grant are recorded in `deploy/poc/README.md`.

To test the local PostgreSQL reply lifecycle against a disposable database:

```bash
DATABASE_URL=postgresql://hail:password@127.0.0.1:5432/hail \
  bun --bun vitest run test/reply-capabilities.integration.test.ts
```

Run the PostgreSQL repository integration test against a disposable migrated
database with:

```bash
DATABASE_URL=postgresql://hail:password@127.0.0.1:5432/hail \
  bun run test:integration
```

The integration test skips when `DATABASE_URL` is absent.

## Backend Hardening

The first hardening slice shares one response schedule and bounded validation
budget between envelope submission and delivery-status push. The provisional
750 ms response minimum, 10-second processing deadline, and 32-work provider
gate are not production-calibrated. The complete checklist and measurement
criteria are in the sibling TypeScript backend POC guide, Phase 12.
PLC directory reads now use a 5-second cancellable HTTP deadline, 1 MiB
decoded response ceiling, strict duplicate-member-rejecting JSON parsing,
and no redirects; the directory base is configured rather than derived from
an untrusted DID. PLC operation submission remains delegated to the pinned
official client, preserving onboarding's exact-operation retry semantics.

To exercise the initial response and PLC rotation fixtures without a running
provider database:

```bash
bun run test test/envelope-routes.test.ts test/protected-schedule.test.ts \
  test/envelope-deadline.test.ts test/plc-rotation-boundary.test.ts \
  test/plc-client.test.ts
```

Against a disposable PostgreSQL database, the ambiguous PLC-write fixture
tests restart-safe exact-operation reconciliation, exact retransmission after
an uncommitted request, and hash-prefix collision rejection:

```bash
DATABASE_URL=postgresql://hail:password@127.0.0.1:5432/hail \
  bun --bun vitest run test/onboarding-restart.integration.test.ts
```

The PLC fixture validates a signed operation-log update and current endpoint
selection. It does not simulate the fenced provider-state transfer required
for a real service migration. The first bounded-processing and PLC-read slice
is deployed to both public POC providers; tested runtime and backup details
are in `deploy/poc/README.md`. Further sustained-load calibration and
broader migration failure/recovery coverage remain outstanding. One live
private-PLC transfer has delivered a previously accepted message exactly once.

## Portable Provider Cutover (Disposable Rehearsal)

Migrations 13–31 add DID-scoped source write fences, authenticated immutable
snapshots, destination-owned prepared operational keys, a signed user-consent
and PLC operation check, and an inactive destination import. The activation
service verifies two independently witnessed current PLC reads and monitor
coverage for the exact top-user-key-signed operation, with no fixed wait, and
the user's externally published Address Binding before importing all state in
one transaction. It renews the Sender Profile with the destination messaging
key, normalizes inherited leases, and gives the source a signed retirement
receipt. The source never receives the destination private key; the snapshot
contains **no encrypted private-key ciphertext** from the source.

Before fencing, the source validates a user-identity-signed Transfer Grant
naming a **provider domain**, derives that provider's fixed well-known HTTPS
invitation endpoint, and sends a signed invitation. The destination verifies
both signatures, prepares keys and returns an inactive signed **Transfer
Offer** over TLS. The old provider retains origin proof of the offered key.
The client then directly signs and submits its chosen address under that
domain to the new provider, which reserves the address atomically in its
local account namespace and returns a signed receipt. The new provider
**pushes** a final Transfer Request, signed by the offered key, to the old
provider's fixed endpoint. The source verifies the exact user selection and
reservation and consumes the user grant
atomically with the fence. Neither source messaging nor provider PLC keys can
issue the user grant or sign the final top-recovery-key PLC operation.

The user client can POST its signed grant to the current source's fixed
`/hail/transfers/grants` endpoint. A `200` returns the origin-verified Offer;
`202` means invitation delivery remains pending and retrying the **same**
signed grant retrieves it once available. PostgreSQL-leased source/target
workers retry pending invitations and final requests after restarts. Rate
buckets are shared by provider processes. Before fencing, the user can sign
an exact transfer cancellation: the old provider signs a no-fence receipt,
and only that receipt allows the target to release an ambiguous submitted
reservation. Expiry cleanup releases only transfers with no final push.

These commands are operator building blocks, **not a public migration
procedure**: `transfer:grant` in `../hail-user-client-ts` produces a private
signed domain grant; `migration:invite -- <grant-file> <invitation-file> <offer-file>`
on the source validates/stores it, sends the invitation to the derived fixed
well-known HTTPS endpoint, and saves the inactive origin-verified Offer.
If delivery fails after grant issuance, retry with
`migration:deliver-invitation -- <local-did> <new-offer-file>` rather than
reissuing the still-live grant. The user reference client signs and sends an
Address Selection directly to the new provider; its server reserves the
address and pushes the final request to the old provider. An ambiguous
push is retried from the target with `migration:publish-final -- <transfer-id>`.
The old provider's final-request endpoint returns `204` only after it fences
the DID; `migration:fence -- <final-request-file> <selection-file> <receipt-file>`
is an operator diagnostic that still requires origin-proven offer state. Then
run
`migration:export` on the source and
`migration:stage` with separate user-signed consent, exact signed PLC update,
and fresh user-signed Address Binding. Export and consent files must be private
(`0600`) and transferred over an authenticated administrative channel.
The reference client additionally has `transfer:submit-grant` and
`transfer:cancel` commands. Production account UX, automatic submission
of the final user-signed PLC operation and activation CLIs remain open; an independent
monitor, mirror/checkpoint, vault recovery and destination-domain publication still
require production infrastructure. Do not deploy this rehearsal as a public
transfer service.
The original Alice/Bob POC accounts were created with custodial keys in a private
directory and **must not be used as portable migration sources**. New user-held
private-PLC DIDs have completed the separate POC ceremony below. Separate
reference projects now exist at `../hail-user-client-ts` for user-controlled
key generation, encrypted vault recovery and offline signing, and
`../hail-plc-monitor-ts` for user-run independent PLC monitoring and signed
coverage attestations. They are reference implementations, not production
infrastructure. Mobile clients can implement the same signing profile with
platform-specific secure storage. See the sibling
`../hailproto/docs/production-portable-custody.md` for the complete trust model.

Test the safe cutover boundaries using two disposable PostgreSQL databases:

```bash
DATABASE_URL=postgresql://hail:password@127.0.0.1:5432/hail_source \
TRANSFER_TARGET_DATABASE_URL=postgresql://hail:password@127.0.0.1:5432/hail_target \
  bun --bun vitest run test/migration-fence.integration.test.ts
```

### Private-PLC POC Ceremony (New DIDs Only)

The `private-poc` profile is explicitly restricted to the POC's internal
`http://plc:2582` registry and the configured `hailproto.app`/`hailproto.dev`
Hail service bases. Disposable tests also permit `http://plc.fixture:2582`.
It uses one validated canonical private PLC log and records `poc-local`
monitor evidence: **no independent mirror or monitoring guarantee is implied**.
The normal public activation profile still requires `https://plc.directory`,
two independent read paths and the signed external monitor attestation.

For a **fresh** POC DID, generate and independently back up a user vault using
`../hail-user-client-ts`. After verifying its recovery secret, the source
provider and client run:

```text
source: poc:prepare-portable -- <address> <user-recovery-key> <user-identity-key> <new-private-preparation-file> --backup-verified
client: poc:sign-onboarding -- <vault> <preparation-file> <new-signed-output-file>
source: poc:register-portable -- <signed-output-file>
source: activate:public -- <address>
```

The source imports the exact user-signed genesis and Address Binding before
`activate:public` verifies public HTTPS WebFinger and binding retrieval. Here
`activate:public` describes the **external HTTPS address verification**,
not registration on the public PLC network. The source stores its own
operational keys but neither user private key. Existing custodial POC DIDs
cannot be reused for this profile.

After the user signs/submits a Transfer Grant and selects an address at the
other POC provider, use `migration:export` on the fenced source:

```text
client: poc:sign-cutover -- <vault> <snapshot> <origin-verified-offer> <signed-reservation> <new-consent> <new-plc-operation> <new-binding>
target: migration:stage -- <snapshot> <consent> <plc-operation> <binding>
target: poc:submit-cutover -- <transfer-id>
target: poc:publish-address -- <transfer-id>
target: poc:activate-transfer -- <transfer-id> <new-receipt-file>
source: poc:retire-source -- <did> <transfer-id> <receipt-file>
```

The client signs the exact PLC cutover, consent and Address Binding; the
source verifies the target's activation receipt before retiring. Signed files must
be private mode `0600`, transferred over an authenticated administrative
channel. The user-held vault/recovery secret never goes to either provider.
No signed cutover is submitted automatically by starting the web server.

To rehearse message continuity with a user-held identity, the source POC
provider can prepare a Grant after verifying the sender address and profile:

```text
source: poc:grant-propose -- <user-address> <sender-address> <offered-category> <new-proposal-file>
client: poc:sign-grant -- <user-vault> <proposal-file> <reviewed-own-address> <reviewed-sender-address> <new-signed-grant.cose>
source: poc:grant-import -- <user-address> <sender-address> <signed-grant.cose>
source: grant:publish -- --once
```

The client signs with its own `#hail-identity` key; the source re-verifies
the exact Address Binding, Sender Profile, chosen scope and consent hashes
before queuing publication. Import of unchanged signed bytes is idempotent.
An accepted message with a pending delivery obligation can then be used to
test more than empty-account transfer.

Migration 31 preserves both local Grant roles when a transfer places grantor
and grantee on the same provider, retaining one exact immutable revision
chain. Activation, signed receipt writes and retirement support exact
completion retries after a lost response. Resume the existing staged transfer
after a fault; never release an exported fence or re-sign a submitted PLC
operation merely to get past a failure. Returning to a former provider with a
retained retired account and coordinated post-export rollback remain separate
work. See the linked recovery guide and deployment log for the verified proof.

For user-held Grant revocation, the client signs a terminal successor of the
exact current Grant; the provider uses the same signed-Grant import command:

```text
client: poc:revoke-grant -- <user-vault> <current-grant.cose> <reviewed-grant-id> <reviewed-sender-address> <new-revocation.cose>
current-provider: poc:grant-import -- <user-address> <reviewed-sender-address> <revocation.cose>
```

The provider checks the current user identity signature, local ownership,
exact predecessor, timestamps and preserved fields, then commits the terminal
revision and publication outbox entry atomically. It never retrieves a
provider-held user identity key, and it does not require sender/profile
availability or an unexpired Grant. Exact retries converge without another
revision or job. Existing fences and collocated grantor/grantee roles continue
to apply. `grant:revoke` remains the custodial authoring command; user-held
accounts use signed import. See the client README for its reference-vault
limitation: routine unlocking currently also loads the PLC recovery key and
needs an identity-only path before production.
