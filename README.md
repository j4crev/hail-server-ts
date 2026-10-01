# Hail Server TypeScript

Reusable Bun and Hono provider implementation for Hail Protocol.

This repository is under active development. The implementation method,
security limitations, and deployment procedure are documented in the sibling
Hail Protocol checkout at
[`../hailproto/docs/typescript-backend-poc.md`](../hailproto/docs/typescript-backend-poc.md).

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

## Single-Use Replies (Local POC)

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
continuity-preserving provider migration work remain outstanding.

## Portable Provider Cutover (Disposable Rehearsal)

Migrations 13–25 add DID-scoped source write fences, authenticated immutable
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
User-facing grant submission, automatic outbox retries, public
PLC submission and activation CLIs are **not implemented**; an independent
monitor, mirror/checkpoint, vault recovery and destination-domain publication still
require production infrastructure. Do not deploy this rehearsal as a public
transfer service.
The current public POC accounts were created with custodial keys in a private
directory and **must not be used as portable migration sources**. Separate
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
