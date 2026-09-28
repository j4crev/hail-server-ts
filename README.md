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
Grant is revoked and its signed envelope did not invite replies; this phase
has not been deployed to the public providers.

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
