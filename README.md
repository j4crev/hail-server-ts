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
bun test
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
