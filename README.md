# NovaShield authentication service

NovaShield owns credentials and session security independently of application profiles.
It provides registration, email verification, login, token rotation, replay detection,
session management and password lifecycle security.

## Does NovaShield need a frontend?

No separate frontend is required to run this API. A consuming application supplies
registration, verification, login, recovery and session-management screens. You can
also exercise the API with an HTTP client. NovaShield currently has no hosted login
page, admin dashboard, OAuth/OIDC authorization server or client SDK.

Your application keeps profiles and business data; NovaShield owns credentials,
verification and sessions. The `EXPENSEHUB_ORIGIN` setting is the allowed browser
origin, even when the consuming application has a different name.

## Integration and deployment

- Start with the [software integration guide](docs/integration.md): endpoint contracts,
  browser cookies, token handling, backend trust and migration boundaries.
- Follow the [deployment walkthrough](docs/deploy.md): local setup, image checks,
  production configuration, HTTPS ingress, staging acceptance and rollback.
- Read the [current project review](docs/project-review.md) before release. The
  registration ownership finding is a release blocker; passing tests alone do not
  make this a production-approved identity service.

## Local setup

Use Node 24 and a MongoDB replica set (transactions are required).

```powershell
npm ci
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
# Replace placeholders locally; never commit secrets.
npm run typecheck
npm test
npm run dev
```

Set `OUTBOX_ENCRYPTION_KEY` to 32 random bytes encoded as 64 hex characters.
Enable `OUTBOX_WORKER_ENABLED=true` only after configuring the intended SMTP provider.
Email jobs are queued even while the worker is disabled. OTP jobs expire rather than
sending stale codes. Use a dedicated development database and test inbox.

## Documentation

- [Registration](docs/registration.md)
- [Login](docs/login.md)
- [Sessions](docs/session-lifecycle.md)
- [Password lifecycle](docs/password-lifecycle.md)
- [Abuse defense](docs/auth-abuse.md)
- [Production operations and deployment gates](docs/production.md)

## Checks

`npm run lint`, `npm run typecheck`, `npm test`, `npm run test:security`,
`npm run build`, and `npm audit --audit-level=high` run in CI.
Tests normally create local ephemeral MongoDB replica sets. The explicit
`node scripts/test-with-configured-db.cjs` runner uses isolated test databases on a
configured server when a local MongoDB binary is unavailable. Neither test mode sends
real email. Do not run tests against a production deployment.
