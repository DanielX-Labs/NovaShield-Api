# Deploying NovaShield

This is a platform-neutral deployment walkthrough for the current Docker service.
It prepares a staging deployment first. Public production signup remains blocked
by the registration ownership finding in [the project review](project-review.md).
No cloud account, DNS, secrets or deployment is created by these instructions.

## 1. Choose the deployment shape

You need a continuously running Node/Docker service, a MongoDB replica set,
HTTPS ingress, outbound HTTPS to Pwned Passwords and outbound SMTP to Brevo.
The email worker runs inside each API instance; sleeping or request-only compute
will delay delivery. SES is not implemented; use `EMAIL_PROVIDER=brevo`.

Record the API hostname, application browser origin, ingress proxy addresses,
database network access and monitoring destination. For example:

```text
Browser: https://app.example.com
Auth API: https://auth.example.com/api/v1
Container: internal TCP port 4001
Database: dedicated novashield database on a replica set
```

Choose a region and instance size after measuring your expected load. Start with
one staging API instance and scale only after testing database contention and SMTP
throughput. MongoDB transactions require a supported deployment topology; a plain
standalone local `mongod` is insufficient. See [MongoDB transactions](https://www.mongodb.com/docs/manual/core/transactions/).

## 2. Prepare and verify the source

Use Node 24 (the CI and Docker major) and the committed lockfile. Run each command
separately and stop on failure:

```powershell
# Install the exact locked dependencies.
npm ci
npm run typecheck
npm run lint
npm test
npm run test:security
npm run build
npm audit --audit-level=high
```

Tests start isolated local replica sets and mock email/HIBP. Their first run may
download MongoDB. The local cached-binary workaround is recorded in
[verification results](hardening-verification.md); it is not a production dependency.
Never point tests at production. Require the `Security checks` workflow to pass for
the exact commit you intend to release, including the image smoke test.

## 3. Provision database, email and secrets

1. Create separate staging and production databases and scoped database users.
   Allow connections only from the service network/egress addresses. Enable TLS,
   backups and a restore policy. Startup creates collections/indexes, so the user
   must have those permissions on the service database.
2. Configure a verified Brevo sender and the provider's domain authentication.
   Confirm outbound SMTP connectivity from the hosting platform. Use 465 for TLS
   or 587 for STARTTLS; this code selects TLS according to the configured port.
3. Generate independent cryptographic secrets in your secret manager:
   `JWT_ACCESS_SECRET`, `AUTH_PEPPER`, `IP_HASH_SECRET` (at least 32 characters each)
   and `OUTBOX_ENCRYPTION_KEY` (exactly 32 random bytes as 64 lowercase hex characters).
   Do not reuse development keys or rotate existing peppers casually.
4. Store `MONGODB_URI`, SMTP login/key and key rings as runtime secrets. Keep retained
   keys with backups: restoring MongoDB without matching peppers/outbox keys is not
   full recovery. Follow [key rotation](production.md#secret-rotation).

For local development only, copy `.env.example` to `.env` if it does not already
exist, then replace placeholders privately. Do not overwrite an existing `.env`.
Never commit secrets or include them in Docker build arguments, screenshots or logs.

## 4. Set production configuration

Start with every required field in `.env.example`, inject real credentials through
the platform, and override the following values:

```env
# Production process and browser boundary.
NODE_ENV=production
PORT=4001
EXPENSEHUB_ORIGIN=https://app.example.com
COOKIE_SECURE=true
COOKIE_SAME_SITE=lax

# Delivery and password enforcement are required at production startup.
EMAIL_PROVIDER=brevo
OUTBOX_WORKER_ENABLED=true
PASSWORD_MIN_LENGTH=15
BREACHED_PASSWORD_CHECK_ENABLED=true
BREACHED_PASSWORD_FAIL_MODE=closed

# Initial bounds; validate them under your measured workload.
AUTH_HASH_CONCURRENCY=4
OUTBOX_CONCURRENCY=4
MAX_ACTIVE_SESSIONS=20
```

Set `TRUST_PROXY_CIDRS` only to the actual ingress source IPs/CIDRs. Leave it empty
when directly connected. Do not copy broad private-network ranges without checking
who can reach the service. The proxy must overwrite client forwarding headers and
the container must not be publicly reachable around that proxy. See
[Express proxy configuration](https://expressjs.com/en/guide/behind-proxies/).

The origin must have no trailing slash. Cross-site browser deployments need a
different cookie choice; see [integration](integration.md#2-configure-the-browser-boundary).
All Brevo sender/support/login fields remain required. Production startup rejects
placeholder secrets, insecure cookies, disabled workers and weakened password settings.

## 5. Build and exercise the image

Install Docker locally or use a CI runner with Docker. These commands use disposable
synthetic resources, not production credentials:

```powershell
# Run the repository's actual image test before publishing.
docker build -t novashield:ci .
node scripts/container-smoke.cjs
```

The script checks login, cookie flags, refresh replay, non-root/read-only operation,
restart and readiness on database loss. It does not prove HTTPS ingress or SMTP delivery.
Publish the tested image to your registry and record its immutable digest and source
commit. Configure your hosting service to run that digest, not a mutable `latest` tag.

For a Linux Docker host, the following illustrates runtime settings. Replace the
image reference and provision the environment file outside the repository with
restricted permissions, or use your platform's runtime secret injection instead:

```sh
# Bind privately; a separately configured HTTPS ingress fronts this port.
docker run -d --name novashield \
  --restart unless-stopped \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL --security-opt no-new-privileges \
  --memory 512m --cpus 1 --pids-limit 128 \
  --stop-timeout 60 \
  --env-file /etc/novashield/runtime.env \
  -p 127.0.0.1:4001:4001 \
  registry.example.com/novashield@sha256:REPLACE_WITH_TESTED_DIGEST
```

512 MiB and one CPU are staging starting points, not capacity guarantees. The image
already sets `USER node`. Do not override it with root. Docker environment variables
are visible to administrators with Docker access; restrict that access. See
[Docker runtime options](https://docs.docker.com/engine/containers/run/).

## 6. Configure ingress and health checks

Create DNS for the chosen API hostname and attach a valid TLS certificate at the
ingress. Forward the original API path, preserve Host, overwrite forwarded headers,
and restrict access to the container. Configure ingress request-size, connection and
rate limits. Allow legitimate CORS preflight requests. Do not cache authentication
responses or log Authorization, cookies, request bodies or response tokens.

Use `/api/v1/health` for liveness and `/api/v1/ready` for traffic readiness. Readiness
must return 200 before traffic is routed; database loss returns 503. Do not treat
an SMTP outage as process death; alert on outbox failures/backlog instead. Allow
startup time for database/index initialization and at least 60 seconds for termination.

## 7. Run staging acceptance through the real hostname

1. Confirm HTTPS health/readiness and inspect sanitized startup logs.
2. With a controlled mailbox, register, receive the email, verify, then login.
   Record actual inbox receipt; SMTP acceptance alone is insufficient.
3. In a real browser, inspect HttpOnly/Secure/SameSite/path, refresh, logout, session
   revocation and password reset. Use the reset challenge ID from its email.
4. Verify an unauthorized Origin is rejected and spoofed forwarding headers do not
   change abuse identity. Test this through your real ingress topology.
5. Terminate an instance while an email job is pending; confirm another/restarted
   worker recovers it. At-least-once delivery permits duplicate emails.
6. Exercise outbox age/backlog warnings and a database outage in staging. Confirm
   alerts reach the operator and readiness recovers when storage returns.
7. Restore a backup into an isolated database; verify credentials, retained key rings,
   indexes, transactions and recovery. Never restore over the live service as a test.
8. Measure peak concurrency, Argon2 memory, response latency and queue age. Tune bounds
   without dropping the password-security baseline.

## 8. Promote and roll back deliberately

Fix the release-blocking findings, pass the [release gate](deployment-release.md),
and promote the same tested image/configuration to production. Keep staging and
production data/secrets separate. Record deployment time, digest and validation evidence.

Keep the previous image digest and compatible configuration available. On failure,
stop promotion, drain the bad revision and restore the previous compatible revision.
Do not blindly downgrade across reset protocol-v2 or key changes: older code may
re-enable invalidated challenges or fail to read newer records. Prefer a forward fix
when compatibility has not been demonstrated. A database restore is a separate
disaster-recovery decision, not an automatic deployment rollback.

## Troubleshooting

| Symptom | First check |
| --- | --- |
| Startup configuration error | Reported field names; exact origin, real secrets, secure cookies, worker enabled |
| Database startup/readiness fails | Replica set, DNS/TLS, network allowlist, database permissions |
| 202 but no email | Worker enabled, pending queue age, SMTP connectivity, sender configuration and inbox/spam |
| Browser cookie missing | HTTPS, credentials include, SameSite/site relationship, cookie path |
| Repeated 429 across clients | Actual proxy boundary and forwarded client identity |
| Unexpected refresh replay | Concurrent tabs/requests or retry after a lost response |
| Password operation returns 503 | HIBP connectivity, hash concurrency, database and safe operation logs |

Current status: local automated tests passed; live CI/container, ingress, restore,
alerting and inbox evidence still need completion. This guide is not evidence of deployment.
