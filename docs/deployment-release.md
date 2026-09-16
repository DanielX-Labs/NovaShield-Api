# Deployment release gate

Repository preparation is not evidence that a deployed environment is ready.
Do not promote until the following checks pass for the exact release revision.

Start with the [deployment walkthrough](deploy.md). The latest
[project review](project-review.md) identifies a registration ownership release
blocker and resend disruption that must be corrected before public signup.

## Repository and image

- Run typecheck, lint, the complete unit/integration/security suites, build and dependency audit.
- Run the `Security checks` workflow for the release revision. It builds `novashield:ci`
  and runs `node scripts/container-smoke.cjs` with generated secrets and a disposable
  MongoDB replica set. No production credentials are needed by this workflow.
- The smoke script checks non-root/read-only execution, cookie flags, origin rejection,
  refresh replay, graceful restart and readiness during database loss. Its requests use
  local HTTP with an explicit cookie header; it does not verify a real HTTPS ingress.
- Publish/promote an immutable image digest only after these checks. Never bake `.env`
  into the image. Review the diff and confirm `.env` remains ignored before committing.

## Infrastructure-specific verification

Record the hosting platform, API hostname, frontend origin, trusted proxy CIDRs, image
digest and operator for the release. These have not yet been supplied for this project.

1. Inject independent production secrets from the platform's secret manager, with
   retained key versions and restricted service access. Use a dedicated database user.
2. Configure HTTPS, an exact allowed origin, secure cookies, and only actual trusted
   proxy addresses. Validate in a browser that login/refresh/logout work and that a
   foreign origin cannot refresh. Verify spoofed forwarding headers cannot change
   the client identity at the actual ingress. Do not set blanket proxy trust.
3. Run the container as non-root with a read-only root filesystem, dropped capabilities,
   `no-new-privileges`, resource limits and a termination grace period over 45 seconds.
4. Enable the outbox worker. Send an authorized verification email, confirm inbox receipt,
   verify the code, and inspect sanitized delivery/audit state. Provider acceptance alone
   does not prove receipt. Exercise worker termination with a pending job in staging;
   verify lease recovery and tolerate documented at-least-once delivery.
5. Route structured logs into the chosen monitoring service. Trigger a queue-age warning
   and a readiness failure in staging, and verify that the on-call destination receives
   both alerts. Restore normal service and confirm recovery alerts/state.
6. Restore a database backup into an isolated staging database using the provider's
   supported restore process. Verify identities, credentials, indexes and transactions;
   confirm the corresponding retained key rings can decrypt/verify restored records.
   Never test restoration over the live database.
7. Measure login/reset throughput and memory under expected peak load. Tune the Argon2,
   source/network, session and outbox limits using those measurements. Verify the ingress
   also bounds connections and requests before traffic reaches MongoDB.

## API and data rollout

Reset confirmation now requires `email`, `challengeId`, `otp`, and `newPassword`.
The 96-bit random challenge ID is sent only through email. Protocol-v1 reset challenges
are no longer accepted; queued legacy reset jobs are discarded. Existing users must
request a fresh reset email. Coordinate the client update before releasing the API.
Existing usable protocol-v2 reset challenges survive anonymous repeat requests.

Session listing returns at most 20 rows by default (maximum 50), with `data.nextCursor`.
Clients must follow the cursor for all sessions. `MAX_ACTIVE_SESSIONS` defaults to 20;
at capacity, users can revoke an existing session or reset their password to revoke all.
The new session index is created by startup storage initialization.

## Diagnostics

Error logs retain only allowlisted type/code/category and operation values, plus safe
request correlation. Raw error messages, stacks, SMTP responses, nested causes and
request bodies are not emitted. Categories distinguish DATABASE, EMAIL, NETWORK,
PROGRAMMING and APPLICATION errors; unknown values remain UNCLASSIFIED/UNKNOWN.
Alert on operational error rates and use request IDs to correlate sanitized events.
Do not enable raw third-party error serialization as a troubleshooting shortcut.

## Evidence status

Docker and the GitHub CLI are not installed in the current workspace environment.
The container smoke script is configured for CI but has not been executed here.
Live hosting/proxy, backup restoration and alert destinations have not been verified.
The previous SMTP test was accepted on port 465; inbox confirmation is still pending.
See `hardening-verification.md` for historical executed checks; new changes require
their own validation results before promotion.
