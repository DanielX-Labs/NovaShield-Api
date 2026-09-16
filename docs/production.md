# Production hardening and operations

See [hardening verification](hardening-verification.md) for executed checks and remaining external gates.
Use the [deployment release gate](deployment-release.md) for the current API changes,
container smoke checks and infrastructure validation that must precede promotion.

## Implemented safeguards

- Atomic MongoDB admission reservations cover each IP and account/IP pair before password work.
- Account-wide failures cause bounded delay and risk signals, never an account-wide refusal.
- Password work has a per-process concurrency cap and no unbounded queue.
- Registration and reset responses do not depend on SMTP results; email jobs commit with domain writes.
- AES-256-GCM protects outbox recipients and OTPs at rest with a separate versioned key.
- Leased workers retry delivery; expired/replaced OTP jobs are discarded and completed ciphertext removed.
- Password hashes and JWT signing support retained keys during rotation.
- Successful login upgrades outdated password hashes inside its session transaction.
- Readiness pings MongoDB with a timeout and fails during shutdown.
- Bounded maintenance batches clean expired authentication records and old audit events.
- Lint, typecheck, tests, dependency audit and container build are defined in CI.

## Email outbox semantics

Set `OUTBOX_WORKER_ENABLED=true` after configuring the intended sender and SMTP credentials.
Every production instance runs the leased worker; multiple instances coordinate through MongoDB.
`OUTBOX_ENCRYPTION_KEY` must be a random 32-byte key, encoded as 64 hexadecimal characters.
Keep it separately from the database, alongside your other managed runtime secrets.

Delivery is **at least once**. A crash after SMTP acceptance but before marking a job SENT can
send the same message again. SMTP does not offer a transactional exactly-once guarantee.
The duplicate OTP remains bound to the same challenge; consuming the challenge is still atomic.
Workers check challenge state before delivery, but an email already being sent can race with
resend or verification. Superseded codes remain unusable.

Failure retries use capped exponential backoff until the job expires. Password-change notices
expire after seven days; OTP jobs expire with their challenge. Monitor PENDING job count, oldest
job age and first-failure audit events. Alert on delivery failures and on jobs reaching EXPIRED.
Do not interpret HTTP 202 or provider acceptance as proof of inbox receipt.

Registration can still have ordinary database timing differences; it does not promise perfectly
identical timing. SMTP outages no longer expose eligibility through status or provider latency.

## Abuse policy and resource budgets

`AUTH_ACCOUNT_FAILURE_LIMIT` now limits reservations for an **account/IP pair**, rather than
locking an email across all sources. `AUTH_IP_FAILURE_LIMIT` caps total source reservations.
Transactions reserve both or neither; failures keep reservations until the fixed window ends.
Successful login refunds its reservations atomically. Infrastructure failures attempt a refund;
if storage is unavailable, the conservative reservation expires naturally. Risk assessment still
uses rolling completed attempts. Window-boundary bursts remain possible with fixed windows.

A distributed attacker cannot be perfectly distinguished from legitimate users without another
proof of identity. This design avoids globally locking the victim's account; account-wide signals
slow attempts while source limits and `AUTH_HASH_CONCURRENCY` bound work. Size instance limits
and the load balancer's request/concurrency limits from measurements before deployment.

## Secret rotation

### Password peppers

Unversioned Argon2 records use the existing `AUTH_PEPPER`. Keep that secret unchanged while
legacy credentials or history exist; OTP HMACs also use it. New stored credentials use
`ns1:<pepper-id>:<argon2-encoded-hash>`. The enclosed Argon2 hash retains its random salt.

1. Add a random secret to `PASSWORD_PEPPER_KEYS`, a JSON object keyed by a short ID.
2. Set `PASSWORD_PEPPER_ID` to that ID on all instances. Roll out retained keys first.
3. Successful login verifies with the stored ID and upgrades to the active ID/cost settings.
4. Keep old keys while Credential or PasswordHistory references them. Inactive users need a
   reset before their unavailable plaintext password can be rehashed. Do not remove keys merely
   because a deployment completed. Back up key rings independently of MongoDB and test recovery.

A rehash does not increment passwordVersion, create password history or revoke sessions because
it does not change the password. Actual password replacement still does all three.

### JWT signing

New tokens include `JWT_ACCESS_KEY_ID` as kid. On rotation, retain the previous secret under its
old ID in `JWT_PREVIOUS_KEYS`, then change the current ID and `JWT_ACCESS_SECRET`. Keep old keys
for at least the maximum token lifetime plus deployment overlap. Pre-kid tokens can use the
`legacy` entry during migration. Never reuse an ID for a different secret during overlap.

### Outbox encryption

Move the old `OUTBOX_ENCRYPTION_KEY` into `OUTBOX_PREVIOUS_KEYS` under its old `OUTBOX_KEY_ID`,
then set a new current ID and key. Retain old keys until no pending payload envelope references
them. Losing a key makes those messages unrecoverable; OTPs can be reissued, but notifications
must not silently be treated as delivered. The worker fails closed and retries unavailable keys.

## Retention

Maintenance removes batches of up to 500 expired Session, RefreshToken and OtpChallenge records
older than `AUTH_RECORD_RETENTION_DAYS` beyond absolute expiry (default seven days).
Refresh families use absolute expiry, so live replay evidence is retained. SecurityEvent retention
is `SECURITY_EVENT_RETENTION_DAYS` (default 90). Choose this with your operational/privacy policy.
AuthAttempt and completed outbox metadata have seven-day TTL indexes. TTL cleanup is approximate
and never substitutes for authorization expiry checks. Monitor database growth and cleanup lag.

## Deployment configuration

The Docker image runs as the non-root node user and includes production dependencies only.
Run it with a read-only root filesystem, dropped Linux capabilities, `no-new-privileges`, a memory
limit and runtime-injected secrets. The image does not include `.env`. Use HTTPS at the ingress,
`COOKIE_SECURE=true`, one exact HTTPS `EXPENSEHUB_ORIGIN`, and only the trusted proxy CIDRs for
your actual ingress in `TRUST_PROXY_CIDRS`. Leave proxy trust empty when no proxy is present.

Production startup rejects placeholder secrets, disabled breach enforcement, insecure cookies,
and a disabled worker. The supported mail adapter is currently Brevo SMTP with required TLS;
selecting the unimplemented SES adapter is rejected at startup rather than failing on first mail.

MongoDB must be a replica set with credentials scoped to this service database. Configure backups,
restore testing, encryption at rest, network access restrictions, alerting and secret-manager access
in the hosting environment. CI needs no production credentials and uses ephemeral local databases.

## Release gates outside this repository

Before deploying, the operator must verify the container build/runtime, actual HTTPS/proxy/cookie
behavior, live SMTP inbox delivery, worker recovery across process restarts, load/memory budgets,
backup restoration, and alerts. Apply infrastructure-specific settings only after the deployment
architecture is chosen. Repository checks cannot prove those external properties.
No deployment, production secret provisioning or ExpenseHub integration is performed by this milestone.

## Review follow-up: delivery and source budgets

IPv6 addresses are canonicalized; IPv4-mapped addresses share the IPv4 host identity.
Login also has a shared IPv6 /64 admission budget of 120 requests per 15 minutes.
Individual host/pair budgets remain in place. Successful HTTP logins refund the network
reservation. The larger shared budget reduces collateral throttling, but a busy shared
network can still reach it; measure before deployment. IPv4 addresses are not grouped.

Anonymous registration/resend requests no longer consume an email-wide request quota.
Source limits remain, and actual verification email issuance is limited transactionally
to five jobs per user per 15-minute window, plus the existing resend cooldown. Duplicate,
unknown, cooldown and delivery-budget cases retain generic responses. Issuance quotas
still balance mailbox flooding against availability; they cannot prove inbox ownership.

OUTBOX_CONCURRENCY (default 4, maximum 16) bounds simultaneous SMTP sends per process.
Busy lanes drain immediately; idle lanes poll once per second. Maintenance runs separately.
Each minute queue telemetry records pending count and oldest age without recipients or OTPs.
OUTBOX_ALERT_BACKLOG (100) and OUTBOX_ALERT_AGE_SECONDS (60) produce warning logs when
exceeded. Connect these warnings to your deployment alerting system. Shutdown stops new
claims and waits for in-flight sends. Email templates use the stored challenge's UTC expiry.

Audit cleanup uses the createdAt index explicitly. The integration suite verifies an
IXSCAN plan for its time-only bounded retention query.
