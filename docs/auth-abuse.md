# Authentication abuse defense

Login now applies two layers before Argon2 verification: the existing shared
HTTP/IP request limiter, then a rolling assessment of completed authentication
attempts. Unknown identities receive dummy Argon2 verification and the same public
credential failure as incorrect passwords.

## Development policy

| Setting | Default | Purpose |
| --- | --- | --- |
| `AUTH_FAILURE_WINDOW_MINUTES` | 15 | Rolling window of failures |
| `AUTH_ACCOUNT_FAILURE_LIMIT` | 8 | Temporary refusal per protected email identity |
| `AUTH_IP_FAILURE_LIMIT` | 30 | Temporary refusal per protected IP |
| `AUTH_PROGRESSIVE_DELAY_AFTER` | 3 | First delayed login after this many failures |
| `AUTH_PROGRESSIVE_DELAY_BASE_MS` | 500 | Initial delay |
| `AUTH_PROGRESSIVE_DELAY_MAX_MS` | 5000 | Delay cap |
| `AUTH_SPRAY_ACCOUNT_THRESHOLD` | 8 | Distinct failed identities indicating spraying |
| `AUTH_SUSPICIOUS_SCORE_THRESHOLD` | 50 | Minimum score for a suspicious event |

Delays grow as 500, 1000, 2000, 4000, then 5000 milliseconds with the default policy.
The event loop remains available during the delay. Requests already over a refusal
threshold return 429 immediately without holding a timer or invoking Argon2.
Database failure fails closed with a generic 503.

## Temporary refusal and recovery

Throttling never changes `AuthUser.status` or permanently locks an identity.
Only `FAILURE` records influence the rolling counters. `BLOCKED` and `SUCCESS`
records do not increase those counters. Blocked requests therefore cannot extend
the window indefinitely. Old failures stop influencing the assessment based on
an explicit timestamp query; recovery does not depend on MongoDB TTL deletion.

Account-level refusal still has an availability tradeoff: an attacker can cause a
legitimate account to receive 429 until enough failures age out. The correct
password does not bypass that refusal. These development thresholds require tuning.
Successful login resets the existing user failure counter but preserves attempt
telemetry, since failures followed by success can be an important risk signal.

The assessment uses completed attempts, not an atomic admission reservation.
Concurrent requests may pass the same pre-verification snapshot and exceed a
failure threshold before their outcomes are recorded. The outer IP limiter counts
in-flight requests immediately, but distributed attempts can still exceed the
account threshold within a burst. Exact distributed admission limits remain a
production-hardening consideration; no permanent lockout is used as a workaround.

## Signals and storage

`AuthAttempt` stores `emailHash`, optional `ipHash`/`userId`, outcome, reason and
creation time. Email normalization uses NFKC, trimming and lowercase before HMAC.
An `auth-email:` prefix separates this use from IP hashing with `IP_HASH_SECRET`.
No plaintext email, password, OTP, token or request body is stored in attempts.
TTL cleanup retains these records for approximately seven days. Security events
have their own retention policy; the attempt TTL does not remove them.

Scores combine repeated account failures, account/IP refusal thresholds, distinct
failed accounts from one IP, and multi-account failure patterns. Scores cap at 100.
These are indicators, not proof of spraying, credential stuffing or compromise.
No subnet grouping, device fingerprinting or geolocation is implemented here.

`AUTH_SUSPICIOUS_LOGIN` and `AUTH_RATE_LIMITED` events use allowlisted assessment
metadata: score, reason codes, account failure count, IP failure count and distinct
account count. Successful-login events retain the assessment too, allowing failures
followed by success to be investigated. Event metadata never copies request bodies.
Attempts and corresponding login outcomes participate in database transactions;
a successful session cannot commit if its success telemetry cannot be written.

## Verification

Standard commands:

```powershell
npm run typecheck
npm test
npm run test:security
npm run build
```

Tests use isolated MongoDB replica-set databases and local synthetic credentials.
They never target a deployed authentication system or send real email. If downloading
the memory-server binary is impractical, the explicitly configured database runner
supports the same complete and security-only suites:

```powershell
node scripts/test-with-configured-db.cjs
node scripts/test-with-configured-db.cjs tests/security
```

The runner creates a random `ns_it_*` database per suite and removes only those
databases afterward. Unit tests cover exponential delay boundaries, identifier
normalization and timer behavior. Security tests cover generic failures, account
and IP refusal, rolling recovery, spraying indicators, successful-login cleanup,
concurrent failure recording and transaction failures.

Express proxy trust remains disabled for local development. Configure the actual
trusted proxy boundary before deployment rather than trusting arbitrary forwarded
headers. `LOGIN_ACCOUNT_LIMIT` is a legacy unused setting; the abuse engine uses
`AUTH_ACCOUNT_FAILURE_LIMIT`. Production hardening is the next milestone.
