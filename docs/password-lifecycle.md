# Password lifecycle security

All paths below start with `/api/v1`. Send JSON. Responses include a request ID
and `Cache-Control: no-store`.

## Endpoints

| Method and path | Authentication | JSON body |
| --- | --- | --- |
| `POST /password/change` | Bearer access token | `currentPassword`, `newPassword` |
| `POST /password/reset/request` | None | `email` |
| `POST /password/reset/confirm` | Emailed challenge ID and OTP | `email`, `challengeId`, `otp`, `newPassword` |

Change and confirmation return 200 and clear the refresh cookie. Every existing
session is revoked, including the requesting session. Sign in again with the new
password. Reset requests return the same 202 response for eligible, unknown,
unavailable and cooldown-limited accounts, including SMTP delivery failure.
A 202 does not prove that email was delivered. Disallowed browser origins fail 403.

## Atomic credential replacement

Password changes verify the current password and the authenticated session.
Reset confirmation first verifies knowledge of a valid reset OTP without consuming
it. Only then can policy, breach screening and account-specific reuse checks run.
A policy rejection leaves the OTP unconsumed; each submission still uses one of
its attempt slots. Never send the old password to the reset endpoint.

Expensive password checks and hashing run outside transaction retries. The commit
compares the credential version and hash with the verified snapshot. In one MongoDB
transaction it replaces the credential, increments its version, updates timestamps,
archives the old hash, consumes outstanding challenges, revokes all sessions and
refresh tokens, and records the security event. Any write failure rolls this back.
Concurrent changes cannot overwrite a newer credential. Concurrent reset submissions
can commit only once; reset codes are bound to the issuing credential version.

For A -> B -> C, history contains A and B, while Credential contains C. The newest
`PASSWORD_HISTORY_LIMIT` previous hashes are retained. Legacy history entries that
already contain the outgoing hash are deduplicated during replacement.
Current-password reuse is checked separately, including when history is empty.

## OTP and abuse protection

Reset codes are six-digit cryptographically generated values. MongoDB stores only
challenge-bound HMAC hashes. Verification enforces purpose, target, credential
version, expiry, single use and a persisted attempt budget. Confirmation also requires
the unpredictable 96-bit challenge ID included only in the email, not the request
response. Wrong locators cannot consume another challenge's attempts. Existing usable
reset challenges are preserved when strangers request another code. New issuance
replaces expired/exhausted challenges and shares the configured resend cooldown.
Password replacement invalidates all outstanding challenges for the identity.

Source request limits protect HTTP work. A separate transactional per-user budget
counts actual reset emails, with the same generic 202 response when exhausted.
There is no email-wide request or confirmation counter. Reset challenges created
before protocol version 2 are rejected and their queued emails discarded; request a
new reset email after rollout. Clients must collect both values from the email.

Configuration defaults:

- `PASSWORD_RESET_OTP_TTL_MINUTES=10`
- `PASSWORD_RESET_MAX_ATTEMPTS=5`
- `PASSWORD_RESET_REQUEST_WINDOW_MINUTES=15`
- `PASSWORD_RESET_REQUEST_LIMIT=5`

Request limits apply independently to IP and normalized email through shared
MongoDB counters. Confirmation permits 10 requests per IP and email per 15 minutes;
the smaller per-challenge attempt budget still applies. Authenticated changes have
an IP limit of 10 requests per 15 minutes. The login [abuse engine](auth-abuse.md) now provides progressive account throttling;
password endpoints retain their own budgets. Permanent account lockouts are not used.

## Email and failure handling

Reset codes and password-change notices are encrypted and queued in the same MongoDB
transaction as their security state. The worker delivers and retries after commit.
Delivery failure does not change the successful HTTP response. See
[production operations](production.md) for outbox guarantees and retention.

## Verification

Run `npm run typecheck`, `npm test`, and `npm run build`. The integration suite
uses real MongoDB transactions with mocked SMTP and HIBP. The explicit
`node scripts/test-with-configured-db.cjs` runner uses and removes an isolated test
database on the configured MongoDB server; see [registration](registration.md).

Tests cover replacement, versioning, history, old-token rejection, OTP replay,
attempt exhaustion, expiry, purpose binding, concurrent confirmation, transactional
rollback and email failures. Real inbox delivery still requires a configured Brevo
SMTP key and a verified development account; mocked tests do not prove delivery.
