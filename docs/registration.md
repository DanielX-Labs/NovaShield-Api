# Registration and email verification

## Endpoints

All paths start with `/api/v1`. Send JSON; responses include a request ID.

- `POST /auth/register`: `{ "email": "...", "password": "...", "name": "optional" }`.
  Returns HTTP 202 and `data.challengeId`. Keep this ID for verification.
  Names are used only for password assessment; NovaShield does not store profiles.
- `POST /email/verify`: `{ "challengeId": "...", "otp": "123456" }`.
  Returns HTTP 200 when the pending account becomes verified and ACTIVE.
- `POST /email/resend`: `{ "email": "..." }`.
  Wait at least `OTP_RESEND_COOLDOWN_SECONDS` before requesting another code.
  Use the new challenge ID with the new email's code.

Registration and resend return the same HTTP 202 shape for ineligible addresses.
A 202 is not proof that an email was sent. Duplicate registration does not replace
credentials. Ineligible requests return an inert challenge ID.

## Persistence and failure handling

MongoDB must support replica-set transactions. Startup prepares collections and
adds the required indexes without dropping existing indexes.

Registration atomically creates AuthUser, Credential, PasswordHistory,
OtpChallenge, and AUTH_REGISTERED. SMTP runs after commit so transaction retries
cannot send duplicate emails. A failed send leaves the identity pending,
invalidates the challenge, records AUTH_EMAIL_DELIVERY_FAILURE, and returns 503.
The caller can resend after the cooldown. A process crash between commit and SMTP
can also leave a pending account; resend recovers it. Durable email delivery via
an outbox is not part of this milestone.

Successful provider acceptance records AUTH_EMAIL_OTP_SENT or
AUTH_EMAIL_OTP_RESENT. It does not prove inbox delivery. Successful verification
consumes outstanding verification challenges, activates only a pending identity,
and records AUTH_EMAIL_VERIFIED in one transaction.

Only Argon2id hashes and challenge-bound HMACs are stored. Audit events accept
only selected context; raw bodies, passwords, OTPs, email addresses and raw IPs
are not copied into event metadata.

## Abuse limits

MongoDB-backed counters enforce fixed 15-minute windows across API processes:

- Registration: 10 requests per IP.
- Resend: 10 requests per IP.
- Registration and resend combined: 5 requests per normalized email.
- Verification: 50 requests per IP, plus the configured per-challenge attempt cap.

HTTP 429 includes Retry-After. Counters store HMAC identifiers and have TTL cleanup.
OTP expiry and attempt limits are checked explicitly, independently of cleanup.
Proxy trust is disabled; configure trusted proxies deliberately before deploying
behind a reverse proxy so IP limits apply to actual clients.

## Verification

`npm run typecheck`, `npm test`, and `npm run build` are the standard checks.
Integration tests normally start an ephemeral local MongoDB replica set; the
first run may download a MongoDB binary. They mock SMTP and HIBP only.

If the binary download is impractical, explicitly run
`node scripts/test-with-configured-db.cjs`. This runs the full suite against a
random `ns_it_*` database on the configured MongoDB server and drops only that
test database afterward. It requires permission to create and drop test databases.
The normal test command does not load the private database credentials.

A live inbox check must use an address controlled by the tester. Registration
creates a persistent test identity; it is not automatically deleted. Do not
place real passwords or OTPs in committed fixtures, logs, or screenshots.

Registration does not automatically create a session. Follow it with
[login](login.md) and the [session lifecycle](session-lifecycle.md).
