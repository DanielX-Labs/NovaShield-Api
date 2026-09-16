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

Registration atomically creates AuthUser, Credential, OtpChallenge, an encrypted
EmailOutbox job, and AUTH_REGISTERED. Password history starts empty. SMTP never runs
in the HTTP request. Failed delivery is retried by the worker and does not change
registration's public HTTP 202 response. See [production operations](production.md)
for outbox leasing, expiry, duplicate-delivery semantics and key management.

Successful provider acceptance records AUTH_EMAIL_OTP_SENT or
AUTH_EMAIL_OTP_RESENT. It does not prove inbox delivery. Successful verification
consumes outstanding verification challenges, activates only a pending identity,
and records AUTH_EMAIL_VERIFIED in one transaction.

Credential records store versioned Argon2id envelopes; challenge records store HMACs.
Outbox jobs temporarily hold encrypted recipients and codes under a separate key. Audit events accept
only selected context; raw bodies, passwords, OTPs, email addresses and raw IPs
are not copied into event metadata.

## Abuse limits

MongoDB-backed counters enforce fixed 15-minute windows across API processes:

- Registration: 10 requests per IP.
- Resend: 10 requests per IP.
- Verification delivery: 5 actual email jobs per user per window, reserved in the
  issuance transaction. Anonymous and duplicate requests do not consume this quota;
  unavailable issuance still returns the generic response.
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
