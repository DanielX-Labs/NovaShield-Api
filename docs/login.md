# Login and session foundation

## HTTP contract

`POST /api/v1/auth/login` accepts JSON containing `email` and `password`.
Email is trimmed and lowercased; password bytes are preserved.

A successful response is HTTP 200 with `data.userId`, `data.accessToken`,
`data.expiresIn` (seconds), and `data.sessionId`. The opaque refresh token is
delivered only in a host-only HttpOnly cookie scoped to `/api/v1/auth`.
Token responses have `Cache-Control: no-store`.

Wrong passwords, unknown email addresses, and missing credentials return
`401 INVALID_CREDENTIALS`. Correct passwords for unavailable or unverified
accounts return `403 ACCOUNT_NOT_AVAILABLE`. Failed persistence returns
`503 AUTH_UNAVAILABLE`, without issuing a cookie or partial session.

Browser origins must match `EXPENSEHUB_ORIGIN`. Native API clients can omit
Origin. Proxy trust remains disabled until trusted proxy topology is configured.

## Tokens and storage

Access tokens use HS256, issuer `novashield`, audience `expensehub-api`, and
`ACCESS_TOKEN_TTL_MINUTES`. Verification checks signature, expiration, token
type, subject, session ID, issue time, and positive integer credential version.
`verifyAccessToken` validates the token only; future authenticated middleware
must also validate current account, credential, and session state.

Refresh tokens use `ObjectId.random-secret` with 48 random bytes. MongoDB stores
only SHA-256 of the complete token. Each login starts a new token family. Session
and refresh-token expiry are aligned to `REFRESH_TOKEN_TTL_DAYS`.

Login state, Session, RefreshToken, and AUTH_LOGIN_SUCCESS commit in one MongoDB
transaction. Wrong-password increments and failure audit events also commit
together. No external service is called during login. Dummy Argon2 verification
runs for unknown users and missing credentials and is initialized before listen.

Network correlation uses the dedicated `IP_HASH_SECRET`; password pepper is not
used for IP hashing. Rotating this key changes IP correlation and rate-limit keys.

## Configuration

`ACCESS_TOKEN_TTL` and JWT refresh signing are retired. Only access-token JWTs
require `JWT_ACCESS_SECRET`; opaque refresh tokens need no JWT signing secret.

Use `COOKIE_SECURE=false` with `COOKIE_SAME_SITE=lax` only for local HTTP.
Production and SameSite=None require Secure cookies. The cookie has no Domain
attribute; set and clear helpers use identical path and security settings.

Login uses shared MongoDB IP counters with `LOGIN_IP_LIMIT` attempts per
`LOGIN_WINDOW_MINUTES`. In-flight attempts count immediately; successful
responses release their reservation. HTTP 429 includes Retry-After. Counter
storage failures fail closed. `LOGIN_ACCOUNT_LIMIT` is reserved for the next
abuse-service milestone; this stage does not implement account-keyed throttling,
progressive delays, or permanent lockouts.

## Verification and next milestone

The integration suite verifies registration through activation and login, real
Argon2 verification, cookie delivery, MongoDB hash-only storage, status rejection,
dummy verification, rate limits, concurrent failures, and transaction rollback.
SMTP and HIBP are mocked; MongoDB operations are real and use an isolated test DB.
See [registration](registration.md) for standard and configured-database runners.

A live development login still requires a genuinely verified account and its
password. Tests create identities only inside their isolated database.

Refresh rotation, reuse detection, logout, session management, and authenticated
middleware are the next protocol milestone. No refresh or logout route is exposed
yet; the cookie-clear helper is prepared for those routes.
