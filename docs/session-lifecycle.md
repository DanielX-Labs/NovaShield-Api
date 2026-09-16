# Session lifecycle

## Endpoints

All routes are under `/api/v1` and return non-cacheable responses.

| Method and route | Authentication | Result |
| --- | --- | --- |
| POST /auth/refresh | Refresh cookie | Access token JSON and replacement HttpOnly cookie |
| POST /auth/logout | Bearer access token | Current session revoked; cookie cleared; HTTP 204 |
| GET /auth/sessions | Bearer access token | Owned, active, unexpired sessions and current marker |
| DELETE /auth/sessions/:sessionId | Bearer access token | Owned session revoked; HTTP 204 |
| DELETE /auth/sessions | Bearer access token | All owned sessions revoked; cookie cleared; HTTP 204 |

Refresh takes no request body. Browsers must send cookies and an allowed Origin.
Native API clients can omit Origin. Mutation routes reject untrusted browser
origins; CORS alone is not treated as CSRF protection.

Session listing accepts `?limit=20&cursor=<sessionId>` (limit 1–50, default 20).
The response retains `data.sessions` and adds `data.nextCursor`, or null on the last
page. Follow that cursor unchanged. Ordering uses immutable public session IDs;
concurrent additions/revocations are not a snapshot. Internal IDs and IP hashes remain
excluded. Invalid or unexpected query parameters return 400.

`MAX_ACTIVE_SESSIONS=20` bounds active unexpired sessions per identity (configurable
from 1 to 100). A transactional identity write serializes concurrent admission.
At capacity, login returns `409 ACTIVE_SESSION_LIMIT` without issuing credentials.
Revoke an existing session to free a slot; password reset also revokes all sessions.

## Rotation and replay

The adapter parses the exact opaque-token format, explicitly selects its hidden
digest and state fields, and compares the SHA-256 digest in constant time before
changing any records. Knowing a token ID without its secret cannot revoke a session.

One MongoDB transaction conditionally consumes R1, creates R2 in the same family,
updates session activity, and records AUTH_REFRESH_ROTATED. The original absolute
expiry is preserved in both the replacement record and the browser cookie.

Reusing a valid consumed R1 revokes the session and all its refresh tokens,
including R2, and records AUTH_REFRESH_REUSED at HIGH severity. This revocation
commits before the 401 response is raised. Invalid credentials clear the cookie;
temporary database failures return 503 and retain it for retry.

Clients must serialize refresh requests. Two simultaneous uses of R1 yield one
successful rotation and one replay rejection; replay invalidates even the token
returned to the winning request. There is deliberately no replay grace window.

## Authentication and revocation

Authentication validates JWT signature and claims, then reads current user,
credential, and owned session state. A revoked or expired session stops an
otherwise unexpired access JWT from working on subsequent requests.

Sessions also store the credential version present at login. Both access and
refresh reject a version mismatch, so an old refresh token cannot obtain a JWT
with a newly changed credential version. Sessions created before this field was
introduced require login again; no version is guessed for existing sessions.

Logout and manual revocation update session and refresh records with their audit
event in one transaction. Session writes conflict with concurrent rotation, so
a replacement cannot remain active after revocation. A new login starts a new
session and is separate from a revoke-all operation.

Users can revoke only sessions owned by their authenticated user ID. Revoking
another device leaves the current browser cookie alone; revoking the current
session or all sessions clears it. Already-running protected requests cannot be
retroactively canceled; sensitive future writes must check state in their own
transaction.

## Checks and limits

Refresh and session management each use shared MongoDB counters allowing 60
requests per IP per five-minute fixed window. Missing or invalid bearer tokens
return 401. Database outages return 503 and never grant access.

The integration suite covers rotation, replay, wrong secrets, concurrent refresh,
cookie handling, cross-user authorization, logout, revoke-all, credential changes,
and rollback of failed writes. It uses real MongoDB transactions with SMTP and
HIBP mocked; passing it does not demonstrate delivery to a real inbox.

Run `npm run typecheck`, `npm test`, and `npm run build`. If the local MongoDB
binary is unavailable, `node scripts/test-with-configured-db.cjs` runs the full
suite against a uniquely named temporary database on the configured replica set.
Only that test database is dropped afterward.
