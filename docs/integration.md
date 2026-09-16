# Integrating NovaShield into an application

This guide describes the current API, plus the backend trust boundary that still
needs implementation. Resolve the registration findings in [the review](project-review.md)
before enabling public signup. ExpenseHub is not part of this repository.

## 1. Ownership and application structure

```text
Application browser screens ──HTTPS──> NovaShield API
          │                            │
          │                            ├── identity / credentials / sessions
          │                            └── email outbox / security events
          ▼
Application backend ──> profiles / subscriptions / business data
```

NovaShield runs without a frontend. Build these screens in the consuming application:
register, enter verification code, login, forgot/reset password, change password,
and manage sessions. A separate NovaShield dashboard is optional.

An application user should eventually have a unique `authUserId` pointing to the
verified NovaShield subject, plus application-owned fields such as name and preferences.
Do not accept a browser-supplied `authUserId` as authenticated identity. Derive it
from a token validated by the backend. The registration `name` field is used for
password assessment and is not persisted as a profile.

## 2. Configure the browser boundary

Example production addresses are `https://app.example.com` and
`https://auth.example.com`. Configure NovaShield:

```env
# Exact browser origin, without a path or trailing slash.
EXPENSEHUB_ORIGIN=https://app.example.com
COOKIE_SECURE=true
COOKIE_SAME_SITE=lax
```

Use `credentials: "include"` for browser login, refresh and logout so cookies are
accepted and sent. The refresh cookie is HttpOnly, host-only, and scoped to
`/api/v1/auth`; JavaScript does not read it. SameSite is based on site, not origin.
Unrelated frontend/API domains require `SameSite=None; Secure` and may still be
affected by browser third-party-cookie restrictions. Prefer a same-site deployment.
See [browser cookie semantics](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie).

Do not disable the origin middleware to solve a CORS problem. Configure the actual
browser origin. Server/native requests may omit Origin; Origin is a CSRF boundary,
not service authentication.

## 3. Current endpoint contract

All paths below start with `/api/v1`. Send `Content-Type: application/json` for JSON bodies.
Protected endpoints require `Authorization: Bearer <accessToken>`.

| Method and path | Input | Successful result |
| --- | --- | --- |
| POST `/auth/register` | `email`, `password`, optional `name` | 202; `data.challengeId` |
| POST `/email/resend` | `email` | 202; replacement `data.challengeId` |
| POST `/email/verify` | `challengeId`, six-digit string `otp` | 200; identity activated |
| POST `/auth/login` | `email`, `password` | 200; access token, user ID, session ID, expiry; refresh cookie |
| POST `/auth/refresh` | Refresh cookie; no JSON required | 200; new access token and rotated cookie |
| POST `/auth/logout` | Bearer token | 204; session revoked, cookie cleared |
| GET `/auth/sessions?limit=20&cursor=...` | Bearer token; optional query | 200; `data.sessions`, `data.nextCursor` |
| DELETE `/auth/sessions/:sessionId` | Bearer token | 204; owned session revoked |
| DELETE `/auth/sessions` | Bearer token | 204; all current sessions revoked |
| POST `/password/change` | Bearer token; `currentPassword`, `newPassword` | 200; sign in again |
| POST `/password/reset/request` | `email` | Generic 202; no challenge ID returned |
| POST `/password/reset/confirm` | `email`, emailed `challengeId`, `otp`, `newPassword` | 200; sign in again |

Registration/resend 202 does not prove eligibility or delivery. Keep the challenge
ID with its matching verification code. Reset challenge IDs come from the email,
not the request response. Password change/reset revoke sessions. Session pagination
is ordered by public session ID, not newest first; stop when `nextCursor` is null.

## 4. Browser login example

```js
// This module belongs in the consuming application's browser code.
const authBase = "https://auth.example.com/api/v1";
let accessToken = null;

export async function login(email, password) {
  // Let the browser handle the HttpOnly refresh cookie.
  const response = await fetch(`${authBase}/auth/login`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  const result = await response.json();

  // Expose a safe API message to the UI; never log credentials or tokens.
  if (!response.ok) {
    throw new Error(result.error?.message ?? "Sign-in failed.");
  }
  accessToken = result.data.accessToken;
  return { userId: result.data.userId, expiresIn: result.data.expiresIn };
}

export async function listSessions() {
  // This demonstrates a protected NovaShield endpoint, not application API trust.
  return fetch(`${authBase}/auth/sessions?limit=20`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    credentials: "include",
  });
}
```

Keep access tokens in memory; avoid localStorage and URLs. On a page reload, a
single refresh can restore authentication if the cookie remains valid. Handle 401
as reauthentication, 429 with backoff/Retry-After, and 503 as temporary unavailability.
Login may return 409 `ACTIVE_SESSION_LIMIT`; use an existing signed-in session to
revoke another session, or account recovery to revoke all.

Only one refresh may run per browser session at a time, including across tabs.
Coordinate tabs with a browser lock or a carefully designed backend-for-frontend.
Concurrent or retried consumption of the same refresh token is treated as replay
and revokes the session. A lost refresh response can therefore require login again;
do not blindly retry refresh or automatically replay non-idempotent application writes.
Logout needs a valid access token: refresh first if expired, then logout and clear
the in-memory token after server acknowledgement.

## 5. Application backend integration: required work

The current JWT uses HS256, issuer `novashield`, audience `expensehub-api`, and
claims `sub`, `sid`, `type`, `ver`. These are implementation details, not a complete
third-party integration protocol. There is no JWKS, token-introspection endpoint,
service-client authentication or signed identity webhook today.

Do not give the browser the signing key. Giving an independent application backend
the HS256 key also gives it the ability to mint identities. Signature-only validation
would additionally miss immediate revocation, disabled identities and password-version
changes: NovaShield's own middleware checks these against authoritative database state.

Before connecting a separate application backend, implement and test an explicit
trust boundary. One option is an authenticated internal introspection endpoint that
checks signature, expiry, issuer/audience, active identity, session and credential
version, then returns an allowlisted subject. Another is asymmetric signing with
public-key distribution plus an explicit revocation strategy. Neither is implemented
here. Do not improvise an introspection API by calling session listing, or grant the
application direct access to the NovaShield database.

After that boundary exists, the application backend can create/find its profile by
the verified `sub`, enforce its own roles and resource ownership, and store business
data. Authentication does not grant permission to another user's records.

## 6. Migrating an existing application

1. Back up application data and validate the new service in staging.
2. Implement backend trust and browser flows, including recovery and replay handling.
3. Choose a reviewed migration flow that proves ownership of the existing account.
   Do not automatically link users solely because a browser supplies the same email.
4. Add a unique `authUserId` and backfill through that verified migration flow.
5. Move application authorization to the verified NovaShield subject; test that
   revoked sessions cannot access application data.
6. Cut over a small cohort with monitoring and a rollback plan. Remove old password,
   OTP and token storage only after migration and recovery paths are verified.

Existing bcrypt hashes are not compatible with this service's Argon2id envelope.
This repository has no legacy-hash import adapter. Never ask users to send plaintext
passwords to an administrator or place migration credentials in logs.
