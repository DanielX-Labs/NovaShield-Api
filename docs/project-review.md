# NovaShield project review — 2026-09-16

## Assessment

**Overall: 7.5/10 as an authentication engineering project. Production release
readiness: 5/10.** These are qualitative ratings, not a security certification.
The implementation is substantial and well tested, but registration ownership and
live deployment evidence prevent a production approval. A separate application's
backend trust boundary also remains unfinished.

This review covered API routing/validation, identity and password workflows,
session rotation/revocation, MongoDB transactions and indexes, admission/risk
signals, email leasing/encryption, logging, configuration, tests, Docker, CI and
operational documentation. It is a source review with local automated validation,
not an independent penetration test or cloud infrastructure audit. No real email
was sent, production database accessed or deployment performed in this review.

## Findings, ordered by priority

### 1. High — verification can activate a password chosen by a different registrant

Evidence: [duplicate registration branch](../src/services/auth/registration.service.ts),
especially the existing-user return around line 101, `resend()` around line 129,
and the activation update around line 195.

An initial registrant can create a pending account with another person's email
and a password they know. A later registration by the mailbox owner returns the
generic response without replacing that credential. If the owner then requests a
resend and verifies their emailed code, the existing identity becomes ACTIVE with
the first registrant's password still installed. The first registrant can then log
in. This requires the mailbox owner's later verification; it is not an OTP bypass.

The current tests assert that duplicate registration preserves the first hash,
but do not cover the full two-registrant activation scenario. This finding follows
from the source flow; a dedicated adversarial regression is still needed.

**Release requirement:** bind activation to the credential setup authorized by
the verified mailbox owner. For example, finish password setup only after proving
mailbox ownership, using a narrowly scoped setup proof. Do not fix this by blindly
overwriting pending credentials on anonymous registration. Add a test proving that
the earlier registrant's password cannot authenticate after the owner's activation.

### 2. Medium — anonymous resend still invalidates the owner's usable verification code

Evidence: `resend()` in
[registration.service.ts](../src/services/auth/registration.service.ts) calls
`createChallenge()`, which calls
[createOtpChallenge](../src/services/otp/otpChallenge.service.ts) and consumes all
previous unused challenges. The new challenge ID is returned to the requesting
client, while [verification email](../src/services/email/email.service.ts) contains
the OTP but not that ID.

After the resend cooldown, someone knowing a pending user's address can trigger a
replacement. The owner's prior ID/code pair stops working; the new email code is
not usable with the ID still in their browser. Repetition can also spend the actual
issuance budget. The reset flow already preserves usable challenges, but verification
does not. HTTP response consistency alone does not prevent this disruption.

**Improve:** redesign resend with the ownership fix: preserve usable verification
proofs or bind replacement to the initiating flow, while keeping issuance and
attempt limits. Test two independent clients, including retries during cooldown.

### 3. Medium — separate application integration has no complete verification protocol

Evidence: [accessToken.service.ts](../src/services/session/accessToken.service.ts)
uses HS256 and the fixed `expensehub-api` audience. The only complete authoritative
check is the internal [authenticate middleware](../src/middleware/authenticate.middleware.ts),
which queries identity, session and credential state. Routes expose no dedicated
authenticated introspection API or JWKS/service-client protocol.

This is an integration gap, not a bypass in existing NovaShield protected routes.
Giving an independent backend the signing secret also gives it signing authority;
checking only the signature would lose immediate session revocation semantics.

**Before integration:** implement an authenticated backend verification boundary,
or asymmetric token verification with a defined revocation strategy. Test identity
mapping, wrong audience, expired/revoked sessions, disabled accounts and credential
changes end to end in the consuming application. See [integration guide](integration.md).

### 4. Medium release gate — production behavior remains unverified

CI configuration and a container smoke script exist, but successful execution of
the exact current revision in CI/Docker is not established here. Docker and GitHub
CLI are unavailable on this workstation. HTTPS ingress/cookies, backup restoration,
alert delivery and real inbox receipt remain unverified. These are evidence gaps,
not newly demonstrated application defects.

Follow [deployment walkthrough](deploy.md) and [release gate](deployment-release.md).
Keep public production signup closed until the registration ownership fix passes.

## What improved and is verified

- Reset requests separate source admission from actual issuance; confirmation uses
  a random emailed challenge ID and challenge-specific attempts.
- Session lists are bounded and paginated. A transactional identity write serializes
  admission at the active-session cap.
- Error logs retain allowlisted categories/codes/operations without raw third-party
  error messages, request bodies or token material.
- Login admission reserves MongoDB source/pair budgets before password verification.
- Refresh rotation stores only token hashes and commits reuse revocation before
  returning an error. Authentication checks authoritative session state.
- Password replacement, history, session revocation and notification enqueue commit
  together. Outbox payloads are encrypted; leased concurrent workers recover jobs.
- Retention has an audit time index; readiness checks the live database; production
  configuration enforces key safeguards. CI covers multiple independent checks.

## Fresh validation in this review

| Check | Result |
| --- | --- |
| TypeScript | Passed |
| ESLint | Passed |
| Production build | Passed |
| Complete Vitest run | 180 passed, 25 files, including database/security suites |
| Dependency audit | 0 reported vulnerabilities |
| Docker / live CI / deployed infrastructure | Not executed or verified |

Vitest initially hit sandbox `spawn EPERM`; the approved rerun launched isolated
local MongoDB replica sets and passed. It used the cached MongoDB executable
described in [hardening verification](hardening-verification.md). SMTP and HIBP
were mocked. A green test suite proves the tested cases, not the missing ownership
scenario or the absence of all vulnerabilities. Audit results are a point-in-time
dependency database check, not a code security review.

## Rating breakdown

| Area | Rating | Basis |
| --- | --- | --- |
| Structure and separation of responsibilities | 8/10 | Clear services/models, explicit boundaries; some dense formatting and duplicated transaction/error patterns |
| Password and session foundations | 8/10 | Strong storage and transaction design, replay handling and key rotation |
| Registration ownership | 4/10 | Activation can preserve another registrant's known credential |
| Automated verification | 8/10 | Broad 180-test suite; missing adversarial registration flow and real browser/ingress checks |
| Operations and deployability | 6/10 | Useful CI/container/outbox setup; external release gates still open |

## Recommended order

1. Fix and regression-test registration ownership and resend behavior.
2. Execute CI/container and staging release gates on the exact corrected revision.
3. Implement and test the consuming backend's authentication trust boundary.
4. Integrate application screens and migrate identities in controlled cohorts.

A dedicated NovaShield frontend is optional. The consuming application needs user
screens, but that UI does not solve the backend trust or ownership findings.
