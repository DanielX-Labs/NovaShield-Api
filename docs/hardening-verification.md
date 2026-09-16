# Hardening verification — 2026-09-16

## Latest reset, diagnostics and session hardening

The complete local run passed **180 tests across 25 files**: 94 unit tests and
86 database integration/security tests. Typecheck, ESLint and the production
build also passed. The container smoke script passed syntax checking; it has
not been executed in Docker on this workstation.

Database tests used isolated local MongoDB replica sets. They cover reset
challenge binding, legacy challenge invalidation, issuance quotas, session
pagination and competing requests for the final active-session slot, alongside
the existing lifecycle, admission, refresh replay and outbox recovery tests.

An earlier remote run encountered DNS and connection failures and is not counted
as successful verification. The complete passing run used the cached MongoDB
8.2.6 executable extracted from a complete entry in a partial archive, with
entry size and CRC verified. This is not a publisher-signature or full archive
checksum verification. To reproduce with that local test binary in PowerShell:

```powershell
$env:MONGOMS_SYSTEM_BINARY = (Resolve-Path 'node_modules/.cache/mongodb-memory-server/mongod-verified-8.2.6.exe').Path
npm test -- --maxWorkers=2
```

Current-revision CI execution, Docker runtime verification, deployed proxy and
cookie behavior, backup restoration, alert delivery and recipient confirmation
of inbox delivery remain release gates. See [deployment release checks](deployment-release.md).

## Earlier hardening milestone

These checks used synthetic data in isolated `ns_it_*` databases on the configured
MongoDB replica set. Application collections were not used or cleared. SMTP and HIBP
were mocked in automated tests; the authorized SMTP delivery check was separate.

| Check | Result |
| --- | --- |
| TypeScript, ESLint, production build | Passed |
| Offline unit tests | 93 passed |
| Registration integration | 17 passed |
| Password lifecycle integration | 16 passed |
| Session integration | 15 passed |
| Authentication abuse security | 12 passed |
| Outbox/retention integration | 7 passed |
| IPv6 network admission integration | 1 passed |
| Login integration | 12 passed on final rerun |
| Live SMTP provider acceptance | Passed using TLS on port 465 |
| Inbox receipt | Awaiting recipient confirmation |

The outbox checks verify competing claims, abandoned lease recovery, retries, expiration,
transaction rollback and encrypted persistence. Worker unit tests verify bounded concurrent
lanes, immediate draining, shutdown waiting and queue threshold telemetry. The retention
explain-plan assertion confirms IXSCAN rather than COLLSCAN.

Initial database execution exposed stale test fixtures: re-exported import bindings were
undefined, the hash assertion omitted the pepper envelope, and a limiter assertion assumed
one budget rather than the new three budgets. Those tests were corrected without weakening
the security checks. Remote setup/cleanup timeouts were increased, and independent collection
cleanup runs concurrently. Intermittent Atlas DNS/connection failures remain environmental.

Port 587 timed out; ports 465 and 2525 were reachable. An authorized diagnostic email was
accepted on TLS port 465, and the private development `.env` now selects that port. Provider
acceptance is not proof of inbox delivery. The outbox worker remains explicitly opt-in in
development; production requires it. Docker/runtime deployment checks remain separate gates.

All 80 database integration/security tests passed across completed suite runs and targeted reruns, alongside 93 unit tests. The initial combined run exposed fixture defects and connectivity interruptions; the corrected suites subsequently passed.

