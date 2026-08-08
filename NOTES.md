# Security Hardening CTF Notes

## Objective

Identify and remediate the 40 independently scored platform vulnerabilities in
Security Shepherd, map each confirmed issue to the OWASP Top 10 (2021), and
submit the fixes in a pull request targeting `OWASP-CTF/SecurityShepherd:dc34-ctf`.

The deliverable is secure code with regression coverage; this is not a
flag-hunting exercise.

## Scope

- Authorized repository: `OWASP-CTF/SecurityShepherd`
- Authorized base branch: `dc34-ctf`
- Local application and containers built from that branch
- GitHub Actions scoring workflow attached to pull requests against that branch

Explicitly excluded from remediation by the repository instructions:

- `src/main/java/servlets/module/lesson/`
- `src/main/java/servlets/module/challenge/`
- `mobile/MobileShepherd/`
- Deliberately vulnerable challenge and lesson web content

## Provided Artifacts

- Java 8 servlet application built as a Maven WAR
- Tomcat, MariaDB, and MongoDB Docker environment
- Unit and integration tests
- Hidden GitHub Actions scoring rubric invoked by
  `.github/workflows/score.yml`
- No expected flag format; passing challenge tests are the score

## Observations

- The CTF branch's newest commit adds only the scoring workflow and disables
  inherited workflows; it does not expose a simple injected-vulnerability diff.
- Upstream is public and the connected GitHub identity is `D-Sound2000`.
- The connected account has pull-only access to the upstream repository.
- Local GitHub CLI is installed but is not authenticated.
- No pre-existing `NOTES.md` was present.
- The unmodified project passes its unit suite in the official Java 17 Maven
  container: 164 tests, 0 failures, 0 errors, 2 skipped.
- The first hardening batch passes the expanded full suite: 197 tests, 0
  failures, 0 errors, 2 skipped. Spotless also passes after formatting.
- The second hardening batch passes the expanded full suite: 211 tests, 0
  failures, 0 errors, 2 skipped. Spotless also passes after formatting.
- The application has only an installation-gating filter mapped globally; it
  does not have a central platform-security filter.
- Administrative servlets consistently perform role and request-token checks,
  while public/API routes have uneven unauthenticated-request handling.

## Confirmed Vulnerability Candidates

These are platform findings supported directly by source behavior. Hidden-score
coverage is not yet known, so each fix will receive an explicit regression test.

1. `Validate.getToken` and `Validate.getSessionId` dereference a null cookie
   array, turning ordinary unauthenticated requests without a Cookie header into
   server errors. OWASP A05:2021 Security Misconfiguration.
2. `ChangePassword` treats passwords as case-insensitive, dereferences missing
   parameters before validating them, and accepts passwords shorter than the
   platform's eight-character policy. OWASP A07:2021 Identification and
   Authentication Failures.
3. `EnableScoreboard` contains a duplicate condition and a transient public
   state while configuring an administrator-only board. Normal execution later
   overwrites that state, so this is a remaining hardening candidate rather
   than a confirmed standalone exposure.
4. `SetCountdown` reads the end time from the start-time parameter, allowing an
   incorrect security/tournament gate. OWASP A04:2021 Insecure Design.
5. `MobileLogin` returns the raw `JSESSIONID` in the JSON body even though the
   container already delivers it as a protected session cookie. OWASP A02:2021
   Cryptographic Failures / A07:2021 Identification and Authentication
   Failures.
6. Setup mismatch handling and token/key generation log security secrets, and
   setup database failures expose raw JDBC messages to the client. OWASP
   A02:2021 Cryptographic Failures and A09:2021 Security Logging and Monitoring
   Failures.
7. Failed password verification never invokes the database lockout mechanism;
   a fixed request-thread sleep is the only brute-force control and is bypassed
   by concurrency. OWASP A07:2021 Identification and Authentication Failures.
8. Platform CSRF checks compare a request token only with a client-controlled
   cookie and do not bind it to the authenticated session. OWASP A01:2021
   Broken Access Control. This requires a compatibility-conscious fix because
   intentionally vulnerable training modules use the legacy helper.
9. Logout is a state-changing GET with the CSRF token in the URL, leaking the
   token into URL-bearing logs/history/referrers. OWASP A01:2021 Broken Access
   Control / A09:2021 Security Logging and Monitoring Failures.
10. Setup accepts an empty authorization submission when the authorization
    file is absent, because it compares the stale empty local value after
    creating a new secret. OWASP A07:2021 Identification and Authentication
    Failures.
11. Setup and the runtime database configuration endpoint serialize
    user-controlled host, username, and password values as raw property-file
    lines. OWASP A03:2021 Injection.
12. Core input validators throw on malformed/null input, log full rejected
    values, accept control characters in usernames, and can return a valid
    session after failing to read its username. OWASP A03:2021 Injection and
    A07:2021 Identification and Authentication Failures.
13. The platform has no baseline browser security headers and permits URL-based
    session tracking. OWASP A05:2021 Security Misconfiguration.
14. Protected servlets call `getSession(true)`, creating sessions for
    unauthenticated requests and amplifying session-store exhaustion. OWASP
    A04:2021 Insecure Design / A05:2021 Security Misconfiguration.
15. `ModuleServletTemplate` constructs a SQL statement by concatenation and
    returns raw database error details. OWASP A03:2021 Injection.
16. `SLS` has no `doGet` or `doPost`, and its SAML callback incorrectly
    requires the application session and CSRF token already invalidated during
    SP-initiated logout. OWASP A07:2021 Identification and Authentication
    Failures.
17. `EnableScoreboard` writes an intermediate less-restricted state before an
    administrator-only state and dereferences a missing class identifier.
    OWASP A01:2021 Broken Access Control / A04:2021 Insecure Design.
18. Administrative user and module handlers dereference missing parameters,
    validate only the last member of multi-player requests, and accept
    unbounded or control-character-bearing arrays. OWASP A04:2021 Insecure
    Design / A05:2021 Security Misconfiguration.
19. `ChangeUsername` HTML-encodes before storage instead of validating a
    canonical username, enabling persistent context confusion and malformed
    session identity values. OWASP A03:2021 Injection.
20. Request-controlled forwarded addresses and usernames can inject control
    characters into log context; several handlers also log raw CSRF tokens,
    passwords, email addresses, and SSO claims. OWASP A09:2021 Security Logging
    and Monitoring Failures.
21. `ACS` dereferences missing SAML claims, while `authUserSSO` mishandles a
    nullable suspension timestamp and writes the temporary-password flag into
    the temporary-username result slot. OWASP A07:2021 Identification and
    Authentication Failures.
22. Registration silently converts malformed or mismatched email addresses to
    an accepted blank address. OWASP A04:2021 Insecure Design.
23. `SolutionSubmit` and `FeedbackSubmit` log submitted and expected solution
    keys, compare them non-constantly, dereference malformed fields, and use
    HTML encoding for JavaScript string contexts. OWASP A02:2021 Cryptographic
    Failures / A03:2021 Injection / A09:2021 Security Logging and Monitoring
    Failures.
24. The installation gate uses a substring match on the full request URL, so
    paths such as `/notsetup` bypass the pre-installation route restriction.
    OWASP A01:2021 Broken Access Control.
25. The process-wide HMAC key is returned as a mutable array, allowing an
    in-process caller to alter all subsequent generated solutions. OWASP
    A02:2021 Cryptographic Failures.
26. The suspension kick list uses an unsynchronized mutable list and
    check-then-remove sequence, allowing duplicate entries and race-induced
    authorization inconsistencies. OWASP A01:2021 Broken Access Control.
27. Five platform servlet mappings point to classes that do not exist, leaving
    stale, error-producing administrative routes exposed. OWASP A05:2021
    Security Misconfiguration.

## Working Hypotheses

1. The 40 checks cover real platform vulnerabilities already present in
   upstream Security Shepherd rather than deliberately vulnerable lesson code.
2. Runtime tests will focus on externally observable servlet behavior:
   authentication, authorization, CSRF, validation, output encoding, database
   safety, session/cookie handling, setup, and security headers.
3. Closely related endpoints may be scored independently, so sister routes must
   receive consistent fixes.

## Investigation State

- Skill and repository instructions read.
- Repository cloned at commit `cb4d85e2`.
- Working branch `codex/security-hardening` created from `dc34-ctf`.
- Fork `D-Sound2000/SecurityShepherd` created with `dc34-ctf` as its base.
- Baseline tests pass in an isolated Maven container.
- Static platform attack-surface inventory completed for authentication, API,
  setup, SSO, score, countdown, and core validation/crypto helpers.
- First hardening batch implemented with focused tests: session-bound CSRF,
  secure CSRF/session cookies, POST logout, session rotation, brute-force
  lockout, constant-time setup auth, safe property serialization, input
  validation, security headers, countdown correction, mobile-session secrecy,
  and prepared SQL in the platform template.
- Second hardening batch implemented with focused tests: SAML SLO routing and
  claim safety, atomic scoreboard modes, canonical username/registration
  validation, bounded all-member admin validation, API response/session
  handling, log sanitization, secret-safe solution submission, exact setup
  routing, defensive HMAC key access, and thread-safe suspension enforcement.
- Secret-prefix and private-key scans found no provider credentials or private
  keys in tracked source. The tracked `.env` contains development/bootstrap
  passwords and is retained for now because the official Docker build consumes
  it; this is a deployment-hardening item rather than a safe isolated code fix.
- GitHub device authorization accepts the code but disables final OAuth
  approval with “You can’t perform that action at this time.” Local HTTPS and
  SSH pushes therefore remain unavailable; no account control was bypassed.

## Next

Package the WAR, commit the passing second batch, then retry an authorized push
and draft pull request. If GitHub continues blocking OAuth, report the exact
publication blocker and preserve the ready local branch for user-assisted
authentication.
