---
name: jwt-scan
description: Scan a project for JWT (JSON Web Token) usage and write a security report that documents how tokens are issued, verified, stored and revoked, plus every risk found (alg none, unverified decoding, hardcoded secrets, missing exp/iss/aud checks, tokens in logs, URLs or localStorage, hardcoded tokens). Use when the user asks to audit, scan, review or document JWT / token authentication in a codebase.
argument-hint: "[path]"
---

# JWT scan

Produce `JWT_SECURITY_REPORT.md` for the project at the path given as argument
(default: the current working directory). The report must document the whole JWT
setup of the project and every risk, with file and line references.

## 1. Get the scanner

The automated part uses `jwtscan`, from https://github.com/fraaancesco/JWT-token-analyzer.

```bash
command -v jwtscan || go install github.com/fraaancesco/jwt-token-analyzer/cmd/jwtscan@latest
```

`go install` needs Go 1.27 or later and puts the binary in `$(go env GOPATH)/bin`:
call it with that full path if it is not on `PATH`. If Go is missing, tell the
user and continue with step 3 only (manual review), saying that the automated
scan was not run.

## 2. Run the automated scan

```bash
jwtscan -format json <path> > /tmp/jwtscan.json
jwtscan -o jwt-scan-raw.md <path>
```

- Add `-exclude 'pattern,pattern'` for generated code, fixtures or vendored files the
  user does not own (`node_modules`, `vendor`, `dist`, `build`, `.git`, ... are already skipped).
- The JSON has `findings` (code patterns, with `rule_id`, `severity`, `file`, `line`,
  `snippet`), `tokens` (JWTs found in the files, already redacted, with the full
  analysis of header, claims, expiry and issues), `counts` and `rating`.
- Severity order: critical > high > medium > low > info. `LIB_*` findings with
  severity info only document which libraries are used.

## 3. Review the code by hand

The scanner matches text patterns: confirm each finding and look for what it cannot see.
Open every file listed in the findings, then search the project for the JWT code
(`jwt`, `jose`, `token`, `bearer`, `Authorization`, `sign(`, `verify(`, `decode(`, `parse(`).
For each point below, write down what the project does and where (`file:line`):

1. **Issuance**: where tokens are created, algorithm, claims (`iss`, `sub`, `aud`, `exp`,
   `iat`, `nbf`, `jti`, custom claims), lifetime of access and refresh tokens.
2. **Keys and secrets**: where the signing key comes from (env, secret manager, file,
   hardcoded), its strength, rotation, JWKS endpoint, `kid` handling.
3. **Verification**: every place where an incoming token is accepted. Check that the
   signature is verified, the algorithm is an explicit allow-list, the key is not taken
   from the token (`jwk`, `jku`, `x5u` headers), and `exp`, `nbf`, `iss`, `aud` are
   validated with a small clock skew. Check every route or middleware is protected.
4. **Transport and storage**: Authorization header or cookie (`HttpOnly`, `Secure`,
   `SameSite`), tokens in URLs, logs, error messages, localStorage.
5. **Lifecycle**: refresh token rotation and reuse detection, logout, revocation
   (deny-list on `jti`), invalidation after password change.
6. **Claims content**: personal or secret data inside the payload, roles or permissions
   trusted without server-side checks.

Mark false positives (for example a rule that matches a test fixture or a comment)
and keep them out of the risks, listing them in their own section.

## 4. Write the report

Write `JWT_SECURITY_REPORT.md` in the root of the scanned project, following
[report-template.md](report-template.md). Rules:

- Write it in the language the user is using.
- Every risk has: severity, location (`file:line`), what happens, impact, how to fix it.
- Sort risks by severity. Give the overall rating from the worst confirmed risk.
- Never copy a full token, secret or private key into the report or the chat:
  use the redacted form from `jwtscan` (`eyJhbGciOi...abcd`) or mask the value.
- If a hardcoded token or secret looks real, say it must be rotated and removed from
  the git history, not just deleted from the current files.
- Explain risks and fixes; do not write exploit code.

Delete `jwt-scan-raw.md` and `/tmp/jwtscan.json` when the report is written, unless the
user asked to keep them.

## 5. Answer

Reply with the path of the report, the overall rating, the number of risks per
severity and the three most important fixes.
