# JWT Security Report — <project name>

- **Date:** <YYYY-MM-DD>
- **Scope:** <path scanned, excluded paths>
- **Tools:** jwtscan <version or commit> + manual review
- **Overall rating:** <Critical | Poor | Fair | Good | Excellent>

## 1. Executive summary

<3-5 sentences: how the project uses JWTs, the worst risks, what to fix first.>

| Severity | Confirmed risks |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Info | 0 |

## 2. JWT inventory

| Topic | What the project does | Where |
|---|---|---|
| Libraries | <name and version> | `<file:line>` |
| Issuance | <endpoint / function that creates tokens> | `<file:line>` |
| Algorithm(s) | <HS256, RS256, ...> | `<file:line>` |
| Signing key source | <env var, secret manager, file, hardcoded> | `<file:line>` |
| Verification | <middleware / function, accepted algorithms, validated claims> | `<file:line>` |
| Claims | <standard and custom claims issued> | `<file:line>` |
| Lifetime | <access token / refresh token> | `<file:line>` |
| Transport and storage | <header, cookie flags, client storage> | `<file:line>` |
| Refresh, logout, revocation | <how it works, or "not implemented"> | `<file:line>` |

## 3. Token flow

<Step by step: login -> token issued -> sent by the client -> verified -> refreshed -> revoked.
A short list or a mermaid sequence diagram.>

## 4. Risks

### <ID> [<SEVERITY>] <Title>

- **Location:** `<file:line>`
- **What happens:** <description>
- **Impact:** <what an attacker or a bug could cause>
- **Fix:** <concrete change, with a short code example if useful>

<repeat for every confirmed risk, most severe first>

## 5. Tokens and secrets found in the code

| Token / secret (redacted) | Where | Analysis | Action |
|---|---|---|---|
| `eyJhbGciOi...abcd` | `<file:line>` | <alg, exp, issues> | <rotate / remove from history / test fixture> |

## 6. False positives

| Rule | Where | Why it is not a risk |
|---|---|---|

## 7. Checklist

- [ ] Signature always verified with a trusted key
- [ ] Explicit algorithm allow-list, no `none`
- [ ] `exp`, `iss`, `aud` validated
- [ ] Short access token lifetime, refresh rotation
- [ ] Secrets from a secret manager, >= 256 bits, rotatable
- [ ] No tokens in logs, URLs or localStorage
- [ ] No sensitive data in claims
- [ ] Logout and password change revoke tokens

## 8. Next steps

1. <most urgent fix>
2. <...>
