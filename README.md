# JWT Token Analyzer

A security analysis tool for JWT (JSON Web Token) tokens. It comes in three parts:

- a **REST API** that analyzes JWT structure and claims and identifies potential security vulnerabilities and best practices violations;
- **`jwtscan`**, a CLI that scans a whole project for JWTs and JWT-related code and prints a Markdown or JSON report;
- a **Claude Code skill** (`/jwt-scan`) that runs `jwtscan`, reviews the JWT code by hand and writes a complete security report.

## Features

- **JWT Decoding**: Decode and parse JWT tokens without verification
- **Security Analysis**: Comprehensive security checks including:
  - Algorithm vulnerabilities (none algorithm, weak HMAC, etc.)
  - Header injection attacks (JKU, JWK, X5U, X5C, KID injection)
  - Expiration and lifetime issues
  - Missing standard claims
  - Signature validation
  - Sensitive data detection
- **Batch Processing**: Analyze multiple tokens in a single request
- **Swagger Documentation**: Interactive API documentation
- **Project scanner**: find JWT libraries, risky code patterns and hardcoded tokens in any codebase
- **Claude Code skill**: a full, documented JWT security report for a project

## Security Checks

### Critical
- `ALG_NONE` - None algorithm used
- `ALG_MISSING` - Missing algorithm
- `JWK_EMBEDDED` - Embedded JWK in header
- `EMPTY_SIGNATURE` - Empty signature
- `MALFORMED_TOKEN` - Malformed token structure

### High
- `ALG_UNKNOWN` - Unknown algorithm
- `JKU_PRESENT` - JKU header present
- `X5U_PRESENT` - X5U header present
- `KID_INJECTION` - Potential KID injection
- `NO_EXPIRATION` - Missing expiration claim
- `TOKEN_EXPIRED` - Token has expired
- `VERY_LONG_EXPIRATION` - Excessive token lifetime (>7 days)

### Medium
- `ALG_WEAK_HMAC` - Weak HMAC algorithm (HS256)
- `X5C_PRESENT` - X5C header present
- `LONG_EXPIRATION` - Long token lifetime (>24 hours)
- `NO_ISSUER` - Missing issuer claim
- `NO_AUDIENCE` - Missing audience claim
- `IAT_FUTURE` - Issued at in future
- `SENSITIVE_DATA` - Potentially sensitive data in claims

### Low
- `NO_IAT` - Missing issued at claim
- `NO_SUBJECT` - Missing subject claim
- `NO_JTI` - Missing JWT ID

### Info
- `ALG_SYMMETRIC` - Symmetric algorithm used
- `NOT_YET_VALID` - Token not yet valid

## Installation

### Prerequisites
- Go 1.27 or higher
- Docker (optional)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/fraaancesco/JWT-token-analyzer.git
cd JWT-token-analyzer

# Install dependencies
go mod tidy

# Install swag for Swagger documentation
go install github.com/swaggo/swag/cmd/swag@v1.16.6

# Build and run
make run
```

### Docker

```bash
# Build and run with Docker Compose
docker-compose up -d

# Or build manually
docker build -t jwt-token-analyzer .
docker run -p 8082:8082 jwt-token-analyzer
```

## Usage

### API Endpoints

#### Health Check
```bash
curl http://localhost:8082/health
```

#### Analyze JWT Tokens
```bash
curl -X POST http://localhost:8082/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "tokens": ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"]
  }'
```

#### Decode JWT Token (without full security analysis)
```bash
curl -X POST http://localhost:8082/decode \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
  }'
```

### Request Options

The `/analyze` endpoint accepts the following options:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `tokens` | string[] | required | List of JWT tokens to analyze |
| `check_expiration` | bool | true | Whether to check expiration-related issues |
| `max_token_lifetime_hours` | int | 168 | Maximum acceptable token lifetime in hours |
| `warn_token_lifetime_hours` | int | 24 | Token lifetime threshold for warnings |

### Response Format

```json
{
  "analysis_date": "2024-01-10T15:04:05Z",
  "results": [
    {
      "token": "eyJhbGci...",
      "is_valid": true,
      "header": {
        "alg": "HS256",
        "typ": "JWT"
      },
      "payload": {
        "standard_claims": {
          "sub": "1234567890",
          "iat": 1516239022
        },
        "custom_claims": {
          "name": "John Doe"
        },
        "raw_claims": {...}
      },
      "signature": "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      "token_info": {
        "is_expired": false,
        "has_signature": true,
        "parts_count": 3
      },
      "security_issues": [
        {
          "code": "ALG_WEAK_HMAC",
          "title": "Weak HMAC Algorithm",
          "description": "The JWT uses HS256 which may be vulnerable...",
          "severity": "medium",
          "recommendation": "Consider using HS384 or HS512...",
          "affected_field": "alg"
        }
      ],
      "summary": {
        "total_issues": 5,
        "critical_count": 0,
        "high_count": 1,
        "medium_count": 2,
        "low_count": 2,
        "info_count": 0,
        "security_score": "65%",
        "overall_rating": "Fair"
      }
    }
  ]
}
```

## Project scanner (`jwtscan`)

`jwtscan` walks a project and reports:

- the **JWT libraries** in use (Go, Node.js, Python, Java, .NET, PHP), including deprecated ones such as `dgrijalva/jwt-go`;
- **risky code patterns**: `none` algorithm, decoding without signature verification, disabled `exp` / `iss` / `aud` / signing key validation, hardcoded secrets, tokens in `localStorage`, in URLs or in logs, very long lifetimes;
- **hardcoded JWTs**, each one decoded and analyzed with all the checks of the API.

Tokens and secrets are always redacted in the output.

### Install

```bash
go install github.com/fraaancesco/jwt-token-analyzer/cmd/jwtscan@latest
```

The binary goes to `$(go env GOPATH)/bin`. From a clone you can also use `make build-jwtscan` or `go run ./cmd/jwtscan`.

### Usage

```bash
jwtscan [flags] [path]          # path defaults to the current directory

jwtscan .                                   # Markdown report on stdout
jwtscan -o jwt-report.md ~/code/my-api      # write the report to a file
jwtscan -format json . > jwt-report.json    # JSON report
jwtscan -exclude 'testdata,*.min.js' .      # skip more paths (glob, comma separated)
jwtscan -fail-on high .                     # exit code 2 if something high or critical is found (CI)
```

| Flag | Default | Description |
|------|---------|-------------|
| `-format` | `md` | Report format: `md` or `json` |
| `-o` | stdout | Write the report to a file |
| `-exclude` | | Extra glob patterns to skip; `.git`, `node_modules`, `vendor`, `dist`, `build`, `target`, virtualenvs, ... are always skipped |
| `-fail-on` | | Exit with code 2 when a finding has this severity or higher (`critical`, `high`, `medium`, `low`, `info`) |

Exit codes: `0` success, `1` error, `2` findings at or above `-fail-on`.

## Claude Code skill: `/jwt-scan`

The skill in [`.claude/skills/jwt-scan`](.claude/skills/jwt-scan/SKILL.md) makes Claude Code:

1. run `jwtscan` on the project;
2. review by hand the issuance, keys, verification, storage, refresh and revocation of the tokens;
3. write `JWT_SECURITY_REPORT.md` in the project root, following [the report template](.claude/skills/jwt-scan/report-template.md): JWT inventory, token flow, every risk with location, impact and fix, tokens and secrets found, false positives, checklist and next steps.

### Install the skill

Requirements: [Claude Code](https://code.claude.com) and Go 1.27+ (the skill installs `jwtscan` by itself if it is missing).

**For all your projects** (personal skill, in `~/.claude/skills`):

```bash
git clone --depth 1 https://github.com/fraaancesco/JWT-token-analyzer.git /tmp/jwt-token-analyzer
mkdir -p ~/.claude/skills
cp -r /tmp/jwt-token-analyzer/.claude/skills/jwt-scan ~/.claude/skills/
rm -rf /tmp/jwt-token-analyzer
```

**For a single project** (shared with whoever clones it, in `<project>/.claude/skills`):

```bash
cd /path/to/your/project
git clone --depth 1 https://github.com/fraaancesco/JWT-token-analyzer.git /tmp/jwt-token-analyzer
mkdir -p .claude/skills
cp -r /tmp/jwt-token-analyzer/.claude/skills/jwt-scan .claude/skills/
rm -rf /tmp/jwt-token-analyzer
```

Optionally install the scanner in advance:

```bash
go install github.com/fraaancesco/jwt-token-analyzer/cmd/jwtscan@latest
```

Inside this repository the skill is already available, no installation needed.

### Use the skill

Start Claude Code in the project to audit and run:

```text
/jwt-scan              # scan the current directory
/jwt-scan services/api # scan a sub-directory
```

or simply ask "scan the JWT usage of this project and write a security report". If `/jwt-scan` does not show up, restart Claude Code and check that the file is at `~/.claude/skills/jwt-scan/SKILL.md` (or `.claude/skills/jwt-scan/SKILL.md` in the project).

To update the skill, repeat the copy commands; to remove it, delete the `jwt-scan` folder.

## Swagger Documentation

Access the interactive API documentation at:
```
http://localhost:8082/swagger/index.html
```

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_PORT` | 8082 | Server port |
| `GIN_MODE` | debug | Gin mode (debug/release) |
| `ANALYZER_CHECK_EXPIRATION` | true | Enable expiration checks |
| `ANALYZER_MAX_TOKEN_LIFETIME` | 168 | Max token lifetime in hours |
| `ANALYZER_WARN_TOKEN_LIFETIME` | 24 | Warn threshold in hours |

## Development

```bash
# Run tests
make test

# Run tests with coverage (fails below 100%)
make cover

# Build the jwtscan CLI
make build-jwtscan

# Regenerate Swagger docs
make swagger

# Clean build artifacts
make clean

# Full rebuild
make rebuild
```

## Project Structure

```
jwt-token-analyzer/
├── .claude/
│   └── skills/
│       └── jwt-scan/         # Claude Code skill (SKILL.md + report template)
├── cmd/
│   ├── jwtscan/
│   │   └── main.go           # Project scanner CLI
│   └── server/
│       └── main.go           # API entry point
├── internal/
│   ├── analyzer/
│   │   └── analyzer.go       # JWT analysis logic
│   ├── config/
│   │   └── config.go         # Configuration management
│   ├── handler/
│   │   └── analyze.go        # HTTP handlers
│   ├── report/
│   │   └── report.go         # Markdown / JSON scan reports
│   ├── scanner/
│   │   ├── rules.go          # Code patterns looked for
│   │   └── scanner.go        # Project walker and token extraction
│   └── testutil/             # Test helpers
├── pkg/
│   └── models/
│       ├── checks.go         # Security check definitions
│       ├── jwt.go            # JWT data models
│       └── severity.go       # Severity levels
├── docs/                     # Generated Swagger docs
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── README.md
```

