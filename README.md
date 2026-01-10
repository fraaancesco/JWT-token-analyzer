# JWT Token Analyzer

A security analysis tool for JWT (JSON Web Token) tokens. This REST API service analyzes JWT structure, claims, and identifies potential security vulnerabilities and best practices violations.

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
- Go 1.21 or higher
- Docker (optional)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/fraaancois/jwt-token-analyzer.git
cd jwt-token-analyzer

# Install dependencies
go mod tidy

# Install swag for Swagger documentation
go install github.com/swaggo/swag/cmd/swag@latest

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
├── cmd/
│   └── server/
│       └── main.go           # Application entry point
├── internal/
│   ├── analyzer/
│   │   └── analyzer.go       # JWT analysis logic
│   ├── config/
│   │   └── config.go         # Configuration management
│   └── handler/
│       └── analyze.go        # HTTP handlers
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

