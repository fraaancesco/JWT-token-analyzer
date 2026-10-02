package scanner

import (
	"regexp"

	"github.com/fraaancesco/jwt-token-analyzer/pkg/models"
)

// Rule is a source-code pattern that indicates how a project uses JWTs.
// Rules with SeverityInfo document usage (libraries, APIs); the others are risks.
type Rule struct {
	ID             string
	Title          string
	Description    string
	Severity       models.Severity
	Recommendation string
	Pattern        *regexp.Regexp
}

// Rules is the list of code patterns looked for in every scanned file.
var Rules = []Rule{
	// Libraries (documentation of the JWT stack in use)
	{
		ID:             "LIB_GOLANG_JWT",
		Title:          "Go library: golang-jwt",
		Description:    "The project uses github.com/golang-jwt/jwt",
		Severity:       models.SeverityInfo,
		Recommendation: "Keep the library on the latest major version and always pass jwt.WithValidMethods to the parser",
		Pattern:        regexp.MustCompile(`github\.com/golang-jwt/jwt`),
	},
	{
		ID:             "LIB_DGRIJALVA_JWT",
		Title:          "Deprecated Go library: dgrijalva/jwt-go",
		Description:    "github.com/dgrijalva/jwt-go is unmaintained and affected by CVE-2020-26160 (audience check bypass)",
		Severity:       models.SeverityHigh,
		Recommendation: "Migrate to github.com/golang-jwt/jwt/v5",
		Pattern:        regexp.MustCompile(`github\.com/dgrijalva/jwt-go`),
	},
	{
		ID:             "LIB_GO_JOSE",
		Title:          "Go library: go-jose / lestrrat-go/jwx",
		Description:    "The project uses a JOSE library for Go",
		Severity:       models.SeverityInfo,
		Recommendation: "Restrict the accepted algorithms and keep the library updated",
		Pattern:        regexp.MustCompile(`github\.com/(go-jose/go-jose|square/go-jose|lestrrat-go/jwx)`),
	},
	{
		ID:             "LIB_NODE_JSONWEBTOKEN",
		Title:          "Node.js library: jsonwebtoken",
		Description:    "The project uses the jsonwebtoken package",
		Severity:       models.SeverityInfo,
		Recommendation: "Use version 9 or later and always pass the algorithms option to jwt.verify",
		Pattern:        regexp.MustCompile(`require\(\s*['"]jsonwebtoken['"]\s*\)|from\s+['"]jsonwebtoken['"]|"jsonwebtoken"\s*:`),
	},
	{
		ID:             "LIB_NODE_JOSE",
		Title:          "Node.js library: jose / jwt-decode",
		Description:    "The project uses the jose or jwt-decode package",
		Severity:       models.SeverityInfo,
		Recommendation: "jwt-decode does not verify signatures: use it only to read claims client-side, never to authorize",
		Pattern:        regexp.MustCompile(`require\(\s*['"](jose|jwt-decode)['"]\s*\)|from\s+['"](jose|jwt-decode)['"]|"(jose|jwt-decode)"\s*:`),
	},
	{
		ID:             "LIB_PYJWT",
		Title:          "Python library: PyJWT / python-jose",
		Description:    "The project uses PyJWT or python-jose",
		Severity:       models.SeverityInfo,
		Recommendation: "Always pass the algorithms argument to jwt.decode",
		Pattern:        regexp.MustCompile(`(?m)^\s*(import\s+jwt\b|from\s+jwt\s+import|from\s+jose\s+import|import\s+jose\b)|(?i)^\s*(pyjwt|python-jose)\b`),
	},
	{
		ID:             "LIB_JAVA_JWT",
		Title:          "Java library: jjwt / java-jwt / nimbus-jose-jwt",
		Description:    "The project uses a Java JWT library",
		Severity:       models.SeverityInfo,
		Recommendation: "Keep the library updated and configure an explicit signing key and algorithm",
		Pattern:        regexp.MustCompile(`io\.jsonwebtoken|com\.auth0\.jwt|com\.nimbusds\.jose`),
	},
	{
		ID:             "LIB_DOTNET_JWT",
		Title:          ".NET library: System.IdentityModel.Tokens.Jwt",
		Description:    "The project uses the Microsoft JWT libraries",
		Severity:       models.SeverityInfo,
		Recommendation: "Keep ValidateIssuer, ValidateAudience, ValidateLifetime and ValidateIssuerSigningKey enabled",
		Pattern:        regexp.MustCompile(`System\.IdentityModel\.Tokens\.Jwt|Microsoft\.IdentityModel\.Tokens`),
	},
	{
		ID:             "LIB_PHP_JWT",
		Title:          "PHP library: firebase/php-jwt / lcobucci/jwt",
		Description:    "The project uses a PHP JWT library",
		Severity:       models.SeverityInfo,
		Recommendation: "Pass an explicit Key with algorithm to JWT::decode",
		Pattern:        regexp.MustCompile(`Firebase\\JWT|firebase/php-jwt|Lcobucci\\JWT|lcobucci/jwt`),
	},

	// Risky usage
	{
		ID:             "CODE_ALG_NONE",
		Title:          "'none' algorithm accepted or produced",
		Description:    "The code references the 'none' algorithm, which disables signature verification",
		Severity:       models.SeverityCritical,
		Recommendation: "Remove 'none' from the accepted algorithms and never sign tokens with it",
		Pattern:        regexp.MustCompile(`(?i)\b(alg|algorithms?)['"]?\s*[:=]\s*\[?\s*['"]none['"]|SigningMethodNone|UnsafeAllowNoneSignatureType`),
	},
	{
		ID:             "CODE_UNVERIFIED_PARSE",
		Title:          "Token parsed without signature verification",
		Description:    "The code decodes a JWT without verifying its signature",
		Severity:       models.SeverityHigh,
		Recommendation: "Use the verifying API (jwt.Parse with a key, jwt.verify, jwt.decode with key and algorithms) for any authorization decision",
		Pattern:        regexp.MustCompile(`ParseUnverified\(|verify_signature['"]?\s*:\s*False|verify\s*=\s*False|\bjwt\.decode\(\s*[A-Za-z_$][\w$.]*\s*(,\s*\{[^}]*complete[^}]*\})?\s*\)|\bjwtDecode\(|parseClaimsJwt\(|parseUnsecuredClaims\(`),
	},
	{
		ID:             "CODE_IGNORE_EXPIRATION",
		Title:          "Expiration check disabled",
		Description:    "The code explicitly disables the 'exp' validation",
		Severity:       models.SeverityHigh,
		Recommendation: "Keep expiration validation enabled and use short-lived tokens with refresh",
		Pattern:        regexp.MustCompile(`ignoreExpiration\s*:\s*true|verify_exp['"]?\s*:\s*False|ValidateLifetime\s*=\s*false|WithoutClaimsValidation\(`),
	},
	{
		ID:             "CODE_NO_AUDIENCE_CHECK",
		Title:          "Issuer or audience validation disabled",
		Description:    "The code disables issuer or audience validation, so tokens from other services may be accepted",
		Severity:       models.SeverityMedium,
		Recommendation: "Validate both 'iss' and 'aud' against the expected values",
		Pattern:        regexp.MustCompile(`verify_aud['"]?\s*:\s*False|verify_iss['"]?\s*:\s*False|ValidateAudience\s*=\s*false|ValidateIssuer\s*=\s*false`),
	},
	{
		ID:             "CODE_NO_SIGNING_KEY_CHECK",
		Title:          "Signing key validation disabled",
		Description:    "The code disables the validation of the issuer signing key",
		Severity:       models.SeverityCritical,
		Recommendation: "Set ValidateIssuerSigningKey = true and configure the trusted keys",
		Pattern:        regexp.MustCompile(`ValidateIssuerSigningKey\s*=\s*false|RequireSignedTokens\s*=\s*false`),
	},
	{
		ID:             "CODE_HARDCODED_SECRET",
		Title:          "Hardcoded JWT secret",
		Description:    "A JWT signing secret appears to be written directly in the source code",
		Severity:       models.SeverityHigh,
		Recommendation: "Load the secret from a secret manager or environment variable, rotate the exposed one, and use at least 256 random bits",
		Pattern:        regexp.MustCompile(`(?i)\b(jwt|token|signing|access|refresh)[_-]?(secret|key)\w*['"]?\s*[:=]\s*['"][^'"\s]{4,}['"]|(?i)jwt\.sign\([^,]+,\s*['"][^'"]+['"]|\[\]byte\(\s*"[^"]{4,}"\s*\)\s*,?\s*nil|(?i)hmac\w*key\s*[:=]\s*\[\]byte\(\s*"`),
	},
	{
		ID:             "CODE_TOKEN_IN_LOCALSTORAGE",
		Title:          "Token stored in Web Storage",
		Description:    "The token is saved in localStorage or sessionStorage, readable by any XSS payload",
		Severity:       models.SeverityMedium,
		Recommendation: "Prefer HttpOnly, Secure, SameSite cookies for session tokens",
		Pattern:        regexp.MustCompile(`(?i)(localStorage|sessionStorage)\.setItem\(\s*['"][^'"]*(token|jwt)[^'"]*['"]`),
	},
	{
		ID:             "CODE_TOKEN_IN_URL",
		Title:          "Token passed in the URL",
		Description:    "The token is sent as a query parameter and may end up in logs, history and Referer headers",
		Severity:       models.SeverityMedium,
		Recommendation: "Send tokens in the Authorization header or in a cookie",
		Pattern:        regexp.MustCompile(`(?i)[?&](access_token|token|jwt|id_token)=`),
	},
	{
		ID:             "CODE_TOKEN_LOGGED",
		Title:          "Token written to logs",
		Description:    "A JWT or Authorization header seems to be logged",
		Severity:       models.SeverityMedium,
		Recommendation: "Never log tokens; log only the 'jti' or a hash",
		Pattern:        regexp.MustCompile(`(?i)(console\.\w+|\blog\.\w+|logger\.\w+|\bprint|fmt\.Print\w*)\((.*,\s*)?[\w.]*(token|jwt|authorization)\w*\s*[,)]`),
	},
	{
		ID:             "CODE_LONG_EXPIRY",
		Title:          "Very long token lifetime configured",
		Description:    "The token expiration is configured in days, months or years",
		Severity:       models.SeverityMedium,
		Recommendation: "Use access tokens of minutes or hours and refresh token rotation",
		Pattern:        regexp.MustCompile(`(?i)expiresIn\s*:\s*['"]\d+\s*(d|days?|w|weeks?|y|years?)['"]|expiresIn\s*:\s*\d{6,}|timedelta\(\s*days\s*=\s*\d+`),
	},
}

// tokenPattern matches strings that look like a compact-serialized JWT.
var tokenPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*`)
