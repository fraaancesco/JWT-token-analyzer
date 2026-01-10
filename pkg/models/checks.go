package models

// SecurityCheck defines a security check to perform on JWT tokens
type SecurityCheck struct {
	Code           string
	Title          string
	Description    string
	Severity       Severity
	Recommendation string
}

// SecurityChecks contains all the security checks performed on JWT tokens
var SecurityChecks = []SecurityCheck{
	// Algorithm vulnerabilities
	{
		Code:           "ALG_NONE",
		Title:          "None Algorithm Used",
		Description:    "The JWT uses 'none' algorithm which means no signature verification is performed",
		Severity:       SeverityCritical,
		Recommendation: "Never accept tokens with 'none' algorithm. Always require a valid cryptographic algorithm",
	},
	{
		Code:           "ALG_WEAK_HMAC",
		Title:          "Weak HMAC Algorithm",
		Description:    "The JWT uses HS256 which may be vulnerable to brute-force attacks if the secret is weak",
		Severity:       SeverityMedium,
		Recommendation: "Consider using HS384 or HS512 for stronger security, and ensure a strong secret key (256+ bits)",
	},
	{
		Code:           "ALG_SYMMETRIC",
		Title:          "Symmetric Algorithm Used",
		Description:    "HMAC algorithms require shared secrets which can be leaked. Asymmetric algorithms are preferred",
		Severity:       SeverityInfo,
		Recommendation: "Consider using asymmetric algorithms (RS256, ES256) for better key management",
	},
	{
		Code:           "ALG_MISSING",
		Title:          "Missing Algorithm",
		Description:    "The JWT header does not specify an algorithm",
		Severity:       SeverityCritical,
		Recommendation: "Always specify a valid signing algorithm in the JWT header",
	},
	{
		Code:           "ALG_UNKNOWN",
		Title:          "Unknown Algorithm",
		Description:    "The JWT uses an unrecognized algorithm",
		Severity:       SeverityHigh,
		Recommendation: "Use standard JWT algorithms: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512",
	},

	// Header vulnerabilities
	{
		Code:           "JKU_PRESENT",
		Title:          "JKU Header Present",
		Description:    "The 'jku' (JWK Set URL) header is present and could be exploited for key injection attacks",
		Severity:       SeverityHigh,
		Recommendation: "Validate JKU URLs against a whitelist of trusted key sources",
	},
	{
		Code:           "JWK_EMBEDDED",
		Title:          "Embedded JWK in Header",
		Description:    "The JWT contains an embedded public key in the 'jwk' header which could be used for key injection",
		Severity:       SeverityCritical,
		Recommendation: "Never trust embedded keys. Always verify signatures using keys from trusted sources",
	},
	{
		Code:           "X5U_PRESENT",
		Title:          "X5U Header Present",
		Description:    "The 'x5u' (X.509 URL) header is present and could be exploited for certificate injection",
		Severity:       SeverityHigh,
		Recommendation: "Validate X5U URLs against a whitelist of trusted certificate sources",
	},
	{
		Code:           "X5C_PRESENT",
		Title:          "X5C Header Present",
		Description:    "The 'x5c' (X.509 Certificate Chain) header contains embedded certificates",
		Severity:       SeverityMedium,
		Recommendation: "Validate certificate chains against trusted root CAs",
	},
	{
		Code:           "KID_INJECTION",
		Title:          "Potential KID Injection",
		Description:    "The 'kid' (Key ID) contains suspicious characters that could be used for injection attacks",
		Severity:       SeverityHigh,
		Recommendation: "Sanitize 'kid' values and use a whitelist of valid key identifiers",
	},

	// Expiration issues
	{
		Code:           "NO_EXPIRATION",
		Title:          "Missing Expiration Claim",
		Description:    "The JWT does not have an 'exp' (expiration) claim, making it valid indefinitely",
		Severity:       SeverityHigh,
		Recommendation: "Always include an 'exp' claim with a reasonable expiration time",
	},
	{
		Code:           "TOKEN_EXPIRED",
		Title:          "Token Has Expired",
		Description:    "The JWT has passed its expiration time and should no longer be accepted",
		Severity:       SeverityHigh,
		Recommendation: "Reject expired tokens and require re-authentication",
	},
	{
		Code:           "LONG_EXPIRATION",
		Title:          "Long Token Lifetime",
		Description:    "The JWT has a very long expiration time (more than 24 hours)",
		Severity:       SeverityMedium,
		Recommendation: "Use shorter token lifetimes and implement refresh token rotation",
	},
	{
		Code:           "VERY_LONG_EXPIRATION",
		Title:          "Excessive Token Lifetime",
		Description:    "The JWT has an excessive expiration time (more than 7 days)",
		Severity:       SeverityHigh,
		Recommendation: "Reduce token lifetime significantly. Long-lived tokens increase the window for attacks",
	},
	{
		Code:           "NO_IAT",
		Title:          "Missing Issued At Claim",
		Description:    "The JWT does not have an 'iat' (issued at) claim",
		Severity:       SeverityLow,
		Recommendation: "Include 'iat' claim to track when the token was issued",
	},
	{
		Code:           "NOT_YET_VALID",
		Title:          "Token Not Yet Valid",
		Description:    "The JWT 'nbf' (not before) claim indicates the token is not yet valid",
		Severity:       SeverityInfo,
		Recommendation: "Wait until the token becomes valid or check system clock synchronization",
	},
	{
		Code:           "IAT_FUTURE",
		Title:          "Issued At In Future",
		Description:    "The 'iat' claim is set to a future time, which is suspicious",
		Severity:       SeverityMedium,
		Recommendation: "Reject tokens with future 'iat' claims or check for clock skew",
	},

	// Identity claims
	{
		Code:           "NO_SUBJECT",
		Title:          "Missing Subject Claim",
		Description:    "The JWT does not have a 'sub' (subject) claim to identify the principal",
		Severity:       SeverityLow,
		Recommendation: "Include 'sub' claim to uniquely identify the token subject",
	},
	{
		Code:           "NO_ISSUER",
		Title:          "Missing Issuer Claim",
		Description:    "The JWT does not have an 'iss' (issuer) claim",
		Severity:       SeverityMedium,
		Recommendation: "Include 'iss' claim to identify the token issuer for validation",
	},
	{
		Code:           "NO_AUDIENCE",
		Title:          "Missing Audience Claim",
		Description:    "The JWT does not have an 'aud' (audience) claim",
		Severity:       SeverityMedium,
		Recommendation: "Include 'aud' claim to prevent token misuse across different services",
	},
	{
		Code:           "NO_JTI",
		Title:          "Missing JWT ID",
		Description:    "The JWT does not have a 'jti' (JWT ID) claim for unique identification",
		Severity:       SeverityLow,
		Recommendation: "Include 'jti' claim to enable token revocation and prevent replay attacks",
	},

	// Signature issues
	{
		Code:           "EMPTY_SIGNATURE",
		Title:          "Empty Signature",
		Description:    "The JWT has an empty signature component",
		Severity:       SeverityCritical,
		Recommendation: "Ensure all tokens are properly signed with a valid algorithm",
	},
	{
		Code:           "MALFORMED_TOKEN",
		Title:          "Malformed Token Structure",
		Description:    "The JWT does not have the standard three-part structure (header.payload.signature)",
		Severity:       SeverityCritical,
		Recommendation: "Ensure the token follows the JWT specification (RFC 7519)",
	},

	// Sensitive data
	{
		Code:           "SENSITIVE_DATA",
		Title:          "Potentially Sensitive Data in Claims",
		Description:    "The JWT payload may contain sensitive information that should not be in a token",
		Severity:       SeverityMedium,
		Recommendation: "Avoid storing sensitive data like passwords, credit cards, or PII in JWT claims",
	},
}

// GetCheckByCode returns a security check by its code
func GetCheckByCode(code string) *SecurityCheck {
	for _, check := range SecurityChecks {
		if check.Code == code {
			return &check
		}
	}
	return nil
}
