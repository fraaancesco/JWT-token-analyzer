package models

import "time"

// JWTHeader represents the decoded JWT header
type JWTHeader struct {
	Algorithm   string  `json:"alg"`
	Type        string  `json:"typ,omitempty"`
	KeyID       *string `json:"kid,omitempty"`
	ContentType *string `json:"cty,omitempty"`
	X5U         *string `json:"x5u,omitempty"`
	X5C         *string `json:"x5c,omitempty"`
	X5T         *string `json:"x5t,omitempty"`
	JKU         *string `json:"jku,omitempty"`
	JWK         *string `json:"jwk,omitempty"`
}

// StandardClaims represents the standard JWT claims (RFC 7519)
type StandardClaims struct {
	Issuer         *string `json:"iss,omitempty"`
	Subject        *string `json:"sub,omitempty"`
	Audience       *string `json:"aud,omitempty"`
	ExpirationTime *int64  `json:"exp,omitempty"`
	NotBefore      *int64  `json:"nbf,omitempty"`
	IssuedAt       *int64  `json:"iat,omitempty"`
	JWTID          *string `json:"jti,omitempty"`
}

// DecodedPayload represents the decoded JWT payload with standard and custom claims
type DecodedPayload struct {
	StandardClaims StandardClaims         `json:"standard_claims"`
	CustomClaims   map[string]interface{} `json:"custom_claims,omitempty"`
	RawClaims      map[string]interface{} `json:"raw_claims"`
}

// SecurityIssue represents a security vulnerability or concern found in the JWT
type SecurityIssue struct {
	Code           string   `json:"code"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Severity       Severity `json:"severity"`
	Recommendation string   `json:"recommendation"`
	AffectedField  string   `json:"affected_field,omitempty"`
}

// TokenInfo contains metadata about the JWT
type TokenInfo struct {
	IsExpired        bool       `json:"is_expired"`
	IsNotYetValid    bool       `json:"is_not_yet_valid"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	IssuedAt         *time.Time `json:"issued_at,omitempty"`
	NotBefore        *time.Time `json:"not_before,omitempty"`
	TokenLifetime    *string    `json:"token_lifetime,omitempty"`
	TimeUntilExpiry  *string    `json:"time_until_expiry,omitempty"`
	TimeSinceExpiry  *string    `json:"time_since_expiry,omitempty"`
	HasSignature     bool       `json:"has_signature"`
	SignaturePresent bool       `json:"signature_present"`
	PartsCount       int        `json:"parts_count"`
}

// AnalysisResult represents the complete analysis of a JWT token
type AnalysisResult struct {
	Token          string          `json:"token"`
	IsValid        bool            `json:"is_valid"`
	Error          *string         `json:"error,omitempty"`
	Header         *JWTHeader      `json:"header,omitempty"`
	Payload        *DecodedPayload `json:"payload,omitempty"`
	Signature      string          `json:"signature,omitempty"`
	TokenInfo      *TokenInfo      `json:"token_info,omitempty"`
	SecurityIssues []SecurityIssue `json:"security_issues"`
	Summary        *AnalysisSummary `json:"summary,omitempty"`
}

// AnalysisSummary provides a summary of the security analysis
type AnalysisSummary struct {
	TotalIssues      int    `json:"total_issues"`
	CriticalCount    int    `json:"critical_count"`
	HighCount        int    `json:"high_count"`
	MediumCount      int    `json:"medium_count"`
	LowCount         int    `json:"low_count"`
	InfoCount        int    `json:"info_count"`
	SecurityScore    string `json:"security_score"`
	OverallRating    string `json:"overall_rating"`
}

// Report represents the complete analysis report
type Report struct {
	AnalysisDate string           `json:"analysis_date"`
	Results      []AnalysisResult `json:"results"`
}
