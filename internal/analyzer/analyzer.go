package analyzer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/fraaancois/jwt-token-analyzer/pkg/models"
)

// Options contains configuration for the JWT analyzer
type Options struct {
	CheckExpiration    bool
	MaxTokenLifetime   time.Duration
	WarnTokenLifetime  time.Duration
	AllowNoneAlgorithm bool
	SensitiveFields    []string
}

// DefaultOptions returns the default analyzer options
func DefaultOptions() Options {
	return Options{
		CheckExpiration:    true,
		MaxTokenLifetime:   7 * 24 * time.Hour,  // 7 days
		WarnTokenLifetime:  24 * time.Hour,      // 24 hours
		AllowNoneAlgorithm: false,
		SensitiveFields: []string{
			"password", "passwd", "pwd", "secret", "token",
			"credit_card", "creditcard", "cc_number", "cvv",
			"ssn", "social_security", "pin",
			"private_key", "privatekey", "api_key", "apikey",
		},
	}
}

// Analyze performs a complete security analysis of a JWT token
func Analyze(token string, opts Options) models.AnalysisResult {
	result := models.AnalysisResult{
		Token:          token,
		IsValid:        true,
		SecurityIssues: []models.SecurityIssue{},
	}

	// Clean the token
	token = strings.TrimSpace(token)
	if strings.HasPrefix(strings.ToLower(token), "bearer ") {
		token = strings.TrimSpace(token[7:])
		result.Token = token
	}

	// Split the token into parts
	parts := strings.Split(token, ".")
	result.TokenInfo = &models.TokenInfo{
		PartsCount: len(parts),
	}

	// Check token structure
	if len(parts) != 3 {
		errMsg := fmt.Sprintf("Invalid JWT structure: expected 3 parts, got %d", len(parts))
		result.IsValid = false
		result.Error = &errMsg
		result.SecurityIssues = append(result.SecurityIssues, createIssue("MALFORMED_TOKEN", ""))
		result.Summary = calculateSummary(result.SecurityIssues)
		return result
	}

	// Decode and analyze header
	header, headerIssues, err := decodeHeader(parts[0])
	if err != nil {
		errMsg := fmt.Sprintf("Failed to decode header: %v", err)
		result.IsValid = false
		result.Error = &errMsg
		result.Summary = calculateSummary(result.SecurityIssues)
		return result
	}
	result.Header = header
	result.SecurityIssues = append(result.SecurityIssues, headerIssues...)

	// Decode and analyze payload
	payload, payloadIssues, err := decodePayload(parts[1], opts)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to decode payload: %v", err)
		result.IsValid = false
		result.Error = &errMsg
		result.Summary = calculateSummary(result.SecurityIssues)
		return result
	}
	result.Payload = payload
	result.SecurityIssues = append(result.SecurityIssues, payloadIssues...)

	// Analyze signature
	result.Signature = parts[2]
	signatureIssues := analyzeSignature(parts[2], header)
	result.SecurityIssues = append(result.SecurityIssues, signatureIssues...)

	// Update token info
	result.TokenInfo.SignaturePresent = len(parts[2]) > 0
	result.TokenInfo.HasSignature = len(parts[2]) > 0 && header.Algorithm != "none"
	updateTokenInfo(result.TokenInfo, payload)

	// Check expiration-related issues
	if opts.CheckExpiration {
		expirationIssues := checkExpiration(payload, result.TokenInfo, opts)
		result.SecurityIssues = append(result.SecurityIssues, expirationIssues...)
	}

	// Calculate summary
	result.Summary = calculateSummary(result.SecurityIssues)

	return result
}

func decodeHeader(encoded string) (*models.JWTHeader, []models.SecurityIssue, error) {
	var issues []models.SecurityIssue

	decoded, err := base64URLDecode(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	var header models.JWTHeader
	if err := json.Unmarshal(decoded, &header); err != nil {
		return nil, nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	// Check algorithm
	issues = append(issues, checkAlgorithm(header.Algorithm)...)

	// Check for dangerous header fields
	if header.JKU != nil && *header.JKU != "" {
		issues = append(issues, createIssue("JKU_PRESENT", "jku"))
	}
	if header.JWK != nil && *header.JWK != "" {
		issues = append(issues, createIssue("JWK_EMBEDDED", "jwk"))
	}
	if header.X5U != nil && *header.X5U != "" {
		issues = append(issues, createIssue("X5U_PRESENT", "x5u"))
	}
	if header.X5C != nil && *header.X5C != "" {
		issues = append(issues, createIssue("X5C_PRESENT", "x5c"))
	}

	// Check for KID injection
	if header.KeyID != nil && *header.KeyID != "" {
		if containsSuspiciousChars(*header.KeyID) {
			issues = append(issues, createIssue("KID_INJECTION", "kid"))
		}
	}

	return &header, issues, nil
}

func decodePayload(encoded string, opts Options) (*models.DecodedPayload, []models.SecurityIssue, error) {
	var issues []models.SecurityIssue

	decoded, err := base64URLDecode(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	var rawClaims map[string]interface{}
	if err := json.Unmarshal(decoded, &rawClaims); err != nil {
		return nil, nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	payload := &models.DecodedPayload{
		RawClaims:    rawClaims,
		CustomClaims: make(map[string]interface{}),
	}

	// Extract standard claims
	standardClaimKeys := map[string]bool{
		"iss": true, "sub": true, "aud": true,
		"exp": true, "nbf": true, "iat": true, "jti": true,
	}

	for key, value := range rawClaims {
		if !standardClaimKeys[key] {
			payload.CustomClaims[key] = value
		}
	}

	// Parse standard claims
	if iss, ok := rawClaims["iss"].(string); ok {
		payload.StandardClaims.Issuer = &iss
	} else {
		issues = append(issues, createIssue("NO_ISSUER", "iss"))
	}

	if sub, ok := rawClaims["sub"].(string); ok {
		payload.StandardClaims.Subject = &sub
	} else {
		issues = append(issues, createIssue("NO_SUBJECT", "sub"))
	}

	if aud, ok := rawClaims["aud"].(string); ok {
		payload.StandardClaims.Audience = &aud
	} else if _, ok := rawClaims["aud"].([]interface{}); ok {
		// Audience can also be an array
		audStr := "array"
		payload.StandardClaims.Audience = &audStr
	} else {
		issues = append(issues, createIssue("NO_AUDIENCE", "aud"))
	}

	if exp, ok := rawClaims["exp"].(float64); ok {
		expInt := int64(exp)
		payload.StandardClaims.ExpirationTime = &expInt
	} else {
		issues = append(issues, createIssue("NO_EXPIRATION", "exp"))
	}

	if nbf, ok := rawClaims["nbf"].(float64); ok {
		nbfInt := int64(nbf)
		payload.StandardClaims.NotBefore = &nbfInt
	}

	if iat, ok := rawClaims["iat"].(float64); ok {
		iatInt := int64(iat)
		payload.StandardClaims.IssuedAt = &iatInt
	} else {
		issues = append(issues, createIssue("NO_IAT", "iat"))
	}

	if jti, ok := rawClaims["jti"].(string); ok {
		payload.StandardClaims.JWTID = &jti
	} else {
		issues = append(issues, createIssue("NO_JTI", "jti"))
	}

	// Check for sensitive data
	sensitiveIssues := checkSensitiveData(rawClaims, opts.SensitiveFields)
	issues = append(issues, sensitiveIssues...)

	return payload, issues, nil
}

func analyzeSignature(signature string, header *models.JWTHeader) []models.SecurityIssue {
	var issues []models.SecurityIssue

	if signature == "" || (header != nil && strings.ToLower(header.Algorithm) == "none") {
		if header == nil || strings.ToLower(header.Algorithm) != "none" {
			issues = append(issues, createIssue("EMPTY_SIGNATURE", "signature"))
		}
	}

	return issues
}

func checkAlgorithm(alg string) []models.SecurityIssue {
	var issues []models.SecurityIssue

	if alg == "" {
		issues = append(issues, createIssue("ALG_MISSING", "alg"))
		return issues
	}

	algLower := strings.ToLower(alg)

	// Check for 'none' algorithm
	if algLower == "none" {
		issues = append(issues, createIssue("ALG_NONE", "alg"))
		return issues
	}

	// Known algorithms
	knownAlgorithms := map[string]bool{
		"hs256": true, "hs384": true, "hs512": true,
		"rs256": true, "rs384": true, "rs512": true,
		"es256": true, "es384": true, "es512": true,
		"ps256": true, "ps384": true, "ps512": true,
	}

	if !knownAlgorithms[algLower] {
		issues = append(issues, createIssue("ALG_UNKNOWN", "alg"))
		return issues
	}

	// Check for symmetric algorithms
	if strings.HasPrefix(algLower, "hs") {
		issues = append(issues, createIssue("ALG_SYMMETRIC", "alg"))
		if algLower == "hs256" {
			issues = append(issues, createIssue("ALG_WEAK_HMAC", "alg"))
		}
	}

	return issues
}

func checkExpiration(payload *models.DecodedPayload, tokenInfo *models.TokenInfo, opts Options) []models.SecurityIssue {
	var issues []models.SecurityIssue
	now := time.Now()

	// Check if token is expired
	if payload.StandardClaims.ExpirationTime != nil {
		expTime := time.Unix(*payload.StandardClaims.ExpirationTime, 0)
		tokenInfo.ExpiresAt = &expTime

		if now.After(expTime) {
			tokenInfo.IsExpired = true
			diff := now.Sub(expTime)
			diffStr := formatDuration(diff)
			tokenInfo.TimeSinceExpiry = &diffStr
			issues = append(issues, createIssue("TOKEN_EXPIRED", "exp"))
		} else {
			diff := expTime.Sub(now)
			diffStr := formatDuration(diff)
			tokenInfo.TimeUntilExpiry = &diffStr
		}

		// Check token lifetime
		if payload.StandardClaims.IssuedAt != nil {
			iatTime := time.Unix(*payload.StandardClaims.IssuedAt, 0)
			tokenInfo.IssuedAt = &iatTime
			lifetime := expTime.Sub(iatTime)
			lifetimeStr := formatDuration(lifetime)
			tokenInfo.TokenLifetime = &lifetimeStr

			if lifetime > opts.MaxTokenLifetime {
				issues = append(issues, createIssue("VERY_LONG_EXPIRATION", "exp"))
			} else if lifetime > opts.WarnTokenLifetime {
				issues = append(issues, createIssue("LONG_EXPIRATION", "exp"))
			}
		}
	}

	// Check not before
	if payload.StandardClaims.NotBefore != nil {
		nbfTime := time.Unix(*payload.StandardClaims.NotBefore, 0)
		tokenInfo.NotBefore = &nbfTime
		if now.Before(nbfTime) {
			tokenInfo.IsNotYetValid = true
			issues = append(issues, createIssue("NOT_YET_VALID", "nbf"))
		}
	}

	// Check issued at in future
	if payload.StandardClaims.IssuedAt != nil {
		iatTime := time.Unix(*payload.StandardClaims.IssuedAt, 0)
		if iatTime.After(now.Add(5 * time.Minute)) { // Allow 5 min clock skew
			issues = append(issues, createIssue("IAT_FUTURE", "iat"))
		}
	}

	return issues
}

func checkSensitiveData(claims map[string]interface{}, sensitiveFields []string) []models.SecurityIssue {
	var issues []models.SecurityIssue

	for key := range claims {
		keyLower := strings.ToLower(key)
		for _, sensitive := range sensitiveFields {
			if strings.Contains(keyLower, sensitive) {
				issue := createIssue("SENSITIVE_DATA", key)
				issue.Description = fmt.Sprintf("The claim '%s' may contain sensitive data", key)
				issues = append(issues, issue)
				break
			}
		}
	}

	return issues
}

func createIssue(code string, affectedField string) models.SecurityIssue {
	check := models.GetCheckByCode(code)
	if check == nil {
		return models.SecurityIssue{
			Code:          code,
			Title:         "Unknown Issue",
			Description:   "An unknown security issue was detected",
			Severity:      models.SeverityInfo,
			AffectedField: affectedField,
		}
	}

	return models.SecurityIssue{
		Code:           check.Code,
		Title:          check.Title,
		Description:    check.Description,
		Severity:       check.Severity,
		Recommendation: check.Recommendation,
		AffectedField:  affectedField,
	}
}

func calculateSummary(issues []models.SecurityIssue) *models.AnalysisSummary {
	summary := &models.AnalysisSummary{
		TotalIssues: len(issues),
	}

	for _, issue := range issues {
		switch issue.Severity {
		case models.SeverityCritical:
			summary.CriticalCount++
		case models.SeverityHigh:
			summary.HighCount++
		case models.SeverityMedium:
			summary.MediumCount++
		case models.SeverityLow:
			summary.LowCount++
		case models.SeverityInfo:
			summary.InfoCount++
		}
	}

	// Calculate security score (0-100)
	// Deduct points based on severity
	score := 100
	score -= summary.CriticalCount * 25
	score -= summary.HighCount * 15
	score -= summary.MediumCount * 10
	score -= summary.LowCount * 5
	score -= summary.InfoCount * 2

	if score < 0 {
		score = 0
	}

	summary.SecurityScore = fmt.Sprintf("%d%%", score)

	// Determine overall rating
	switch {
	case summary.CriticalCount > 0:
		summary.OverallRating = "Critical"
	case summary.HighCount > 0:
		summary.OverallRating = "Poor"
	case summary.MediumCount > 0:
		summary.OverallRating = "Fair"
	case summary.LowCount > 0 || summary.InfoCount > 0:
		summary.OverallRating = "Good"
	default:
		summary.OverallRating = "Excellent"
	}

	return summary
}

func base64URLDecode(encoded string) ([]byte, error) {
	// Add padding if necessary
	switch len(encoded) % 4 {
	case 2:
		encoded += "=="
	case 3:
		encoded += "="
	}

	return base64.URLEncoding.DecodeString(encoded)
}

func containsSuspiciousChars(s string) bool {
	// Check for SQL injection, path traversal, or command injection patterns
	patterns := []string{
		`['";]`,           // SQL injection
		`\.\./`,           // Path traversal
		`[|&;$]`,          // Command injection
		`<[^>]*>`,         // HTML/XML injection
		`\x00`,            // Null byte
	}

	for _, pattern := range patterns {
		matched, _ := regexp.MatchString(pattern, s)
		if matched {
			return true
		}
	}

	return false
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0f seconds", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.0f minutes", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1f hours", d.Hours())
	}
	days := d.Hours() / 24
	return fmt.Sprintf("%.1f days", days)
}

func updateTokenInfo(info *models.TokenInfo, payload *models.DecodedPayload) {
	if payload.StandardClaims.ExpirationTime != nil {
		expTime := time.Unix(*payload.StandardClaims.ExpirationTime, 0)
		info.ExpiresAt = &expTime
	}
	if payload.StandardClaims.IssuedAt != nil {
		iatTime := time.Unix(*payload.StandardClaims.IssuedAt, 0)
		info.IssuedAt = &iatTime
	}
	if payload.StandardClaims.NotBefore != nil {
		nbfTime := time.Unix(*payload.StandardClaims.NotBefore, 0)
		info.NotBefore = &nbfTime
	}
}
