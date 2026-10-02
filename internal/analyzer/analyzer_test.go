package analyzer

import (
	"strings"
	"testing"
	"time"

	"github.com/fraaancesco/jwt-token-analyzer/internal/testutil"
	"github.com/fraaancesco/jwt-token-analyzer/pkg/models"
)

func codes(issues []models.SecurityIssue) map[string]bool {
	m := map[string]bool{}
	for _, i := range issues {
		m[i.Code] = true
	}
	return m
}

func goodClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss": "https://issuer.example",
		"sub": "user-1",
		"aud": "api",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"nbf": now.Add(-time.Minute).Unix(),
		"jti": "abc",
	}
}

func TestAnalyzeGoodToken(t *testing.T) {
	token := testutil.Token(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "key-1"}, goodClaims(time.Now()), "sig")

	res := Analyze("  Bearer "+token+" ", DefaultOptions())
	if !res.IsValid || res.Error != nil {
		t.Fatalf("expected a valid result, got error %v", res.Error)
	}
	if res.Token != token {
		t.Errorf("bearer prefix not stripped: %q", res.Token)
	}
	if len(res.SecurityIssues) != 0 {
		t.Errorf("expected no issues, got %+v", res.SecurityIssues)
	}
	if res.Summary.OverallRating != "Excellent" || res.Summary.SecurityScore != "100%" {
		t.Errorf("unexpected summary %+v", res.Summary)
	}
	info := res.TokenInfo
	if !info.HasSignature || !info.SignaturePresent || info.IsExpired || info.TimeUntilExpiry == nil || info.NotBefore == nil {
		t.Errorf("unexpected token info %+v", info)
	}
	if *res.Payload.StandardClaims.Audience != "api" {
		t.Errorf("audience = %v", *res.Payload.StandardClaims.Audience)
	}
}

func TestAnalyzeMalformed(t *testing.T) {
	res := Analyze("a.b", DefaultOptions())
	if res.IsValid || res.Error == nil || !codes(res.SecurityIssues)["MALFORMED_TOKEN"] {
		t.Fatalf("unexpected result %+v", res)
	}
	if res.TokenInfo.PartsCount != 2 {
		t.Errorf("PartsCount = %d", res.TokenInfo.PartsCount)
	}
}

func TestAnalyzeDecodeErrors(t *testing.T) {
	validHeader := testutil.Encode(map[string]string{"alg": "HS256"})
	validPayload := testutil.Encode(map[string]string{"sub": "x"})
	cases := map[string]string{
		"header base64":  "!!!." + validPayload + ".sig",
		"header json":    testutil.Encode("not an object") + "." + validPayload + ".sig",
		"payload base64": validHeader + ".!!!.sig",
		"payload json":   validHeader + "." + testutil.Encode([]int{1}) + ".sig",
	}
	for name, token := range cases {
		res := Analyze(token, DefaultOptions())
		if res.IsValid || res.Error == nil || res.Summary == nil {
			t.Errorf("%s: expected an invalid result, got %+v", name, res)
		}
		part := strings.Fields(name)[0]
		if !strings.Contains(*res.Error, part) {
			t.Errorf("%s: error %q does not mention %s", name, *res.Error, part)
		}
	}
}

func TestAnalyzeDangerousHeader(t *testing.T) {
	header := map[string]any{
		"alg": "HS256",
		"jku": "https://evil.example/jwks.json",
		"jwk": map[string]any{"kty": "oct", "k": "AAAA"},
		"x5u": "https://evil.example/cert.pem",
		"x5c": []string{"MIIB..."},
		"kid": "../../dev/null",
	}
	res := Analyze(testutil.Token(header, map[string]any{"password": "x"}, ""), DefaultOptions())
	got := codes(res.SecurityIssues)
	for _, want := range []string{
		"ALG_SYMMETRIC", "ALG_WEAK_HMAC", "JKU_PRESENT", "JWK_EMBEDDED", "X5U_PRESENT", "X5C_PRESENT",
		"KID_INJECTION", "EMPTY_SIGNATURE", "SENSITIVE_DATA", "NO_EXPIRATION", "NO_IAT", "NO_ISSUER",
		"NO_SUBJECT", "NO_AUDIENCE", "NO_JTI",
	} {
		if !got[want] {
			t.Errorf("missing issue %s", want)
		}
	}
	if res.Summary.OverallRating != "Critical" || res.Summary.SecurityScore != "0%" {
		t.Errorf("unexpected summary %+v", res.Summary)
	}
	if res.TokenInfo.HasSignature || res.TokenInfo.SignaturePresent {
		t.Errorf("empty signature reported as present: %+v", res.TokenInfo)
	}
}

func TestAnalyzeExpiration(t *testing.T) {
	now := time.Now()
	opts := DefaultOptions()

	claims := goodClaims(now)
	claims["aud"] = []any{"a", "b"}
	claims["iat"] = now.Add(-10 * 24 * time.Hour).Unix()
	claims["exp"] = now.Add(-time.Hour).Unix()
	claims["nbf"] = now.Add(time.Hour).Unix()
	res := Analyze(testutil.Token(map[string]any{"alg": "ES256"}, claims, "sig"), opts)
	got := codes(res.SecurityIssues)
	if !got["TOKEN_EXPIRED"] || !got["VERY_LONG_EXPIRATION"] || !got["NOT_YET_VALID"] {
		t.Errorf("unexpected issues %v", got)
	}
	if !res.TokenInfo.IsExpired || res.TokenInfo.TimeSinceExpiry == nil || !res.TokenInfo.IsNotYetValid {
		t.Errorf("unexpected token info %+v", res.TokenInfo)
	}
	if *res.Payload.StandardClaims.Audience != "array" {
		t.Errorf("array audience not detected")
	}

	claims = goodClaims(now)
	claims["exp"] = now.Add(48 * time.Hour).Unix()
	got = codes(Analyze(testutil.Token(map[string]any{"alg": "PS256"}, claims, "sig"), opts).SecurityIssues)
	if !got["LONG_EXPIRATION"] || got["VERY_LONG_EXPIRATION"] {
		t.Errorf("expected LONG_EXPIRATION only, got %v", got)
	}

	claims = goodClaims(now)
	claims["iat"] = now.Add(time.Hour).Unix()
	claims["exp"] = now.Add(2 * time.Hour).Unix()
	got = codes(Analyze(testutil.Token(map[string]any{"alg": "RS512"}, claims, "sig"), opts).SecurityIssues)
	if !got["IAT_FUTURE"] {
		t.Errorf("expected IAT_FUTURE, got %v", got)
	}

	opts.CheckExpiration = false
	claims = goodClaims(now)
	claims["exp"] = now.Add(-time.Hour).Unix()
	got = codes(Analyze(testutil.Token(map[string]any{"alg": "RS256"}, claims, "sig"), opts).SecurityIssues)
	if got["TOKEN_EXPIRED"] {
		t.Error("expiration must not be checked when disabled")
	}
}

func TestCheckExpirationWithoutIssuedAt(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	payload := &models.DecodedPayload{StandardClaims: models.StandardClaims{ExpirationTime: &exp}}
	info := &models.TokenInfo{}
	if issues := checkExpiration(payload, info, DefaultOptions()); len(issues) != 0 {
		t.Errorf("unexpected issues %+v", issues)
	}
	if info.TokenLifetime != nil {
		t.Error("lifetime needs iat")
	}
}

func TestCheckAlgorithm(t *testing.T) {
	cases := map[string][]string{
		"":      {"ALG_MISSING"},
		"none":  {"ALG_NONE"},
		"NoNe":  {"ALG_NONE"},
		"HS999": {"ALG_UNKNOWN"},
		"HS256": {"ALG_SYMMETRIC", "ALG_WEAK_HMAC"},
		"HS512": {"ALG_SYMMETRIC"},
		"RS256": {},
	}
	for alg, want := range cases {
		got := checkAlgorithm(alg)
		if len(got) != len(want) {
			t.Errorf("%q: got %+v, want %v", alg, got, want)
			continue
		}
		for i, code := range want {
			if got[i].Code != code {
				t.Errorf("%q: issue %d = %s, want %s", alg, i, got[i].Code, code)
			}
		}
	}
}

func TestAnalyzeSignature(t *testing.T) {
	hs := &models.JWTHeader{Algorithm: "HS256"}
	none := &models.JWTHeader{Algorithm: "none"}
	cases := []struct {
		name      string
		signature string
		header    *models.JWTHeader
		want      int
	}{
		{"signed", "sig", hs, 0},
		{"empty", "", hs, 1},
		{"none algorithm", "", none, 0},
		{"none with signature", "sig", none, 0},
		{"no header", "", nil, 1},
		{"no header signed", "sig", nil, 0},
	}
	for _, c := range cases {
		if got := analyzeSignature(c.signature, c.header); len(got) != c.want {
			t.Errorf("%s: got %d issues, want %d", c.name, len(got), c.want)
		}
	}
}

func TestAnalyzeNoneAlgorithm(t *testing.T) {
	res := Analyze(testutil.Token(map[string]any{"alg": "none"}, goodClaims(time.Now()), ""), DefaultOptions())
	got := codes(res.SecurityIssues)
	if !got["ALG_NONE"] || got["EMPTY_SIGNATURE"] {
		t.Errorf("unexpected issues %v", got)
	}
}

func TestCreateIssueUnknownCode(t *testing.T) {
	issue := createIssue("NOPE", "field")
	if issue.Title != "Unknown Issue" || issue.Severity != models.SeverityInfo || issue.AffectedField != "field" {
		t.Errorf("unexpected issue %+v", issue)
	}
}

func TestCalculateSummaryRatings(t *testing.T) {
	issue := func(s models.Severity) models.SecurityIssue { return models.SecurityIssue{Severity: s} }
	cases := []struct {
		issues []models.SecurityIssue
		rating string
		score  string
	}{
		{nil, "Excellent", "100%"},
		{[]models.SecurityIssue{issue(models.SeverityInfo)}, "Good", "98%"},
		{[]models.SecurityIssue{issue(models.SeverityLow)}, "Good", "95%"},
		{[]models.SecurityIssue{issue(models.SeverityMedium)}, "Fair", "90%"},
		{[]models.SecurityIssue{issue(models.SeverityHigh)}, "Poor", "85%"},
		{[]models.SecurityIssue{issue(models.SeverityCritical), issue(models.SeverityOK)}, "Critical", "75%"},
	}
	for _, c := range cases {
		s := calculateSummary(c.issues)
		if s.OverallRating != c.rating || s.SecurityScore != c.score {
			t.Errorf("%v: got %s/%s, want %s/%s", c.issues, s.OverallRating, s.SecurityScore, c.rating, c.score)
		}
	}
}

func TestBase64URLDecode(t *testing.T) {
	for _, in := range []string{"YQ", "YWI", "YWJj"} {
		if _, err := base64URLDecode(in); err != nil {
			t.Errorf("%q: %v", in, err)
		}
	}
	if _, err := base64URLDecode("Y"); err == nil {
		t.Error("expected an error for an invalid length")
	}
}

func TestContainsSuspiciousChars(t *testing.T) {
	for _, s := range []string{"a'b", "../x", "a|b", "<script>", "a\x00b"} {
		if !containsSuspiciousChars(s) {
			t.Errorf("%q should be suspicious", s)
		}
	}
	if containsSuspiciousChars("key-2024_01") {
		t.Error("plain kid flagged as suspicious")
	}
}

func TestFormatDuration(t *testing.T) {
	cases := map[time.Duration]string{
		30 * time.Second: "30 seconds",
		5 * time.Minute:  "5 minutes",
		3 * time.Hour:    "3.0 hours",
		36 * time.Hour:   "1.5 days",
	}
	for d, want := range cases {
		if got := formatDuration(d); got != want {
			t.Errorf("formatDuration(%v) = %q, want %q", d, got, want)
		}
	}
}
