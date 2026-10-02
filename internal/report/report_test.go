package report

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fraaancesco/jwt-token-analyzer/internal/scanner"
	"github.com/fraaancesco/jwt-token-analyzer/pkg/models"
)

var date = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func sampleResult() *scanner.Result {
	exp := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	future := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	errMsg := "Failed to decode payload"
	lib := scanner.Finding{RuleID: "LIB_NODE_JSONWEBTOKEN", Title: "Node.js library: jsonwebtoken", Severity: models.SeverityInfo, Recommendation: "Pin algorithms"}
	risk := scanner.Finding{RuleID: "CODE_ALG_NONE", Title: "'none' algorithm", Description: "desc", Severity: models.SeverityCritical, Recommendation: "rec", Snippet: "alg: `none`"}

	var findings []scanner.Finding
	for i := 1; i <= 7; i++ {
		f := lib
		f.Location = scanner.Location{File: "package.json", Line: i}
		findings = append(findings, f)
	}
	risk.Location = scanner.Location{File: "auth.js", Line: 3}
	findings = append(findings, risk)

	return &scanner.Result{
		Root:         "/project",
		FilesScanned: 10,
		FilesSkipped: 1,
		Findings:     findings,
		Tokens: []scanner.TokenFinding{
			{
				Redacted:  "eyJhbGciOi...abcd",
				Locations: []scanner.Location{{File: "README.md", Line: 4}},
				Analysis: models.AnalysisResult{
					Header:    &models.JWTHeader{Algorithm: "HS256", Type: "JWT"},
					Payload:   &models.DecodedPayload{RawClaims: map[string]any{"sub": "1", "exp": 1}},
					TokenInfo: &models.TokenInfo{ExpiresAt: &exp, IsExpired: true},
					Summary:   &models.AnalysisSummary{SecurityScore: "50%", OverallRating: "Poor"},
					SecurityIssues: []models.SecurityIssue{
						{Code: "NO_JTI", Title: "Missing JWT ID", Severity: models.SeverityLow, AffectedField: "jti"},
						{Code: "TOKEN_EXPIRED", Title: "Token Has Expired", Severity: models.SeverityHigh, AffectedField: "exp"},
					},
				},
			},
			{
				Redacted:  "eyJhbGciOi...efgh",
				Locations: []scanner.Location{{File: "a.txt", Line: 1}},
				Analysis: models.AnalysisResult{
					Header:    &models.JWTHeader{Algorithm: "RS256"},
					Payload:   &models.DecodedPayload{},
					TokenInfo: &models.TokenInfo{ExpiresAt: &future},
				},
			},
			{
				Redacted:  "eyJhbGciOi...ijkl",
				Locations: []scanner.Location{{File: "b.txt", Line: 2}},
				Analysis:  models.AnalysisResult{Error: &errMsg, TokenInfo: &models.TokenInfo{}},
			},
		},
	}
}

func TestMarkdown(t *testing.T) {
	var b strings.Builder
	if err := Markdown(&b, sampleResult(), date); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"# JWT Security Report",
		"- **Generated:** 2026-10-02T12:00:00Z",
		"- **Overall rating:** Critical",
		"| critical | 1 |",
		"| high | 1 |",
		"JWT libraries detected: 1. Risky code patterns: 1. Tokens found in the code: 3.",
		"| Node.js library: jsonwebtoken | `package.json:1`, `package.json:2`, `package.json:3`, `package.json:4`, `package.json:5`, and 2 more | Pin algorithms |",
		"### [CRITICAL] 'none' algorithm (`CODE_ALG_NONE`)",
		"- `auth.js:3` — `alg: 'none'`",
		"### Token 1: `eyJhbGciOi...abcd`",
		"- **Claims:** `exp`, `sub`",
		"- **Expires:** 2020-01-01T00:00:00Z (expired)",
		"- **Expires:** 2030-01-01T00:00:00Z (valid)",
		"- **Claims:** none",
		"- **Decoding error:** Failed to decode payload",
		"No issue found in this token.",
		"| high | Token Has Expired (`TOKEN_EXPIRED`) | exp |",
		"## Checklist to review by hand",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report does not contain %q", want)
		}
	}
	if strings.Index(out, "TOKEN_EXPIRED") > strings.Index(out, "NO_JTI") {
		t.Error("token issues must be sorted by severity")
	}
}

func TestMarkdownEmpty(t *testing.T) {
	var b strings.Builder
	res := &scanner.Result{Root: "/empty"}
	if err := Markdown(&b, res, date); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Overall rating:** Excellent", "No known JWT library", "No risky JWT pattern", "No hardcoded JWT"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("empty report does not contain %q", want)
		}
	}
}

func TestJSON(t *testing.T) {
	var b strings.Builder
	if err := JSON(&b, sampleResult(), date); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(b.String()), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["rating"] != "Critical" || doc["generated_at"] != "2026-10-02T12:00:00Z" || doc["root"] != "/project" {
		t.Errorf("unexpected document %v", doc)
	}
}

func TestWriteErrors(t *testing.T) {
	if err := Markdown(failingWriter{}, sampleResult(), date); err == nil {
		t.Error("Markdown: expected an error")
	}
	if err := JSON(failingWriter{}, sampleResult(), date); err == nil {
		t.Error("JSON: expected an error")
	}
}

func TestRating(t *testing.T) {
	cases := map[models.Severity]string{
		models.SeverityCritical: "Critical",
		models.SeverityHigh:     "Poor",
		models.SeverityMedium:   "Fair",
		models.SeverityLow:      "Good",
		models.SeverityInfo:     "Good",
		models.SeverityOK:       "Excellent",
	}
	for s, want := range cases {
		if got := Rating(s); got != want {
			t.Errorf("Rating(%s) = %s, want %s", s, got, want)
		}
	}
}
