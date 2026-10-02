// Package report renders a scanner.Result as Markdown or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/fraaancesco/jwt-token-analyzer/internal/scanner"
	"github.com/fraaancesco/jwt-token-analyzer/pkg/models"
)

var severities = []models.Severity{
	models.SeverityCritical,
	models.SeverityHigh,
	models.SeverityMedium,
	models.SeverityLow,
	models.SeverityInfo,
}

// Rating converts the worst severity found into a human readable rating.
func Rating(worst models.Severity) string {
	switch worst {
	case models.SeverityCritical:
		return "Critical"
	case models.SeverityHigh:
		return "Poor"
	case models.SeverityMedium:
		return "Fair"
	case models.SeverityLow, models.SeverityInfo:
		return "Good"
	default:
		return "Excellent"
	}
}

// JSON writes the result as indented JSON.
func JSON(w io.Writer, res *scanner.Result, generatedAt time.Time) error {
	doc := struct {
		GeneratedAt string                  `json:"generated_at"`
		Rating      string                  `json:"rating"`
		Counts      map[models.Severity]int `json:"counts"`
		*scanner.Result
	}{
		GeneratedAt: generatedAt.UTC().Format(time.RFC3339),
		Rating:      Rating(res.WorstSeverity()),
		Counts:      res.CountBySeverity(),
		Result:      res,
	}
	data, _ := json.MarshalIndent(doc, "", "  ") // every field is serializable
	_, err := w.Write(append(data, '\n'))
	return err
}

// Markdown writes a complete, human readable report.
func Markdown(w io.Writer, res *scanner.Result, generatedAt time.Time) error {
	var b strings.Builder

	libraries, risks := splitFindings(res.Findings)
	counts := res.CountBySeverity()

	b.WriteString("# JWT Security Report\n\n")
	fmt.Fprintf(&b, "- **Project:** `%s`\n", res.Root)
	fmt.Fprintf(&b, "- **Generated:** %s\n", generatedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Files scanned:** %d (skipped: %d)\n", res.FilesScanned, res.FilesSkipped)
	fmt.Fprintf(&b, "- **Overall rating:** %s\n\n", Rating(res.WorstSeverity()))

	b.WriteString("## Summary\n\n")
	b.WriteString("| Severity | Count |\n|---|---|\n")
	for _, s := range severities {
		fmt.Fprintf(&b, "| %s | %d |\n", s, counts[s])
	}
	fmt.Fprintf(&b, "\nJWT libraries detected: %d. Risky code patterns: %d. Tokens found in the code: %d.\n\n",
		len(groupByRule(libraries)), len(risks), len(res.Tokens))

	writeStack(&b, libraries)
	writeRisks(&b, risks)
	writeTokens(&b, res.Tokens)
	writeChecklist(&b)

	_, err := io.WriteString(w, b.String())
	return err
}

func splitFindings(findings []scanner.Finding) (libraries, risks []scanner.Finding) {
	for _, f := range findings {
		if f.Severity == models.SeverityInfo && strings.HasPrefix(f.RuleID, "LIB_") {
			libraries = append(libraries, f)
		} else {
			risks = append(risks, f)
		}
	}
	return libraries, risks
}

type group struct {
	first    scanner.Finding
	findings []scanner.Finding
}

// groupByRule groups findings by rule, keeping the input order.
func groupByRule(findings []scanner.Finding) []group {
	var groups []group
	index := map[string]int{}
	for _, f := range findings {
		i, ok := index[f.RuleID]
		if !ok {
			i = len(groups)
			index[f.RuleID] = i
			groups = append(groups, group{first: f})
		}
		groups[i].findings = append(groups[i].findings, f)
	}
	return groups
}

func writeStack(b *strings.Builder, libraries []scanner.Finding) {
	b.WriteString("## JWT stack in use\n\n")
	groups := groupByRule(libraries)
	if len(groups) == 0 {
		b.WriteString("No known JWT library was detected. The project may implement JWT handling by hand: review it manually.\n\n")
		return
	}
	b.WriteString("| Library | Where | Notes |\n|---|---|---|\n")
	for _, g := range groups {
		fmt.Fprintf(b, "| %s | %s | %s |\n", g.first.Title, locations(g.findings), g.first.Recommendation)
	}
	b.WriteString("\n")
}

func writeRisks(b *strings.Builder, risks []scanner.Finding) {
	b.WriteString("## Risks found in the code\n\n")
	groups := groupByRule(risks)
	if len(groups) == 0 {
		b.WriteString("No risky JWT pattern was found in the source code.\n\n")
		return
	}
	for _, g := range groups {
		f := g.first
		fmt.Fprintf(b, "### [%s] %s (`%s`)\n\n", strings.ToUpper(f.Severity.String()), f.Title, f.RuleID)
		fmt.Fprintf(b, "%s.\n\n**Recommendation:** %s.\n\n", f.Description, f.Recommendation)
		b.WriteString("Occurrences:\n\n")
		for _, o := range g.findings {
			fmt.Fprintf(b, "- `%s:%d` — `%s`\n", o.File, o.Line, strings.ReplaceAll(o.Snippet, "`", "'"))
		}
		b.WriteString("\n")
	}
}

func writeTokens(b *strings.Builder, tokens []scanner.TokenFinding) {
	b.WriteString("## Tokens found in the code\n\n")
	if len(tokens) == 0 {
		b.WriteString("No hardcoded JWT was found.\n\n")
		return
	}
	b.WriteString("Hardcoded tokens are credentials: if any of them is real, revoke it and remove it from the git history.\n\n")

	for i, t := range tokens {
		a := t.Analysis
		fmt.Fprintf(b, "### Token %d: `%s`\n\n", i+1, t.Redacted)
		fmt.Fprintf(b, "- **Found in:** %s\n", locations(locationFindings(t.Locations)))

		if a.Error != nil {
			fmt.Fprintf(b, "- **Decoding error:** %s\n", *a.Error)
		}
		if a.Header != nil {
			fmt.Fprintf(b, "- **Algorithm:** `%s`, type: `%s`\n", a.Header.Algorithm, a.Header.Type)
		}
		if a.Payload != nil {
			fmt.Fprintf(b, "- **Claims:** %s\n", claimNames(a.Payload.RawClaims))
		}
		if info := a.TokenInfo; info != nil && info.ExpiresAt != nil {
			status := "valid"
			if info.IsExpired {
				status = "expired"
			}
			fmt.Fprintf(b, "- **Expires:** %s (%s)\n", info.ExpiresAt.UTC().Format(time.RFC3339), status)
		}
		if a.Summary != nil {
			fmt.Fprintf(b, "- **Score:** %s, rating: %s\n", a.Summary.SecurityScore, a.Summary.OverallRating)
		}
		b.WriteString("\n")

		if len(a.SecurityIssues) == 0 {
			b.WriteString("No issue found in this token.\n\n")
			continue
		}
		b.WriteString("| Severity | Check | Field | Recommendation |\n|---|---|---|---|\n")
		issues := append([]models.SecurityIssue(nil), a.SecurityIssues...)
		sort.SliceStable(issues, func(i, j int) bool {
			return issues[i].Severity.Priority() > issues[j].Severity.Priority()
		})
		for _, issue := range issues {
			fmt.Fprintf(b, "| %s | %s (`%s`) | %s | %s |\n",
				issue.Severity, issue.Title, issue.Code, issue.AffectedField, issue.Recommendation)
		}
		b.WriteString("\n")
	}
}

func writeChecklist(b *strings.Builder) {
	b.WriteString(`## Checklist to review by hand

The scanner works on text patterns: confirm these points by reading the code.

- [ ] Signatures are always verified with a key from a trusted source, never with a key taken from the token.
- [ ] The accepted algorithms are an explicit allow-list (no ` + "`none`" + `, no mixing HMAC and RSA with the same key).
- [ ] ` + "`exp`, `iss` and `aud`" + ` are validated on every request; clock skew is small (minutes).
- [ ] Access tokens are short-lived; refresh tokens are rotated and can be revoked.
- [ ] Secrets and private keys come from a secret manager or environment, are at least 256 bits and can be rotated.
- [ ] Tokens are not logged, not put in URLs, and are stored in HttpOnly/Secure/SameSite cookies on the web.
- [ ] Claims contain no passwords, secrets or unnecessary personal data.
- [ ] Logout and password change invalidate the existing tokens (deny-list on ` + "`jti`" + ` or short lifetimes).

## Method and limits

Every text file of the project was matched against the rules of the scanner and every string shaped like a JWT
was decoded and analyzed (without verifying its signature). Matches are hints, not proof: false positives are
possible, and logic errors in the authentication flow need a manual review.
`)
}

func locationFindings(locs []scanner.Location) []scanner.Finding {
	findings := make([]scanner.Finding, len(locs))
	for i, l := range locs {
		findings[i].Location = l
	}
	return findings
}

func locations(findings []scanner.Finding) string {
	const max = 5
	parts := make([]string, 0, max)
	for i, f := range findings {
		if i == max {
			parts = append(parts, fmt.Sprintf("and %d more", len(findings)-max))
			break
		}
		parts = append(parts, fmt.Sprintf("`%s:%d`", f.File, f.Line))
	}
	return strings.Join(parts, ", ")
}

func claimNames(claims map[string]any) string {
	if len(claims) == 0 {
		return "none"
	}
	names := make([]string, 0, len(claims))
	for name := range claims {
		names = append(names, "`"+name+"`")
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
