package scanner

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fraaancesco/jwt-token-analyzer/internal/testutil"
	"github.com/fraaancesco/jwt-token-analyzer/pkg/models"
)

func write(t *testing.T, root, name, content string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func testToken() string {
	return testutil.Token(map[string]any{"alg": "HS256", "typ": "JWT"}, map[string]any{"sub": "1", "iat": time.Now().Unix()}, "c2lnbmF0dXJlLXZhbHVl")
}

func rules(res *Result) map[string]int {
	m := map[string]int{}
	for _, f := range res.Findings {
		m[f.RuleID]++
	}
	return m
}

func TestRuleExamples(t *testing.T) {
	examples := map[string][]string{
		"LIB_GOLANG_JWT":             {`import "github.com/golang-jwt/jwt/v5"`},
		"LIB_DGRIJALVA_JWT":          {`"github.com/dgrijalva/jwt-go"`},
		"LIB_GO_JOSE":                {`"github.com/go-jose/go-jose/v4"`, `"github.com/lestrrat-go/jwx/v2/jwt"`},
		"LIB_NODE_JSONWEBTOKEN":      {`const jwt = require('jsonwebtoken')`, `import jwt from "jsonwebtoken"`, `"jsonwebtoken": "^9.0.0",`},
		"LIB_NODE_JOSE":              {`import { jwtVerify } from 'jose'`, `"jwt-decode": "^4.0.0"`},
		"LIB_PYJWT":                  {`import jwt`, `from jose import jwt`, `PyJWT==2.9.0`},
		"LIB_JAVA_JWT":               {`import io.jsonwebtoken.Jwts;`, `import com.auth0.jwt.JWT;`},
		"LIB_DOTNET_JWT":             {`using System.IdentityModel.Tokens.Jwt;`},
		"LIB_PHP_JWT":                {`use Firebase\JWT\JWT;`},
		"CODE_ALG_NONE":              {`jwt.verify(t, k, { algorithms: ['none'] })`, `{"alg":"none"}`, `jwt.SigningMethodNone`},
		"CODE_UNVERIFIED_PARSE":      {`parser.ParseUnverified(tok, claims)`, `jwt.decode(t, options={"verify_signature": False})`, `const p = jwt.decode(token)`, `jwtDecode(token)`},
		"CODE_IGNORE_EXPIRATION":     {`jwt.verify(t, k, { ignoreExpiration: true })`, `ValidateLifetime = false`},
		"CODE_NO_AUDIENCE_CHECK":     {`ValidateAudience = false`, `options={"verify_aud": False}`},
		"CODE_NO_SIGNING_KEY_CHECK":  {`ValidateIssuerSigningKey = false`},
		"CODE_HARDCODED_SECRET":      {`const JWT_SECRET = "supersecret"`, `jwt.sign(payload, 'changeme')`, `return []byte("my-secret"), nil`},
		"CODE_TOKEN_IN_LOCALSTORAGE": {`localStorage.setItem("access_token", t)`},
		"CODE_TOKEN_IN_URL":          {"fetch(`/api?access_token=${t}`)"},
		"CODE_TOKEN_LOGGED":          {`console.log("token", token)`, `log.Printf("auth %s", req.Header.Authorization)`},
		"CODE_LONG_EXPIRY":           {`jwt.sign(p, k, { expiresIn: '30d' })`, `timedelta(days=30)`},
	}
	for _, rule := range Rules {
		lines, ok := examples[rule.ID]
		if !ok {
			t.Errorf("rule %s has no example", rule.ID)
			continue
		}
		for _, line := range lines {
			if !rule.Pattern.MatchString(line) {
				t.Errorf("rule %s does not match %q", rule.ID, line)
			}
		}
	}
}

func TestRulesIgnoreSafeCode(t *testing.T) {
	safe := []string{
		`if header.Algorithm == "none" { return errNone }`,
		`log.Printf("Starting JWT Token Analyzer on %s", addr)`,
		`jwt.verify(token, publicKey, { algorithms: ['RS256'] })`,
		`secret := os.Getenv("JWT_SECRET")`,
	}
	for _, line := range safe {
		for _, rule := range Rules {
			if rule.Severity != models.SeverityInfo && rule.Pattern.MatchString(line) {
				t.Errorf("rule %s matches safe line %q", rule.ID, line)
			}
		}
	}
}

func TestScanProject(t *testing.T) {
	root := t.TempDir()
	token := testToken()
	write(t, root, "src/auth.js", strings.Join([]string{
		`const jwt = require('jsonwebtoken')`,
		`const JWT_SECRET = "supersecret"`,
		`jwt.verify(t, JWT_SECRET, { algorithms: ['none'] })`,
		`const demo = "` + token + `"`,
	}, "\n"))
	write(t, root, "README.md", "Example: "+token+"\n")
	write(t, root, "node_modules/lib/index.js", `const JWT_SECRET = "ignored"`)
	write(t, root, "fixtures/skip.txt", `const JWT_SECRET = "ignored"`)
	write(t, root, "image.png", "\x89PNG\x00\x00"+token)

	opts := DefaultOptions()
	opts.Exclude = append(opts.Exclude, "fixtures/*")
	opts.MaxFileSize = 0 // falls back to DefaultMaxFileSize
	res, err := Scan(root, opts)
	if err != nil {
		t.Fatal(err)
	}

	got := rules(res)
	if got["LIB_NODE_JSONWEBTOKEN"] != 1 || got["CODE_HARDCODED_SECRET"] != 1 || got["CODE_ALG_NONE"] != 1 {
		t.Errorf("unexpected findings %v", got)
	}
	if res.FilesScanned != 2 || res.FilesSkipped != 1 {
		t.Errorf("scanned %d, skipped %d", res.FilesScanned, res.FilesSkipped)
	}
	if res.Findings[0].Severity != models.SeverityCritical {
		t.Errorf("findings not sorted by severity: %+v", res.Findings[0])
	}

	if len(res.Tokens) != 1 || len(res.Tokens[0].Locations) != 2 {
		t.Fatalf("unexpected tokens %+v", res.Tokens)
	}
	tok := res.Tokens[0]
	if strings.Contains(tok.Redacted, token) || tok.Analysis.Token == token || tok.Analysis.Header.Algorithm != "HS256" {
		t.Errorf("token not redacted or not analyzed: %+v", tok)
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Snippet, "supersecret") || strings.Contains(f.Snippet, token) {
			t.Errorf("secret leaked in snippet %q", f.Snippet)
		}
	}
}

func TestScanFileSizeLimit(t *testing.T) {
	root := t.TempDir()
	write(t, root, "big.txt", strings.Repeat("a", 64))
	write(t, root, "small.txt", "a")
	opts := DefaultOptions()
	opts.MaxFileSize = 32
	res, err := Scan(root, opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesScanned != 1 || res.FilesSkipped != 1 {
		t.Errorf("scanned %d, skipped %d", res.FilesScanned, res.FilesSkipped)
	}
}

func TestScanSingleFile(t *testing.T) {
	path := write(t, t.TempDir(), "main.go", `import "github.com/dgrijalva/jwt-go"`)
	res, err := Scan(path, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if rules(res)["LIB_DGRIJALVA_JWT"] != 1 || res.Findings[0].File != "main.go" {
		t.Errorf("unexpected result %+v", res.Findings)
	}
	if res.WorstSeverity() != models.SeverityHigh {
		t.Errorf("worst = %s", res.WorstSeverity())
	}
}

func TestScanSingleExcludedFile(t *testing.T) {
	path := write(t, t.TempDir(), "secret.go", `const JWT_SECRET = "abcdef"`)
	opts := DefaultOptions()
	opts.Exclude = []string{"secret.go"}
	res, err := Scan(path, opts)
	if err != nil || res.FilesScanned != 0 {
		t.Fatalf("excluded file scanned: %+v, %v", res, err)
	}
}

func TestScanErrors(t *testing.T) {
	if _, err := Scan(filepath.Join(t.TempDir(), "missing"), DefaultOptions()); err == nil {
		t.Error("expected an error for a missing path")
	}

	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(".", DefaultOptions()); err == nil {
		t.Error("expected an error when the working directory is gone")
	}
}

type fakeEntry struct {
	dir  bool
	info fs.FileInfo
	err  error
}

func (f fakeEntry) Name() string               { return "fake" }
func (f fakeEntry) IsDir() bool                { return f.dir }
func (f fakeEntry) Type() fs.FileMode          { return 0 }
func (f fakeEntry) Info() (fs.FileInfo, error) { return f.info, f.err }

func newScan(root string) *scan {
	return &scan{root: root, opts: Options{MaxFileSize: DefaultMaxFileSize}, result: &Result{}, tokens: map[string]int{}}
}

func TestVisitErrors(t *testing.T) {
	root := t.TempDir()
	s := newScan(root)
	walkErr := errors.New("permission denied")

	if err := s.visit(filepath.Join(root, "d"), fakeEntry{dir: true}, walkErr); err != filepath.SkipDir {
		t.Errorf("unreadable dir: got %v, want SkipDir", err)
	}
	if err := s.visit(filepath.Join(root, "f"), nil, walkErr); err != nil {
		t.Errorf("unreadable entry: got %v", err)
	}
	if err := s.visit(filepath.Join(root, "f"), fakeEntry{err: walkErr}, nil); err != nil {
		t.Errorf("info error: got %v", err)
	}

	// The file disappears between the directory listing and the read.
	path := write(t, root, "gone.txt", "x")
	info, _ := os.Stat(path)
	os.Remove(path)
	if err := s.visit(path, fakeEntry{info: info}, nil); err != nil {
		t.Errorf("read error: got %v", err)
	}

	if s.result.FilesSkipped != 4 || s.result.FilesScanned != 0 {
		t.Errorf("scanned %d, skipped %d", s.result.FilesScanned, s.result.FilesSkipped)
	}
}

func TestVisitSkipsSpecialFiles(t *testing.T) {
	root := t.TempDir()
	write(t, root, "target.txt", `const JWT_SECRET = "abcdef"`)
	if err := os.Symlink(filepath.Join(root, "target.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Skip(err)
	}
	res, err := Scan(root, DefaultOptions())
	if err != nil || res.FilesScanned != 1 {
		t.Fatalf("symlink scanned: %+v, %v", res, err)
	}
}

func TestRedactAndSnippet(t *testing.T) {
	if got := Redact("short"); got != "*****" {
		t.Errorf("Redact(short) = %q", got)
	}
	if got := Redact("0123456789abcdefXYZW"); got != "0123456789...XYZW" {
		t.Errorf("Redact(long) = %q", got)
	}
	long := strings.Repeat("x", 300)
	if got := snippet(long, false); len(got) != maxSnippet+3 {
		t.Errorf("snippet not truncated: %d", len(got))
	}
	if got := snippet(`  key = "abcdefgh"  `, true); got != `key = "ab****"` {
		t.Errorf("snippet = %q", got)
	}
}

func TestIsBinary(t *testing.T) {
	if isBinary([]byte("text")) || !isBinary([]byte("a\x00b")) {
		t.Error("wrong binary detection")
	}
	big := append([]byte(strings.Repeat("a", 9000)), 0)
	if isBinary(big) {
		t.Error("only the first 8000 bytes must be inspected")
	}
}

func TestCountsAndWorst(t *testing.T) {
	empty := &Result{}
	if empty.WorstSeverity() != models.SeverityOK || len(empty.CountBySeverity()) != 0 {
		t.Error("empty result must be OK")
	}
	res := &Result{
		Findings: []Finding{{Severity: models.SeverityLow}, {Severity: models.SeverityLow}},
		Tokens: []TokenFinding{{Analysis: models.AnalysisResult{SecurityIssues: []models.SecurityIssue{
			{Severity: models.SeverityCritical},
		}}}},
	}
	counts := res.CountBySeverity()
	if res.WorstSeverity() != models.SeverityCritical || counts[models.SeverityLow] != 2 || counts[models.SeverityCritical] != 1 {
		t.Errorf("worst %s, counts %v", res.WorstSeverity(), counts)
	}
}

func TestFindingsOrder(t *testing.T) {
	s := newScan(t.TempDir())
	s.result.Findings = []Finding{
		{Severity: models.SeverityLow, Location: Location{File: "a", Line: 1}},
		{Severity: models.SeverityHigh, Location: Location{File: "b", Line: 9}},
		{Severity: models.SeverityHigh, Location: Location{File: "b", Line: 2}},
		{Severity: models.SeverityHigh, Location: Location{File: "a", Line: 5}},
	}
	s.finish()
	var got []string
	for _, f := range s.result.Findings {
		got = append(got, fmt.Sprintf("%s:%s:%d", f.Severity, f.File, f.Line))
	}
	want := "high:a:5 high:b:2 high:b:9 low:a:1"
	if strings.Join(got, " ") != want {
		t.Errorf("order = %v, want %s", got, want)
	}
}
