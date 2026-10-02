package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func project(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	src := "const jwt = require('jsonwebtoken')\nconst JWT_SECRET = \"supersecret\"\n"
	if err := os.WriteFile(filepath.Join(root, "auth.js"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "legacy.js"), []byte("jwt.verify(t, k, { algorithms: ['none'] })\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func runCLI(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestMarkdownToStdout(t *testing.T) {
	code, out, _ := runCLI(project(t))
	if code != exitOK || !strings.Contains(out, "# JWT Security Report") || !strings.Contains(out, "CODE_HARDCODED_SECRET") {
		t.Fatalf("code %d, output:\n%s", code, out)
	}
}

func TestJSONWithExclude(t *testing.T) {
	code, out, _ := runCLI("-format", "json", "-exclude", " legacy.js , ", project(t))
	if code != exitOK {
		t.Fatalf("code %d", code)
	}
	var doc struct {
		Rating   string `json:"rating"`
		Findings []struct {
			RuleID string `json:"rule_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	for _, f := range doc.Findings {
		if f.RuleID == "CODE_ALG_NONE" {
			t.Error("excluded file was scanned")
		}
	}
	if doc.Rating != "Poor" {
		t.Errorf("rating = %s", doc.Rating)
	}
}

func TestOutputFileAndFailOn(t *testing.T) {
	root := project(t)
	out := filepath.Join(root, "jwt-report.md")
	if err := os.WriteFile(out, []byte("old report with JWT_SECRET = \"zzzzzz\""), 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runCLI("-o", out, "-fail-on", "HIGH", root)
	if code != exitFindings || stdout != "" || !strings.Contains(stderr, "report written to") {
		t.Fatalf("code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "jwt-report.md:") {
		t.Error("the previous report must not be scanned")
	}
}

func TestFailOnNotReached(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "a.go"), []byte(`import "github.com/golang-jwt/jwt/v5"`), 0o644)
	if code, _, _ := runCLI("-fail-on", "low", root); code != exitOK {
		t.Fatalf("code %d, want %d", code, exitOK)
	}
}

func TestErrors(t *testing.T) {
	cases := [][]string{
		{"-format", "xml"},
		{"-fail-on", "severe"},
		{"-unknown"},
		{filepath.Join(t.TempDir(), "missing")},
		{"-o", filepath.Join(t.TempDir(), "missing-dir", "r.md"), t.TempDir()},
	}
	for _, args := range cases {
		if code, _, stderr := runCLI(args...); code != exitError || stderr == "" {
			t.Errorf("%v: code %d, stderr %q", args, code, stderr)
		}
	}
}

func TestWriteError(t *testing.T) {
	var stderr bytes.Buffer
	if code := run([]string{t.TempDir()}, failingWriter{}, &stderr); code != exitError || !strings.Contains(stderr.String(), "broken pipe") {
		t.Fatalf("code %d, stderr %q", code, stderr.String())
	}
}

func TestHelp(t *testing.T) {
	code, _, stderr := runCLI("-h")
	if code != exitOK || !strings.Contains(stderr, "Usage: jwtscan") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
}

func TestDefaultPathAndMain(t *testing.T) {
	t.Chdir(project(t))
	oldExit, oldNow, oldArgs := exit, now, os.Args
	t.Cleanup(func() { exit, now, os.Args = oldExit, oldNow, oldArgs })

	now = func() time.Time { return time.Unix(0, 0) }
	os.Args = []string{"jwtscan", "-o", "report.md"}
	got := -1
	exit = func(code int) { got = code }

	main()
	if got != exitOK {
		t.Fatalf("exit code %d", got)
	}
	data, err := os.ReadFile("report.md")
	if err != nil || !strings.Contains(string(data), "1970-01-01T00:00:00Z") {
		t.Fatalf("report not written: %v", err)
	}
}
