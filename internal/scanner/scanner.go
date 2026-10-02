// Package scanner walks a project tree looking for JWTs and for the way the
// code creates, verifies and stores them.
package scanner

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/fraaancesco/jwt-token-analyzer/internal/analyzer"
	"github.com/fraaancesco/jwt-token-analyzer/pkg/models"
)

// DefaultExcludes are directory and file names skipped during a scan.
var DefaultExcludes = []string{
	".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build", "target",
	".venv", "venv", "__pycache__", ".next", ".nuxt", "coverage", ".idea", ".vscode",
}

// DefaultMaxFileSize is the size above which files are skipped.
const DefaultMaxFileSize int64 = 2 << 20 // 2 MiB

const maxSnippet = 160

// Options configures a scan.
type Options struct {
	// Exclude holds glob patterns matched against the base name and the
	// slash-separated path relative to the root.
	Exclude []string
	// MaxFileSize skips bigger files. Zero means DefaultMaxFileSize.
	MaxFileSize int64
	// Analyzer configures the analysis of the tokens found.
	Analyzer analyzer.Options
}

// DefaultOptions returns the options used by the CLI.
func DefaultOptions() Options {
	return Options{
		Exclude:     append([]string(nil), DefaultExcludes...),
		MaxFileSize: DefaultMaxFileSize,
		Analyzer:    analyzer.DefaultOptions(),
	}
}

// Location is a position inside the scanned project.
type Location struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// Finding is a match of a Rule in the source code.
type Finding struct {
	RuleID         string          `json:"rule_id"`
	Title          string          `json:"title"`
	Description    string          `json:"description"`
	Severity       models.Severity `json:"severity"`
	Recommendation string          `json:"recommendation"`
	Location
	Snippet string `json:"snippet"`
}

// TokenFinding is a JWT found in the project, with its analysis.
type TokenFinding struct {
	Redacted  string                `json:"token"`
	Locations []Location            `json:"locations"`
	Analysis  models.AnalysisResult `json:"analysis"`
}

// Result is the outcome of a scan.
type Result struct {
	Root         string         `json:"root"`
	FilesScanned int            `json:"files_scanned"`
	FilesSkipped int            `json:"files_skipped"`
	Findings     []Finding      `json:"findings"`
	Tokens       []TokenFinding `json:"tokens"`
}

// Scan walks root and returns every JWT-related finding.
func Scan(root string, opts Options) (*Result, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if opts.MaxFileSize <= 0 {
		opts.MaxFileSize = DefaultMaxFileSize
	}

	s := &scan{
		root:   abs,
		opts:   opts,
		result: &Result{Root: abs, Findings: []Finding{}, Tokens: []TokenFinding{}},
		tokens: map[string]int{},
	}

	// visit never returns an error (unreadable entries are only counted), so
	// neither does the walk.
	if info.IsDir() {
		_ = filepath.WalkDir(abs, s.visit)
	} else {
		s.root = filepath.Dir(abs)
		_ = s.visit(abs, fs.FileInfoToDirEntry(info), nil)
	}

	s.finish()
	return s.result, nil
}

type scan struct {
	root   string
	opts   Options
	result *Result
	tokens map[string]int // raw token -> index in result.Tokens
}

func (s *scan) visit(path string, d fs.DirEntry, err error) error {
	if err != nil {
		// Unreadable entries are counted and skipped, the scan goes on.
		s.result.FilesSkipped++
		if d != nil && d.IsDir() {
			return filepath.SkipDir
		}
		return nil
	}

	rel := s.rel(path)
	if rel != "." && s.excluded(rel) {
		if d.IsDir() {
			return filepath.SkipDir
		}
		return nil
	}
	if d.IsDir() || !d.Type().IsRegular() {
		return nil
	}

	info, err := d.Info()
	if err != nil || info.Size() > s.opts.MaxFileSize {
		s.result.FilesSkipped++
		return nil
	}

	content, err := os.ReadFile(path)
	if err != nil || isBinary(content) {
		s.result.FilesSkipped++
		return nil
	}

	s.result.FilesScanned++
	s.scanContent(rel, content)
	return nil
}

func (s *scan) rel(path string) string {
	// Both paths are absolute and path is inside root, so Rel cannot fail.
	rel, _ := filepath.Rel(s.root, path)
	return filepath.ToSlash(rel)
}

func (s *scan) excluded(rel string) bool {
	base := filepath.Base(rel)
	for _, pattern := range s.opts.Exclude {
		if ok, _ := filepath.Match(pattern, base); ok {
			return true
		}
		if ok, _ := filepath.Match(pattern, rel); ok {
			return true
		}
	}
	return false
}

func (s *scan) scanContent(file string, content []byte) {
	for i, line := range strings.Split(string(content), "\n") {
		loc := Location{File: file, Line: i + 1}

		for _, rule := range Rules {
			if rule.Pattern.MatchString(line) {
				s.result.Findings = append(s.result.Findings, Finding{
					RuleID:         rule.ID,
					Title:          rule.Title,
					Description:    rule.Description,
					Severity:       rule.Severity,
					Recommendation: rule.Recommendation,
					Location:       loc,
					Snippet:        snippet(line, rule.ID == "CODE_HARDCODED_SECRET"),
				})
			}
		}

		for _, token := range tokenPattern.FindAllString(line, -1) {
			s.addToken(token, loc)
		}
	}
}

func (s *scan) addToken(token string, loc Location) {
	if idx, ok := s.tokens[token]; ok {
		s.result.Tokens[idx].Locations = append(s.result.Tokens[idx].Locations, loc)
		return
	}

	analysis := analyzer.Analyze(token, s.opts.Analyzer)
	// Never put the full token (and therefore a usable credential) in a report.
	analysis.Token = Redact(token)
	analysis.Signature = Redact(analysis.Signature)

	s.tokens[token] = len(s.result.Tokens)
	s.result.Tokens = append(s.result.Tokens, TokenFinding{
		Redacted:  Redact(token),
		Locations: []Location{loc},
		Analysis:  analysis,
	})
}

func (s *scan) finish() {
	sort.SliceStable(s.result.Findings, func(i, j int) bool {
		a, b := s.result.Findings[i], s.result.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity.Priority() > b.Severity.Priority()
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
}

// Redact keeps only the beginning and the end of a secret value.
func Redact(value string) string {
	if len(value) <= 16 {
		return strings.Repeat("*", len(value))
	}
	return fmt.Sprintf("%s...%s", value[:10], value[len(value)-4:])
}

var quotedValue = regexp.MustCompile(`(['"])([^'"]{4,})(['"])`)

func snippet(line string, maskSecrets bool) string {
	line = strings.TrimSpace(line)
	line = tokenPattern.ReplaceAllStringFunc(line, Redact)
	if maskSecrets {
		line = quotedValue.ReplaceAllStringFunc(line, func(m string) string {
			parts := quotedValue.FindStringSubmatch(m)
			return parts[1] + parts[2][:2] + "****" + parts[3]
		})
	}
	if len(line) > maxSnippet {
		line = line[:maxSnippet] + "..."
	}
	return line
}

func isBinary(content []byte) bool {
	head := content
	if len(head) > 8000 {
		head = head[:8000]
	}
	return bytes.IndexByte(head, 0) >= 0
}

// WorstSeverity returns the most severe level among findings and token issues.
func (r *Result) WorstSeverity() models.Severity {
	worst := models.SeverityOK
	raise := func(s models.Severity) {
		if s.Priority() > worst.Priority() {
			worst = s
		}
	}
	for _, f := range r.Findings {
		raise(f.Severity)
	}
	for _, t := range r.Tokens {
		for _, issue := range t.Analysis.SecurityIssues {
			raise(issue.Severity)
		}
	}
	return worst
}

// CountBySeverity counts the code findings and token issues per severity.
func (r *Result) CountBySeverity() map[models.Severity]int {
	counts := map[models.Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	for _, t := range r.Tokens {
		for _, issue := range t.Analysis.SecurityIssues {
			counts[issue.Severity]++
		}
	}
	return counts
}
