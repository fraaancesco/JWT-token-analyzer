// Command jwtscan scans a project for JWTs and JWT-related code and prints a
// security report.
//
// Usage:
//
//	jwtscan [flags] [path]
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fraaancesco/jwt-token-analyzer/internal/report"
	"github.com/fraaancesco/jwt-token-analyzer/internal/scanner"
	"github.com/fraaancesco/jwt-token-analyzer/pkg/models"
)

// Exit codes.
const (
	exitOK       = 0
	exitError    = 1
	exitFindings = 2
)

// now and exit are variables so tests can replace them.
var (
	now  = time.Now
	exit = os.Exit
)

func main() {
	exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("jwtscan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "md", "report format: md or json")
	output := fs.String("o", "", "write the report to this file instead of stdout")
	exclude := fs.String("exclude", "", "comma-separated glob patterns to skip, added to the defaults")
	failOn := fs.String("fail-on", "", "exit with code 2 if a finding has this severity or higher (critical, high, medium, low, info)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: jwtscan [flags] [path]")
		fmt.Fprintln(stderr, "Scans a project for JWTs and JWT-related code and prints a security report.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return exitOK
		}
		return exitError
	}

	if *format != "md" && *format != "json" {
		fmt.Fprintf(stderr, "jwtscan: unknown format %q (use md or json)\n", *format)
		return exitError
	}
	threshold := models.Severity(strings.ToLower(*failOn))
	if *failOn != "" && threshold.Priority() < 1 {
		fmt.Fprintf(stderr, "jwtscan: unknown severity %q\n", *failOn)
		return exitError
	}

	root := "."
	if fs.NArg() > 0 {
		root = fs.Arg(0)
	}

	opts := scanner.DefaultOptions()
	for _, pattern := range strings.Split(*exclude, ",") {
		if pattern = strings.TrimSpace(pattern); pattern != "" {
			opts.Exclude = append(opts.Exclude, pattern)
		}
	}
	if *output != "" {
		// Do not scan a previous report.
		opts.Exclude = append(opts.Exclude, filepath.Base(*output))
	}

	res, err := scanner.Scan(root, opts)
	if err != nil {
		fmt.Fprintf(stderr, "jwtscan: %v\n", err)
		return exitError
	}

	out := stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(stderr, "jwtscan: %v\n", err)
			return exitError
		}
		defer f.Close()
		out = f
	}

	write := report.Markdown
	if *format == "json" {
		write = report.JSON
	}
	if err := write(out, res, now()); err != nil {
		fmt.Fprintf(stderr, "jwtscan: %v\n", err)
		return exitError
	}
	if *output != "" {
		fmt.Fprintf(stderr, "jwtscan: report written to %s (rating: %s)\n", *output, report.Rating(res.WorstSeverity()))
	}

	if *failOn != "" && res.WorstSeverity().Priority() >= threshold.Priority() {
		return exitFindings
	}
	return exitOK
}
