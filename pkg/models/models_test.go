package models

import "testing"

func TestSeverity(t *testing.T) {
	cases := []struct {
		severity Severity
		priority int
	}{
		{SeverityCritical, 5},
		{SeverityHigh, 4},
		{SeverityMedium, 3},
		{SeverityLow, 2},
		{SeverityInfo, 1},
		{SeverityOK, 0},
		{Severity("unknown"), -1},
	}
	for _, c := range cases {
		if got := c.severity.Priority(); got != c.priority {
			t.Errorf("%s.Priority() = %d, want %d", c.severity, got, c.priority)
		}
		if got := c.severity.String(); got != string(c.severity) {
			t.Errorf("String() = %q, want %q", got, c.severity)
		}
	}
}

func TestGetCheckByCode(t *testing.T) {
	check := GetCheckByCode("ALG_NONE")
	if check == nil || check.Severity != SeverityCritical {
		t.Fatalf("GetCheckByCode(ALG_NONE) = %+v", check)
	}
	if GetCheckByCode("DOES_NOT_EXIST") != nil {
		t.Fatal("expected nil for an unknown code")
	}
}

func TestEveryCheckHasContent(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range SecurityChecks {
		if c.Code == "" || c.Title == "" || c.Description == "" || c.Recommendation == "" || c.Severity.Priority() < 1 {
			t.Errorf("incomplete check: %+v", c)
		}
		if seen[c.Code] {
			t.Errorf("duplicate check code %s", c.Code)
		}
		seen[c.Code] = true
	}
}
