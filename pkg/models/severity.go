package models

// Severity represents the severity level of a security issue
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
	SeverityOK       Severity = "ok"
)

// String returns the string representation of the severity
func (s Severity) String() string {
	return string(s)
}

// Priority returns the priority rank of the severity (higher = more severe)
func (s Severity) Priority() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	case SeverityOK:
		return 0
	default:
		return -1
	}
}
