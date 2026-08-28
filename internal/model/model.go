package model

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionWarn  Action = "warn"
	ActionBlock Action = "block"
)

type Finding struct {
	ID       string   `json:"id"`
	Analyzer string   `json:"analyzer"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Message  string   `json:"message"`
	Path     string   `json:"path,omitempty"`
	Line     int      `json:"line,omitempty"`
	Evidence string   `json:"evidence,omitempty"`
}

type EvaluatedFinding struct {
	Finding Finding `json:"finding"`
	Action  Action  `json:"action"`
}

type Summary struct {
	Findings int `json:"findings"`
	Allowed  int `json:"allowed"`
	Warnings int `json:"warnings"`
	Blocked  int `json:"blocked"`
}

type Result struct {
	SchemaVersion string             `json:"schema_version"`
	Tool          string             `json:"tool"`
	Version       string             `json:"version"`
	Root          string             `json:"root"`
	FilesScanned  int                `json:"files_scanned"`
	Decision      string             `json:"decision"`
	Summary       Summary            `json:"summary"`
	Findings      []EvaluatedFinding `json:"findings"`
}
