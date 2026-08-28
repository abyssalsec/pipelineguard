package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"pipelineguard/internal/model"
)

func testResult() model.Result {
	return model.Result{
		SchemaVersion: "1",
		Tool:          "PipelineGuard",
		Version:       "test",
		Root:          "/tmp/repository",
		FilesScanned:  3,
		RiskScore:     42,
		Decision:      "BLOCK",
		Summary: model.Summary{
			Findings: 1,
			Blocked:  1,
		},
		Findings: []model.EvaluatedFinding{
			{
				Action: model.ActionBlock,
				Finding: model.Finding{
					ID:       "docker.root-user",
					Analyzer: "docker",
					Severity: model.SeverityHigh,
					Title:    "Container runs as root",
					Message:  "Use a non-root user",
					Path:     "Dockerfile",
					Line:     4,
				},
			},
		},
	}
}

func TestJSONReport(t *testing.T) {
	var buffer bytes.Buffer

	if err := JSON(&buffer, testResult()); err != nil {
		t.Fatalf("JSON report failed: %v", err)
	}

	var decoded map[string]any

	if err := json.Unmarshal(
		buffer.Bytes(),
		&decoded,
	); err != nil {
		t.Fatalf("invalid JSON report: %v", err)
	}

	if decoded["decision"] != "BLOCK" {
		t.Fatalf(
			"expected BLOCK decision, got %v",
			decoded["decision"],
		)
	}
}

func TestSARIFReport(t *testing.T) {
	var buffer bytes.Buffer

	if err := SARIF(&buffer, testResult()); err != nil {
		t.Fatalf("SARIF report failed: %v", err)
	}

	var decoded map[string]any

	if err := json.Unmarshal(
		buffer.Bytes(),
		&decoded,
	); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}

	if decoded["version"] != "2.1.0" {
		t.Fatalf(
			"expected SARIF 2.1.0, got %v",
			decoded["version"],
		)
	}

	runs, ok := decoded["runs"].([]any)

	if !ok || len(runs) != 1 {
		t.Fatalf("expected one SARIF run")
	}
}

func TestHTMLReport(t *testing.T) {
	var buffer bytes.Buffer

	if err := HTML(&buffer, testResult()); err != nil {
		t.Fatalf("HTML report failed: %v", err)
	}

	html := buffer.String()

	required := []string{
		"#ABSL SECURITY",
		"PipelineGuard",
		"docker.root-user",
		"BLOCK",
		"42/100",
	}

	for _, value := range required {
		if !strings.Contains(html, value) {
			t.Fatalf(
				"HTML report missing %q",
				value,
			)
		}
	}
}
