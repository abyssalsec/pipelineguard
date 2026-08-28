package provider_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"pipelineguard/internal/analyzer"
	"pipelineguard/internal/model"
	"pipelineguard/internal/provider"
)

func TestTrivyNormalization(t *testing.T) {
	temp := t.TempDir()

	fakeTrivy := filepath.Join(
		temp,
		"trivy",
	)

	script := `#!/bin/sh
cat <<'JSON'
{
  "Results": [
    {
      "Target": "requirements.txt",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-TEST-HIGH",
          "PkgName": "demo-high",
          "InstalledVersion": "1.0.0",
          "FixedVersion": "2.0.0",
          "Severity": "HIGH",
          "Title": "High severity demo vulnerability"
        },
        {
          "VulnerabilityID": "CVE-TEST-LOW",
          "PkgName": "demo-low",
          "InstalledVersion": "1.0.0",
          "FixedVersion": "",
          "Severity": "LOW",
          "Title": "Low severity demo vulnerability"
        }
      ]
    }
  ]
}
JSON
`

	if err := os.WriteFile(
		fakeTrivy,
		[]byte(script),
		0o755,
	); err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(temp, "repository")

	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}

	trivy := provider.TrivyAnalyzer{
		Binary:  fakeTrivy,
		Timeout: time.Second,
	}

	findings, err := trivy.Analyze(
		analyzer.Context{
			Root: root,
		},
	)

	if err != nil {
		t.Fatalf("Trivy analyzer failed: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf(
			"expected 2 findings, got %d",
			len(findings),
		)
	}

	if findings[0].ID !=
		"dependencies.vulnerability.high" {

		t.Fatalf(
			"unexpected first finding ID: %s",
			findings[0].ID,
		)
	}

	if findings[0].Severity != model.SeverityHigh {
		t.Fatalf(
			"expected HIGH severity, got %s",
			findings[0].Severity,
		)
	}

	if findings[1].Severity != model.SeverityLow {
		t.Fatalf(
			"expected LOW severity, got %s",
			findings[1].Severity,
		)
	}
}
