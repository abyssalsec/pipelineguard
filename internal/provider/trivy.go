package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"pipelineguard/internal/analyzer"
	"pipelineguard/internal/model"
)

type TrivyAnalyzer struct {
	Binary  string
	Timeout time.Duration
}

type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string               `json:"Target"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
}

type trivyVulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
}

func NewTrivyAnalyzer(timeout time.Duration) TrivyAnalyzer {
	return TrivyAnalyzer{
		Binary:  "trivy",
		Timeout: timeout,
	}
}

func (TrivyAnalyzer) Name() string {
	return "trivy"
}

func trivySeverity(value string) (model.Severity, string) {
	switch strings.ToUpper(value) {
	case "CRITICAL":
		return model.SeverityCritical, "critical"
	case "HIGH":
		return model.SeverityHigh, "high"
	case "MEDIUM":
		return model.SeverityMedium, "medium"
	case "LOW":
		return model.SeverityLow, "low"
	default:
		return model.SeverityInfo, "unknown"
	}
}

func normalizeTrivyPath(root, target string) string {
	if target == "" {
		return ""
	}

	if filepath.IsAbs(target) {
		relative, err := filepath.Rel(root, target)

		if err == nil {
			return filepath.ToSlash(relative)
		}
	}

	return filepath.ToSlash(target)
}

func (t TrivyAnalyzer) Analyze(
	scanContext analyzer.Context,
) ([]model.Finding, error) {

	binary := t.Binary

	if binary == "" {
		binary = "trivy"
	}

	if _, err := exec.LookPath(binary); err != nil {
		return nil, fmt.Errorf(
			"Trivy executable was not found in PATH",
		)
	}

	timeout := t.Timeout

	if timeout <= 0 {
		timeout = 3 * time.Minute
	}

	commandContext, cancel := context.WithTimeout(
		context.Background(),
		timeout,
	)
	defer cancel()

	command := exec.CommandContext(
		commandContext,
		binary,
		"fs",
		"--scanners",
		"vuln",
		"--format",
		"json",
		"--exit-code",
		"0",
		"--quiet",
		"--no-progress",
		"--skip-version-check",
		scanContext.Root,
	)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	command.Stdout = &stdout
	command.Stderr = &stderr

	if err := command.Run(); err != nil {
		if commandContext.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf(
				"Trivy scan exceeded timeout %s",
				timeout,
			)
		}

		return nil, fmt.Errorf(
			"Trivy execution failed: %w: %s",
			err,
			strings.TrimSpace(stderr.String()),
		)
	}

	var report trivyReport

	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return nil, fmt.Errorf(
			"parse Trivy JSON report: %w",
			err,
		)
	}

	var findings []model.Finding

	for _, result := range report.Results {
		target := normalizeTrivyPath(
			scanContext.Root,
			result.Target,
		)

		for _, vulnerability := range result.Vulnerabilities {
			severity, severityID := trivySeverity(
				vulnerability.Severity,
			)

			title := vulnerability.Title

			if title == "" {
				title = "Dependency vulnerability detected"
			}

			message := fmt.Sprintf(
				"%s affects %s %s",
				vulnerability.VulnerabilityID,
				vulnerability.PkgName,
				vulnerability.InstalledVersion,
			)

			if vulnerability.FixedVersion != "" {
				message += fmt.Sprintf(
					"; fixed in %s",
					vulnerability.FixedVersion,
				)
			}

			evidence := fmt.Sprintf(
				"%s@%s",
				vulnerability.PkgName,
				vulnerability.InstalledVersion,
			)

			findings = append(
				findings,
				model.Finding{
					ID: "dependencies.vulnerability." +
						severityID,
					Analyzer: "trivy",
					Severity: severity,
					Title:    title,
					Message:  message,
					Path:     target,
					Evidence: evidence,
				},
			)
		}
	}

	return findings, nil
}
