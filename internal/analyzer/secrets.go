package analyzer

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"pipelineguard/internal/model"
)

type SecretsAnalyzer struct{}

type secretPattern struct {
	ID       string
	Title    string
	Pattern  *regexp.Regexp
	Severity model.Severity
}

var secretPatterns = []secretPattern{
	{
		ID:       "secrets.aws-access-key",
		Title:    "Potential AWS access key detected",
		Pattern:  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Severity: model.SeverityCritical,
	},
	{
		ID:       "secrets.github-token",
		Title:    "Potential GitHub token detected",
		Pattern:  regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{30,255}`),
		Severity: model.SeverityCritical,
	},
	{
		ID:       "secrets.private-key",
		Title:    "Private key material detected",
		Pattern:  regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----`),
		Severity: model.SeverityCritical,
	},
}

func (SecretsAnalyzer) Name() string {
	return "secrets"
}

func redact(value string) string {
	if len(value) <= 8 {
		return "[REDACTED]"
	}

	return value[:4] + "..." + value[len(value)-4:]
}

func (SecretsAnalyzer) Analyze(ctx Context) ([]model.Finding, error) {
	var findings []model.Finding

	for _, path := range ctx.Files {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}

		if info.Size() > 1024*1024 {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		if bytes.IndexByte(data, 0) >= 0 {
			continue
		}

		content := string(data)
		relative, _ := filepath.Rel(ctx.Root, path)

		for _, candidate := range secretPatterns {
			matches := candidate.Pattern.FindAllStringIndex(content, -1)

			for _, match := range matches {
				value := content[match[0]:match[1]]

				line := 1 + strings.Count(
					content[:match[0]],
					"\n",
				)

				findings = append(
					findings,
					model.Finding{
						ID:       candidate.ID,
						Analyzer: "secrets",
						Severity: candidate.Severity,
						Title:    candidate.Title,
						Message:  "Remove the credential from source control and rotate it if it is real",
						Path:     filepath.ToSlash(relative),
						Line:     line,
						Evidence: redact(value),
					},
				)
			}
		}
	}

	return findings, nil
}
