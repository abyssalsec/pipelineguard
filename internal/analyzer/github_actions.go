package analyzer

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"pipelineguard/internal/model"
)

type GitHubActionsAnalyzer struct{}

var fullCommitSHA = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

func (GitHubActionsAnalyzer) Name() string {
	return "github-actions"
}

func workflowFile(path string) bool {
	clean := filepath.ToSlash(path)

	if !strings.Contains(clean, "/.github/workflows/") &&
		!strings.HasPrefix(clean, ".github/workflows/") {
		return false
	}

	ext := strings.ToLower(filepath.Ext(path))

	return ext == ".yml" || ext == ".yaml"
}

func (GitHubActionsAnalyzer) Analyze(ctx Context) ([]model.Finding, error) {
	var findings []model.Finding

	for _, path := range ctx.Files {
		relative, _ := filepath.Rel(ctx.Root, path)

		if !workflowFile(relative) {
			continue
		}

		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}

		scanner := bufio.NewScanner(file)
		lineNumber := 0

		for scanner.Scan() {
			lineNumber++

			line := strings.TrimSpace(scanner.Text())

			if strings.HasPrefix(line, "#") {
				continue
			}

			if strings.EqualFold(line, "permissions: write-all") {
				findings = append(
					findings,
					model.Finding{
						ID:       "github-actions.write-all-permissions",
						Analyzer: "github-actions",
						Severity: model.SeverityHigh,
						Title:    "GitHub Actions grants write-all permissions",
						Message:  "Use least-privilege workflow permissions",
						Path:     filepath.ToSlash(relative),
						Line:     lineNumber,
						Evidence: line,
					},
				)
			}

			if strings.HasPrefix(line, "pull_request_target:") ||
				line == "pull_request_target:" {

				findings = append(
					findings,
					model.Finding{
						ID:       "github-actions.pull-request-target",
						Analyzer: "github-actions",
						Severity: model.SeverityMedium,
						Title:    "Workflow uses pull_request_target",
						Message:  "Review workflow carefully for untrusted pull request code execution",
						Path:     filepath.ToSlash(relative),
						Line:     lineNumber,
					},
				)
			}

			if !strings.HasPrefix(line, "uses:") &&
				!strings.HasPrefix(line, "- uses:") {
				continue
			}

			value := strings.TrimSpace(
				strings.TrimPrefix(
					strings.TrimPrefix(line, "-"),
					"uses:",
				),
			)

			if strings.HasPrefix(value, "./") ||
				strings.HasPrefix(value, "docker://") {
				continue
			}

			at := strings.LastIndex(value, "@")
			if at == -1 {
				continue
			}

			ref := value[at+1:]

			if fullCommitSHA.MatchString(ref) {
				continue
			}

			findings = append(
				findings,
				model.Finding{
					ID:       "github-actions.unpinned-action",
					Analyzer: "github-actions",
					Severity: model.SeverityMedium,
					Title:    "GitHub Action is not pinned to a commit SHA",
					Message:  "Pin third-party actions to an immutable commit SHA",
					Path:     filepath.ToSlash(relative),
					Line:     lineNumber,
					Evidence: value,
				},
			)
		}

		if err := scanner.Err(); err != nil {
			file.Close()
			return nil, err
		}

		file.Close()
	}

	return findings, nil
}
