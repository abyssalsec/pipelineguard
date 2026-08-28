package scan

import (
	"fmt"
	"path/filepath"
	"sort"
	"sync"

	"pipelineguard/internal/analyzer"
	"pipelineguard/internal/model"
	"pipelineguard/internal/policy"
)

type analyzerResult struct {
	name     string
	findings []model.Finding
	err      error
}

func severityWeight(severity model.Severity) int {
	switch severity {
	case model.SeverityCritical:
		return 25
	case model.SeverityHigh:
		return 15
	case model.SeverityMedium:
		return 7
	case model.SeverityLow:
		return 3
	case model.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func calculateRisk(findings []model.Finding) int {
	score := 0

	for _, finding := range findings {
		score += severityWeight(finding.Severity)
	}

	if score > 100 {
		return 100
	}

	return score
}

func Run(
	root string,
	cfg policy.Config,
	analyzers []analyzer.Analyzer,
	version string,
) (model.Result, error) {

	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return model.Result{}, err
	}

	files, err := Files(absoluteRoot)
	if err != nil {
		return model.Result{}, fmt.Errorf("discover repository: %w", err)
	}

	ctx := analyzer.Context{
		Root:  absoluteRoot,
		Files: files,
	}

	results := make(chan analyzerResult, len(analyzers))
	var wg sync.WaitGroup

	for _, current := range analyzers {
		wg.Add(1)

		go func(a analyzer.Analyzer) {
			defer wg.Done()

			findings, err := a.Analyze(ctx)

			results <- analyzerResult{
				name:     a.Name(),
				findings: findings,
				err:      err,
			}
		}(current)
	}

	wg.Wait()
	close(results)

	var findings []model.Finding

	for result := range results {
		if result.err != nil {
			return model.Result{}, fmt.Errorf(
				"%s analyzer: %w",
				result.name,
				result.err,
			)
		}

		findings = append(findings, result.findings...)
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Path == findings[j].Path {
			if findings[i].Line == findings[j].Line {
				return findings[i].ID < findings[j].ID
			}

			return findings[i].Line < findings[j].Line
		}

		return findings[i].Path < findings[j].Path
	})

	result := model.Result{
		SchemaVersion: "1",
		Tool:          "PipelineGuard",
		Version:       version,
		Root:          absoluteRoot,
		FilesScanned:  len(files),
		RiskScore:     calculateRisk(findings),
		Decision:      "ALLOW",
	}

	for _, finding := range findings {
		action := cfg.Evaluate(finding)

		result.Findings = append(
			result.Findings,
			model.EvaluatedFinding{
				Finding: finding,
				Action:  action,
			},
		)

		result.Summary.Findings++

		switch action {
		case model.ActionBlock:
			result.Summary.Blocked++
			result.Decision = "BLOCK"

		case model.ActionWarn:
			result.Summary.Warnings++

			if result.Decision != "BLOCK" {
				result.Decision = "WARN"
			}

		default:
			result.Summary.Allowed++
		}
	}

	return result, nil
}
