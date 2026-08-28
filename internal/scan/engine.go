package scan

import (
	"fmt"
	"path/filepath"
	"sort"

	"pipelineguard/internal/analyzer"
	"pipelineguard/internal/model"
	"pipelineguard/internal/policy"
)

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

	var findings []model.Finding

	for _, a := range analyzers {
		result, err := a.Analyze(ctx)
		if err != nil {
			return model.Result{}, fmt.Errorf(
				"%s analyzer: %w",
				a.Name(),
				err,
			)
		}

		findings = append(findings, result...)
	}

	sort.Slice(
		findings,
		func(i, j int) bool {
			if findings[i].Path == findings[j].Path {
				return findings[i].Line < findings[j].Line
			}

			return findings[i].Path < findings[j].Path
		},
	)

	result := model.Result{
		SchemaVersion: "1",
		Tool:          "PipelineGuard",
		Version:       version,
		Root:          absoluteRoot,
		FilesScanned:  len(files),
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
