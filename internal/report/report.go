package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"pipelineguard/internal/model"
)

func Text(w io.Writer, result model.Result) error {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "#ABSL Security — PipelineGuard")
	fmt.Fprintln(w)

	fmt.Fprintf(
		w,
		"Repository: %s\nFiles scanned: %d\n\n",
		result.Root,
		result.FilesScanned,
	)

	for _, evaluated := range result.Findings {
		finding := evaluated.Finding

		fmt.Fprintf(
			w,
			"[%-5s] %-42s %-8s %s",
			strings.ToUpper(string(evaluated.Action)),
			finding.ID,
			strings.ToUpper(string(finding.Severity)),
			finding.Path,
		)

		if finding.Line > 0 {
			fmt.Fprintf(w, ":%d", finding.Line)
		}

		fmt.Fprintln(w)
		fmt.Fprintf(w, "        %s\n", finding.Title)

		if finding.Message != "" {
			fmt.Fprintf(w, "        %s\n", finding.Message)
		}

		fmt.Fprintln(w)
	}

	if result.SBOM != "" {
		fmt.Fprintf(
			w,
			"SBOM: %s\n\n",
			result.SBOM,
		)
	}

	fmt.Fprintf(
		w,
		"Summary: findings=%d allowed=%d warnings=%d blocked=%d\n",
		result.Summary.Findings,
		result.Summary.Allowed,
		result.Summary.Warnings,
		result.Summary.Blocked,
	)

	fmt.Fprintf(
		w,
		"Risk score: %d/100\n",
		result.RiskScore,
	)

	fmt.Fprintf(
		w,
		"\nPOLICY RESULT: %s\n",
		result.Decision,
	)

	return nil
}

func JSON(w io.Writer, result model.Result) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	return encoder.Encode(result)
}
