package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"pipelineguard/internal/analyzer"
	"pipelineguard/internal/policy"
	"pipelineguard/internal/provider"
	"pipelineguard/internal/report"
	"pipelineguard/internal/sbom"
	"pipelineguard/internal/scan"
)

var version = "dev"

func usage() {
	fmt.Print(`PipelineGuard

Usage:
  pipelineguard scan [options] [path]
  pipelineguard version
  pipelineguard help

Scan options:
  --policy PATH          Policy configuration file
  --format FORMAT        text or json
  --trivy                Enable Trivy dependency vulnerability provider
  --sbom PATH            Generate CycloneDX JSON SBOM with Syft
  --provider-timeout D   External provider timeout (default 3m)

`)
}

func runScan(args []string) int {
	flags := flag.NewFlagSet(
		"scan",
		flag.ContinueOnError,
	)

	policyPath := flags.String(
		"policy",
		"",
		"policy configuration file",
	)

	format := flags.String(
		"format",
		"text",
		"output format: text or json",
	)

	enableTrivy := flags.Bool(
		"trivy",
		false,
		"enable Trivy vulnerability provider",
	)

	sbomPath := flags.String(
		"sbom",
		"",
		"generate CycloneDX JSON SBOM",
	)

	providerTimeout := flags.Duration(
		"provider-timeout",
		3*time.Minute,
		"external provider timeout",
	)

	if err := flags.Parse(args); err != nil {
		return 1
	}

	root := "."

	if flags.NArg() > 1 {
		fmt.Fprintln(
			os.Stderr,
			"ERROR: scan accepts at most one repository path",
		)
		return 1
	}

	if flags.NArg() == 1 {
		root = flags.Arg(0)
	}

	cfg := policy.Default()

	if *policyPath != "" {
		loaded, err := policy.Load(*policyPath)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"ERROR: %v\n",
				err,
			)
			return 1
		}

		cfg = loaded
	}

	analyzers := []analyzer.Analyzer{
		analyzer.DockerAnalyzer{},
		analyzer.GitHubActionsAnalyzer{},
		analyzer.SecretsAnalyzer{},
		analyzer.TerraformAnalyzer{},
		analyzer.KubernetesAnalyzer{},
	}

	if *enableTrivy {
		analyzers = append(
			analyzers,
			provider.NewTrivyAnalyzer(*providerTimeout),
		)
	}

	result, err := scan.Run(
		root,
		cfg,
		analyzers,
		version,
	)
	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"ERROR: %v\n",
			err,
		)
		return 1
	}

	if *sbomPath != "" {
		artifact, err := sbom.Generate(
			root,
			*sbomPath,
			*providerTimeout,
		)

		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"ERROR: generate SBOM: %v\n",
				err,
			)
			return 1
		}

		result.SBOM = artifact
	}

	switch *format {
	case "text":
		err = report.Text(os.Stdout, result)

	case "json":
		err = report.JSON(os.Stdout, result)

	default:
		fmt.Fprintf(
			os.Stderr,
			"ERROR: unsupported format: %s\n",
			*format,
		)
		return 1
	}

	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"ERROR: render report: %v\n",
			err,
		)
		return 1
	}

	if result.Decision == "BLOCK" {
		return 2
	}

	return 0
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	var rc int

	switch os.Args[1] {
	case "scan":
		rc = runScan(os.Args[2:])

	case "version", "--version":
		fmt.Println(version)
		rc = 0

	case "help", "--help", "-h":
		usage()
		rc = 0

	default:
		fmt.Fprintf(
			os.Stderr,
			"ERROR: unknown command: %s\n\n",
			os.Args[1],
		)

		usage()
		rc = 1
	}

	os.Exit(rc)
}
