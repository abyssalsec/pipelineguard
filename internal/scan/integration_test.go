package scan_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"pipelineguard/internal/analyzer"
	"pipelineguard/internal/policy"
	"pipelineguard/internal/scan"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)

	if !ok {
		t.Fatal("unable to resolve test path")
	}

	return filepath.Clean(
		filepath.Join(
			filepath.Dir(filename),
			"..",
			"..",
		),
	)
}

func nativeAnalyzers() []analyzer.Analyzer {
	return []analyzer.Analyzer{
		analyzer.DockerAnalyzer{},
		analyzer.GitHubActionsAnalyzer{},
		analyzer.SecretsAnalyzer{},
		analyzer.TerraformAnalyzer{},
		analyzer.KubernetesAnalyzer{},
	}
}

func TestSecureFixtureAllows(t *testing.T) {
	root := repositoryRoot(t)

	cfg, err := policy.Load(
		filepath.Join(
			root,
			".pipelineguard.yml",
		),
	)

	if err != nil {
		t.Fatal(err)
	}

	result, err := scan.Run(
		filepath.Join(
			root,
			"testdata",
			"secure",
		),
		cfg,
		nativeAnalyzers(),
		"test",
	)

	if err != nil {
		t.Fatal(err)
	}

	if result.Decision != "ALLOW" {
		t.Fatalf(
			"expected ALLOW, got %s",
			result.Decision,
		)
	}

	if result.RiskScore != 0 {
		t.Fatalf(
			"expected risk score 0, got %d",
			result.RiskScore,
		)
	}

	if result.Summary.Findings != 0 {
		t.Fatalf(
			"expected 0 findings, got %d",
			result.Summary.Findings,
		)
	}
}

func TestInsecureFixtureBlocks(t *testing.T) {
	root := repositoryRoot(t)

	cfg, err := policy.Load(
		filepath.Join(
			root,
			".pipelineguard.yml",
		),
	)

	if err != nil {
		t.Fatal(err)
	}

	result, err := scan.Run(
		filepath.Join(
			root,
			"testdata",
			"insecure",
		),
		cfg,
		nativeAnalyzers(),
		"test",
	)

	if err != nil {
		t.Fatal(err)
	}

	if result.Decision != "BLOCK" {
		t.Fatalf(
			"expected BLOCK, got %s",
			result.Decision,
		)
	}

	if result.RiskScore != 100 {
		t.Fatalf(
			"expected capped risk score 100, got %d",
			result.RiskScore,
		)
	}

	if result.Summary.Blocked == 0 {
		t.Fatal(
			"expected at least one blocked finding",
		)
	}

	if result.Summary.Findings < 10 {
		t.Fatalf(
			"expected multiple insecure findings, got %d",
			result.Summary.Findings,
		)
	}
}
