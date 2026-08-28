package analyzer

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"pipelineguard/internal/model"
)

type TerraformAnalyzer struct{}

type terraformRule struct {
	id       string
	severity model.Severity
	title    string
	message  string
	pattern  *regexp.Regexp
}

var terraformRules = []terraformRule{
	{
		id:       "terraform.world-open-ipv4",
		severity: model.SeverityHigh,
		title:    "Terraform resource is exposed to the entire IPv4 Internet",
		message:  "Restrict 0.0.0.0/0 access to explicitly required networks",
		pattern:  regexp.MustCompile(`["']0\.0\.0\.0/0["']`),
	},
	{
		id:       "terraform.world-open-ipv6",
		severity: model.SeverityHigh,
		title:    "Terraform resource is exposed to the entire IPv6 Internet",
		message:  "Restrict ::/0 access to explicitly required networks",
		pattern:  regexp.MustCompile(`["']::/0["']`),
	},
	{
		id:       "terraform.public-ip",
		severity: model.SeverityMedium,
		title:    "Terraform configuration enables a public IP",
		message:  "Verify that direct Internet exposure is required",
		pattern: regexp.MustCompile(
			`(?i)associate_public_ip_address\s*=\s*true`,
		),
	},
	{
		id:       "terraform.public-read-acl",
		severity: model.SeverityCritical,
		title:    "Terraform configuration enables public-read storage",
		message:  "Avoid public-read object storage unless explicitly required",
		pattern: regexp.MustCompile(
			`(?i)acl\s*=\s*["']public-read["']`,
		),
	},
}

func (TerraformAnalyzer) Name() string {
	return "terraform"
}

func (TerraformAnalyzer) Analyze(ctx Context) ([]model.Finding, error) {
	var findings []model.Finding

	for _, path := range ctx.Files {
		if strings.ToLower(filepath.Ext(path)) != ".tf" {
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

			if line == "" ||
				strings.HasPrefix(line, "#") ||
				strings.HasPrefix(line, "//") {
				continue
			}

			for _, rule := range terraformRules {
				match := rule.pattern.FindString(line)
				if match == "" {
					continue
				}

				relative, _ := filepath.Rel(ctx.Root, path)

				findings = append(findings, model.Finding{
					ID:       rule.id,
					Analyzer: "terraform",
					Severity: rule.severity,
					Title:    rule.title,
					Message:  rule.message,
					Path:     filepath.ToSlash(relative),
					Line:     lineNumber,
					Evidence: match,
				})
			}
		}

		if err := scanner.Err(); err != nil {
			file.Close()
			return nil, err
		}

		file.Close()
	}

	return findings, nil
}
