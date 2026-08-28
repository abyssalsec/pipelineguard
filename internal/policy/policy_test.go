package policy

import (
	"testing"

	"pipelineguard/internal/model"
)

func TestDefaultSeverityPolicy(t *testing.T) {
	cfg := Default()

	tests := []struct {
		name     string
		severity model.Severity
		expected model.Action
	}{
		{
			name:     "critical blocks",
			severity: model.SeverityCritical,
			expected: model.ActionBlock,
		},
		{
			name:     "high blocks",
			severity: model.SeverityHigh,
			expected: model.ActionBlock,
		},
		{
			name:     "medium warns",
			severity: model.SeverityMedium,
			expected: model.ActionWarn,
		},
		{
			name:     "low allows",
			severity: model.SeverityLow,
			expected: model.ActionAllow,
		},
		{
			name:     "info allows",
			severity: model.SeverityInfo,
			expected: model.ActionAllow,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			finding := model.Finding{
				ID:       "test.rule",
				Severity: test.severity,
			}

			action := cfg.Evaluate(finding)

			if action != test.expected {
				t.Fatalf(
					"expected %s, got %s",
					test.expected,
					action,
				)
			}
		})
	}
}

func TestRuleOverride(t *testing.T) {
	cfg := Default()

	cfg.Rules["custom.rule"] = "allow"

	finding := model.Finding{
		ID:       "custom.rule",
		Severity: model.SeverityCritical,
	}

	action := cfg.Evaluate(finding)

	if action != model.ActionAllow {
		t.Fatalf(
			"expected explicit rule override to allow, got %s",
			action,
		)
	}
}

func TestInvalidRuleFallsBackToSeverity(t *testing.T) {
	cfg := Default()

	cfg.Rules["custom.rule"] = "invalid"

	finding := model.Finding{
		ID:       "custom.rule",
		Severity: model.SeverityHigh,
	}

	action := cfg.Evaluate(finding)

	if action != model.ActionBlock {
		t.Fatalf(
			"expected severity fallback to block, got %s",
			action,
		)
	}
}
