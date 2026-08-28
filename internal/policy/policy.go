package policy

import (
	"fmt"
	"os"
	"strings"

	"pipelineguard/internal/model"

	"gopkg.in/yaml.v3"
)

type Gate struct {
	BlockSeverities []string `yaml:"block_severities"`
	WarnSeverities  []string `yaml:"warn_severities"`
}

type Config struct {
	Version int               `yaml:"version"`
	Gate    Gate              `yaml:"gate"`
	Rules   map[string]string `yaml:"rules"`
}

func Default() Config {
	return Config{
		Version: 1,
		Gate: Gate{
			BlockSeverities: []string{"critical", "high"},
			WarnSeverities:  []string{"medium"},
		},
		Rules: map[string]string{},
	}
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read policy: %w", err)
	}

	cfg := Default()

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse policy: %w", err)
	}

	if cfg.Version != 1 {
		return Config{}, fmt.Errorf(
			"unsupported policy version: %d",
			cfg.Version,
		)
	}

	return cfg, nil
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if strings.EqualFold(candidate, value) {
			return true
		}
	}

	return false
}

func parseAction(value string) (model.Action, bool) {
	switch strings.ToLower(value) {
	case "allow":
		return model.ActionAllow, true
	case "warn":
		return model.ActionWarn, true
	case "block":
		return model.ActionBlock, true
	default:
		return "", false
	}
}

func (c Config) Evaluate(f model.Finding) model.Action {
	if configured, ok := c.Rules[f.ID]; ok {
		if action, valid := parseAction(configured); valid {
			return action
		}
	}

	severity := string(f.Severity)

	if contains(c.Gate.BlockSeverities, severity) {
		return model.ActionBlock
	}

	if contains(c.Gate.WarnSeverities, severity) {
		return model.ActionWarn
	}

	return model.ActionAllow
}
