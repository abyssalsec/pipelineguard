package analyzer

import (
	"pipelineguard/internal/model"
)

type Context struct {
	Root  string
	Files []string
}

type Analyzer interface {
	Name() string
	Analyze(Context) ([]model.Finding, error)
}
