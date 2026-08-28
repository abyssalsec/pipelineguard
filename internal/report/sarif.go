package report

import (
	"encoding/json"
	"io"
	"sort"

	"pipelineguard/internal/model"
)

type sarifDocument struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string            `json:"name"`
	Version        string            `json:"version,omitempty"`
	Rules          []sarifRule       `json:"rules,omitempty"`
	InformationURI string            `json:"informationUri,omitempty"`
	Properties     map[string]string `json:"properties,omitempty"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	Help             sarifMessage      `json:"help"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID     string            `json:"ruleId"`
	RuleIndex  int               `json:"ruleIndex"`
	Level      string            `json:"level"`
	Message    sarifMessage      `json:"message"`
	Locations  []sarifLocation   `json:"locations,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func sarifLevel(action model.Action) string {
	switch action {
	case model.ActionBlock:
		return "error"
	case model.ActionWarn:
		return "warning"
	default:
		return "note"
	}
}

func SARIF(w io.Writer, result model.Result) error {
	ruleFindings := make(map[string]model.Finding)

	for _, evaluated := range result.Findings {
		finding := evaluated.Finding

		if _, exists := ruleFindings[finding.ID]; !exists {
			ruleFindings[finding.ID] = finding
		}
	}

	ruleIDs := make([]string, 0, len(ruleFindings))

	for id := range ruleFindings {
		ruleIDs = append(ruleIDs, id)
	}

	sort.Strings(ruleIDs)

	rules := make([]sarifRule, 0, len(ruleIDs))
	ruleIndexes := make(map[string]int, len(ruleIDs))

	for index, id := range ruleIDs {
		finding := ruleFindings[id]
		ruleIndexes[id] = index

		rules = append(rules, sarifRule{
			ID:   finding.ID,
			Name: finding.ID,
			ShortDescription: sarifMessage{
				Text: finding.Title,
			},
			Help: sarifMessage{
				Text: finding.Message,
			},
			Properties: map[string]string{
				"analyzer": finding.Analyzer,
				"severity": string(finding.Severity),
			},
		})
	}

	results := make(
		[]sarifResult,
		0,
		len(result.Findings),
	)

	for _, evaluated := range result.Findings {
		finding := evaluated.Finding

		entry := sarifResult{
			RuleID:    finding.ID,
			RuleIndex: ruleIndexes[finding.ID],
			Level:     sarifLevel(evaluated.Action),
			Message: sarifMessage{
				Text: finding.Title + ": " + finding.Message,
			},
			Properties: map[string]string{
				"analyzer": finding.Analyzer,
				"severity": string(finding.Severity),
				"action":   string(evaluated.Action),
			},
		}

		if finding.Evidence != "" {
			entry.Properties["evidence"] = finding.Evidence
		}

		if finding.Path != "" {
			physical := sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{
					URI: finding.Path,
				},
			}

			if finding.Line > 0 {
				physical.Region = &sarifRegion{
					StartLine: finding.Line,
				}
			}

			entry.Locations = []sarifLocation{
				{
					PhysicalLocation: physical,
				},
			}
		}

		results = append(results, entry)
	}

	document := sarifDocument{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:    "PipelineGuard",
						Version: result.Version,
						Rules:   rules,
						Properties: map[string]string{
							"decision": result.Decision,
						},
					},
				},
				Results: results,
			},
		},
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	return encoder.Encode(document)
}
