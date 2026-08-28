package analyzer

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"

	"pipelineguard/internal/model"

	"gopkg.in/yaml.v3"
)

type KubernetesAnalyzer struct{}

func (KubernetesAnalyzer) Name() string {
	return "kubernetes"
}

func mapValue(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}

func boolValue(value any) bool {
	result, _ := value.(bool)
	return result
}

func listValue(value any) []any {
	result, _ := value.([]any)
	return result
}

func workloadPodSpec(document map[string]any) map[string]any {
	kind, _ := document["kind"].(string)
	spec := mapValue(document["spec"])

	switch kind {
	case "Pod":
		return spec

	case "Deployment",
		"StatefulSet",
		"DaemonSet",
		"ReplicaSet",
		"Job":

		template := mapValue(spec["template"])
		return mapValue(template["spec"])

	case "CronJob":
		jobTemplate := mapValue(spec["jobTemplate"])
		jobSpec := mapValue(jobTemplate["spec"])
		template := mapValue(jobSpec["template"])
		return mapValue(template["spec"])
	}

	return nil
}

func imagePinned(image string) bool {
	if strings.Contains(image, "@sha256:") {
		return true
	}

	lastSlash := strings.LastIndex(image, "/")
	lastColon := strings.LastIndex(image, ":")

	return lastColon > lastSlash &&
		!strings.HasSuffix(image, ":latest")
}

func (KubernetesAnalyzer) Analyze(ctx Context) ([]model.Finding, error) {
	var findings []model.Finding

	for _, path := range ctx.Files {
		ext := strings.ToLower(filepath.Ext(path))

		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		relative, _ := filepath.Rel(ctx.Root, path)
		relative = filepath.ToSlash(relative)

		if strings.HasPrefix(relative, ".github/workflows/") {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}

		decoder := yaml.NewDecoder(bytes.NewReader(data))

		for {
			var document map[string]any

			err := decoder.Decode(&document)

			if err == io.EOF {
				break
			}

			if err != nil {
				break
			}

			if len(document) == 0 {
				continue
			}

			if _, ok := document["apiVersion"]; !ok {
				continue
			}

			podSpec := workloadPodSpec(document)

			if podSpec == nil {
				continue
			}

			if boolValue(podSpec["hostNetwork"]) {
				findings = append(findings, model.Finding{
					ID:       "kubernetes.host-network",
					Analyzer: "kubernetes",
					Severity: model.SeverityHigh,
					Title:    "Kubernetes workload uses host networking",
					Message:  "Avoid hostNetwork unless explicitly required",
					Path:     relative,
				})
			}

			if boolValue(podSpec["hostPID"]) {
				findings = append(findings, model.Finding{
					ID:       "kubernetes.host-pid",
					Analyzer: "kubernetes",
					Severity: model.SeverityHigh,
					Title:    "Kubernetes workload shares the host PID namespace",
					Message:  "Avoid hostPID unless explicitly required",
					Path:     relative,
				})
			}

			podSecurityContext := mapValue(
				podSpec["securityContext"],
			)

			podRunsAsNonRoot := boolValue(
				podSecurityContext["runAsNonRoot"],
			)

			containers := append(
				listValue(podSpec["containers"]),
				listValue(podSpec["initContainers"])...,
			)

			for _, rawContainer := range containers {
				container := mapValue(rawContainer)

				name, _ := container["name"].(string)
				image, _ := container["image"].(string)

				securityContext := mapValue(
					container["securityContext"],
				)

				containerRunsAsNonRoot := boolValue(
					securityContext["runAsNonRoot"],
				)

				if !podRunsAsNonRoot &&
					!containerRunsAsNonRoot {

					findings = append(findings, model.Finding{
						ID:       "kubernetes.run-as-non-root",
						Analyzer: "kubernetes",
						Severity: model.SeverityMedium,
						Title:    "Container does not enforce non-root execution",
						Message:  "Set runAsNonRoot to true at pod or container level",
						Path:     relative,
						Evidence: name,
					})
				}

				if boolValue(securityContext["privileged"]) {
					findings = append(findings, model.Finding{
						ID:       "kubernetes.privileged-container",
						Analyzer: "kubernetes",
						Severity: model.SeverityCritical,
						Title:    "Privileged Kubernetes container detected",
						Message:  "Avoid privileged containers unless strictly required",
						Path:     relative,
						Evidence: name,
					})
				}

				if image != "" && !imagePinned(image) {
					findings = append(findings, model.Finding{
						ID:       "kubernetes.unpinned-image",
						Analyzer: "kubernetes",
						Severity: model.SeverityMedium,
						Title:    "Kubernetes container image is not pinned",
						Message:  "Use an explicit immutable image version or digest",
						Path:     relative,
						Evidence: image,
					})
				}
			}
		}
	}

	return findings, nil
}
