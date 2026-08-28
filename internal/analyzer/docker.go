package analyzer

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"pipelineguard/internal/model"
)

type DockerAnalyzer struct{}

func (DockerAnalyzer) Name() string {
	return "docker"
}

func isDockerfile(path string) bool {
	name := filepath.Base(path)

	return name == "Dockerfile" ||
		strings.HasPrefix(name, "Dockerfile.")
}

func (DockerAnalyzer) Analyze(ctx Context) ([]model.Finding, error) {
	var findings []model.Finding

	for _, path := range ctx.Files {
		if !isDockerfile(path) {
			continue
		}

		currentStageUserSet := false
		currentStageUser := ""
		lastFromLine := 0

		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}

		scanner := bufio.NewScanner(file)
		lineNumber := 0

		for scanner.Scan() {
			lineNumber++
			line := strings.TrimSpace(scanner.Text())

			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}

			instruction := strings.ToUpper(fields[0])

			switch instruction {
			case "FROM":
				currentStageUserSet = false
				currentStageUser = ""
				lastFromLine = lineNumber

				var image string

				for _, field := range fields[1:] {
					if strings.HasPrefix(field, "--") {
						continue
					}

					image = field
					break
				}

				if image == "" || image == "scratch" {
					continue
				}

				if strings.Contains(image, "@sha256:") {
					continue
				}

				lastSlash := strings.LastIndex(image, "/")
				lastColon := strings.LastIndex(image, ":")

				if lastColon <= lastSlash ||
					strings.HasSuffix(image, ":latest") {

					relative, _ := filepath.Rel(ctx.Root, path)

					findings = append(
						findings,
						model.Finding{
							ID:       "docker.unpinned-base-image",
							Analyzer: "docker",
							Severity: model.SeverityMedium,
							Title:    "Docker base image is not pinned",
							Message:  "Use an explicit immutable image version or digest",
							Path:     relative,
							Line:     lineNumber,
							Evidence: image,
						},
					)
				}

			case "USER":
				if len(fields) >= 2 {
					currentStageUserSet = true
					currentStageUser = strings.ToLower(fields[1])
				}
			}
		}

		if err := scanner.Err(); err != nil {
			file.Close()
			return nil, err
		}

		file.Close()

		if lastFromLine == 0 {
			continue
		}

		if !currentStageUserSet ||
			currentStageUser == "root" ||
			currentStageUser == "0" {

			relative, _ := filepath.Rel(ctx.Root, path)

			findings = append(
				findings,
				model.Finding{
					ID:       "docker.root-user",
					Analyzer: "docker",
					Severity: model.SeverityHigh,
					Title:    "Container runs as root",
					Message:  "Final Docker stage does not define a non-root USER",
					Path:     relative,
				},
			)
		}
	}

	return findings, nil
}
