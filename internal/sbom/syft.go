package sbom

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func Generate(
	root string,
	output string,
	timeout time.Duration,
) (string, error) {

	binary, err := exec.LookPath("syft")
	if err != nil {
		return "", fmt.Errorf(
			"Syft executable was not found in PATH",
		)
	}

	if timeout <= 0 {
		timeout = 3 * time.Minute
	}

	absoluteOutput, err := filepath.Abs(output)
	if err != nil {
		return "", fmt.Errorf(
			"resolve SBOM output path: %w",
			err,
		)
	}

	if err := os.MkdirAll(
		filepath.Dir(absoluteOutput),
		0o755,
	); err != nil {
		return "", fmt.Errorf(
			"create SBOM output directory: %w",
			err,
		)
	}

	commandContext, cancel := context.WithTimeout(
		context.Background(),
		timeout,
	)
	defer cancel()

	command := exec.CommandContext(
		commandContext,
		binary,
		root,
		"-o",
		"cyclonedx-json="+absoluteOutput,
	)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	command.Stdout = &stdout
	command.Stderr = &stderr

	if err := command.Run(); err != nil {
		if commandContext.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf(
				"Syft generation exceeded timeout %s",
				timeout,
			)
		}

		return "", fmt.Errorf(
			"Syft execution failed: %w: %s",
			err,
			strings.TrimSpace(stderr.String()),
		)
	}

	info, err := os.Stat(absoluteOutput)
	if err != nil {
		return "", fmt.Errorf(
			"SBOM output was not created: %w",
			err,
		)
	}

	if info.Size() == 0 {
		return "", fmt.Errorf(
			"generated SBOM is empty",
		)
	}

	return absoluteOutput, nil
}
