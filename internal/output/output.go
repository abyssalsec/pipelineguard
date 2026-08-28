package output

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func Render(
	path string,
	render func(io.Writer) error,
) error {

	if path == "" || path == "-" {
		return render(os.Stdout)
	}

	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}

	directory := filepath.Dir(absolutePath)

	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	temp, err := os.CreateTemp(
		directory,
		".pipelineguard-report-*",
	)
	if err != nil {
		return fmt.Errorf("create temporary report: %w", err)
	}

	tempPath := temp.Name()
	success := false

	defer func() {
		if !success {
			_ = temp.Close()
			_ = os.Remove(tempPath)
		}
	}()

	if err := temp.Chmod(0o600); err != nil {
		return fmt.Errorf("set report permissions: %w", err)
	}

	if err := render(temp); err != nil {
		return fmt.Errorf("render report: %w", err)
	}

	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync report: %w", err)
	}

	if err := temp.Close(); err != nil {
		return fmt.Errorf("close report: %w", err)
	}

	if err := os.Rename(tempPath, absolutePath); err != nil {
		return fmt.Errorf("publish report: %w", err)
	}

	success = true
	return nil
}
