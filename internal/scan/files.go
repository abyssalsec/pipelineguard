package scan

import (
	"io/fs"
	"path/filepath"
	"strings"
)

var ignoredDirectories = map[string]struct{}{
	".git":         {},
	"node_modules": {},
	"vendor":       {},
	".venv":        {},
	"venv":         {},
	"dist":         {},
	"build":        {},
	".cache":       {},
}

func Files(root string) ([]string, error) {
	var files []string

	err := filepath.WalkDir(
		root,
		func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if entry.IsDir() {
				if path != root {
					if _, ignored := ignoredDirectories[entry.Name()]; ignored {
						return filepath.SkipDir
					}
				}

				return nil
			}

			if strings.HasPrefix(entry.Name(), ".pipelineguard") {
				return nil
			}

			files = append(files, path)
			return nil
		},
	)

	return files, err
}
