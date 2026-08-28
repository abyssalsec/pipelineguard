package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateCycloneDX(t *testing.T) {
	temp := t.TempDir()

	fakeSyft := filepath.Join(
		temp,
		"syft",
	)

	script := `#!/bin/sh

output=""

for argument in "$@"; do
  case "$argument" in
    cyclonedx-json=*)
      output="${argument#cyclonedx-json=}"
      ;;
  esac
done

if [ -z "$output" ]; then
  exit 1
fi

cat > "$output" <<'JSON'
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "type": "library",
      "name": "demo",
      "version": "1.0.0"
    }
  ]
}
JSON
`

	if err := os.WriteFile(
		fakeSyft,
		[]byte(script),
		0o755,
	); err != nil {
		t.Fatal(err)
	}

	t.Setenv(
		"PATH",
		temp+
			string(os.PathListSeparator)+
			os.Getenv("PATH"),
	)

	repository := filepath.Join(
		temp,
		"repository",
	)

	if err := os.MkdirAll(
		repository,
		0o755,
	); err != nil {
		t.Fatal(err)
	}

	output := filepath.Join(
		temp,
		"reports",
		"sbom.json",
	)

	path, err := Generate(
		repository,
		output,
		time.Second,
	)

	if err != nil {
		t.Fatalf(
			"SBOM generation failed: %v",
			err,
		)
	}

	data, err := os.ReadFile(path)

	if err != nil {
		t.Fatal(err)
	}

	var document map[string]any

	if err := json.Unmarshal(
		data,
		&document,
	); err != nil {
		t.Fatalf(
			"generated SBOM is invalid JSON: %v",
			err,
		)
	}

	if document["bomFormat"] != "CycloneDX" {
		t.Fatalf(
			"expected CycloneDX SBOM, got %v",
			document["bomFormat"],
		)
	}
}
