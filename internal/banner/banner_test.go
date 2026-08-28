package banner

import (
	"bytes"
	"strings"
	"testing"
)

func TestBanner(t *testing.T) {
	var buffer bytes.Buffer

	Print(&buffer, false)

	output := buffer.String()

	required := []string{
		"Pipeline",
		"#ABSL Security Development Project",
		"DevSecOps Security Gate",
	}

	for _, value := range required {
		if !strings.Contains(output, value) {
			t.Fatalf(
				"banner missing %q",
				value,
			)
		}
	}
}
