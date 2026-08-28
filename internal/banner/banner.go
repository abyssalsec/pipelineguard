package banner

import (
	"fmt"
	"io"
)

const (
	brightGreen = "\033[92m"
	reset       = "\033[0m"
)

const artwork = `
 ____  _            _ _            ____                     _
|  _ \(_)_ __   ___| (_)_ __   ___/ ___|_   _  __ _ _ __ __| |
| |_) | | '_ \ / _ \ | | '_ \ / _ \ |  _| | | |/ _' | '__/ _' |
|  __/| | |_) |  __/ | | | | |  __/ |_| | |_| | (_| | | | (_| |
|_|   |_| .__/ \___|_|_|_| |_|\___|\____|\__,_|\__,_|_|  \__,_|
        |_|

PipelineGuard
#ABSL Security Development Project
DevSecOps Security Gate
`

func Print(w io.Writer, color bool) {
	if color {
		fmt.Fprint(w, brightGreen)
	}

	fmt.Fprint(w, artwork)

	if color {
		fmt.Fprint(w, reset)
	}

	fmt.Fprintln(w)
}
