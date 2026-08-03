package runner

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"
)

const banner = `
        __        __          ____         
  _____/ /_      / /_  __  __/ / /_  __  __
 / ___/ __/_____/ __ \/ / / / / __ \/ / / /
/ /__/ /_/_____/ / / / /_/ / / / / / /_/ / 
\___/\__/     /_/ /_/\__,_/_/_/ /_/\__,_/  
                                           
`

var version = ""

func getVersion() string {
	v := version
	if v == "" {
		info, ok := debug.ReadBuildInfo()
		if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
			return "dev"
		}
		v = info.Main.Version
	}
	return strings.TrimPrefix(v, "v")
}

func showBanner() {
	fmt.Fprint(os.Stderr, banner)
	fmt.Fprintf(os.Stderr, "\tv%s - CT Log Parser by Arqsz\n\n", getVersion())
}
