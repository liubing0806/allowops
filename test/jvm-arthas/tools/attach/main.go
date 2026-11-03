// Command ja-attach is a test-only HotSpot attach client and /proc inspector for the Arthas
// stage-0 measurements. It runs on the host (as root) against a JVM inside a container.
//
//	ja-attach inspect -pid P
//	ja-attach load    -pid P -agent /opt/arthas-min/arthas-agent.jar -core /opt/arthas-min/arthas-core.jar -opts-file F
//	ja-attach api     -pid P -port N -pass-file F -action exec -cmd 'jvm'
//	ja-attach probe   -pid P [-secret-file F]
//
// It is not product code and takes shortcuts the product must not take (see docs/arthas-stage0-report.md).
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var out any
	var err error
	switch os.Args[1] {
	case "inspect":
		out, err = cmdInspect(os.Args[2:])
	case "load":
		out, err = cmdLoad(os.Args[2:])
	case "api":
		out, err = cmdAPI(os.Args[2:])
	case "probe":
		out, err = cmdProbe(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ja-attach:", err)
		os.Exit(2)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "ja-attach:", err)
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ja-attach inspect|load|api|probe [flags]")
	os.Exit(64)
}
