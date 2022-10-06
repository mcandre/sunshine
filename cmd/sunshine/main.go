package main

import (
	"github.com/mcandre/sunshine"

	"flag"
	"fmt"
	"os"
)

var flagVersion = flag.Bool("version", false, "Show version information")
var flagHelp = flag.Bool("help", false, "Show usage information")

func main() {
	flag.Parse()

	switch {
	case *flagVersion:
		fmt.Println(sunshine.Version)
		os.Exit(0)
	case *flagHelp:
		flag.PrintDefaults()
		os.Exit(0)
	}

	roots := flag.Args()

	if len(roots) == 0 {
		cwd, err := os.Getwd()

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		roots = []string{cwd}
	}

	os.Exit(sunshine.Report(roots))
}
