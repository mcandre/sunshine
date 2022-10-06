package main

import (
	"github.com/mcandre/sunshine"

	"flag"
	"fmt"
	"log"
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

	scanner, err := sunshine.Scan(roots)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var clean bool
	var warning string

	for {
		select {
		case err = <-scanner.ErrCh:
			clean = false
			log.Println(err)
		case warning = <-scanner.WarnCh:
			clean = false
			log.Println(warning)
		case <-scanner.DoneCh:
			if !clean {
				os.Exit(1)
			}

			os.Exit(0)
		}
	}
}
