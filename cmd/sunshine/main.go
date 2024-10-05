// Package main implements a CLI application to lint file permissions.
package main

import (
	"github.com/mcandre/sunshine"

	"flag"
	"fmt"
	"log"
	"os"
)

var flagDebug = flag.Bool("debug", false, "Enable additional logging")
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

	debug := *flagDebug
	roots := flag.Args()

	if len(roots) == 0 {
		cwd, err := os.Getwd()

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		roots = []string{cwd}
	}

	scanner, err := sunshine.Illuminate(roots, debug)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var msg string
	clean := true

	for {
		select {
		case msg = <-scanner.DebugCh:
			log.Println(msg)
		case msg = <-scanner.WarnCh:
			clean = false
			log.Printf("warning: %s", msg)
		case err = <-scanner.ErrCh:
			clean = false
			log.Println(err)
		case <-scanner.DoneCh:
			if !clean {
				os.Exit(1)
			}

			os.Exit(0)
		}
	}
}
