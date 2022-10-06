package main

import (
	"github.com/mcandre/sunshine"

	"fmt"
	"os"
)

func main() {
	var roots []string

	if len(os.Args) < 2 {
		cwd, err := os.Getwd()

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		roots = append(roots, cwd)
	} else {
		roots = os.Args[1:]
	}

	os.Exit(sunshine.Report(roots))
}
