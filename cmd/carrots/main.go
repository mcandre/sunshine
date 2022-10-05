package main

import (
	"github.com/mcandre/carrots"

	"fmt"
	"os"
)

func main() {
	cwd, err := os.Getwd()

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	os.Exit(carrots.Report(cwd))
}
