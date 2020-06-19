package main

import (
	"os"

	"github.com/joemiller/certin/cmd/certin/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		os.Exit(1)
	}
}
