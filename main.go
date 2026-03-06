package main

import (
	"os"

	"github.com/specmon/specmon/cmd"
)

func main() {
	rootCmd := cmd.Root()

	// Attempt external dispatch via the cmd package helper.
	if cmd.DispatchExternal(rootCmd, os.Args) {
		return
	}

	// Default: run Cobra normally.
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
