// Copyright (C) 2025 CISPA Helmholtz Center for Information Security
// Author: Kevin Morio <kevin.morio@cispa.de>
//
// This file is part of SpecMon.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with program. If not, see <https://www.gnu.org/licenses/>.

package cmd

import (
	"fmt"
	"os"
	"runtime/pprof"

	log "github.com/sirupsen/logrus"

	"github.com/fatih/color"
	"github.com/specmon/specmon/utils"
	"github.com/spf13/cobra"
)

const (
	// Version is the version of the application.
	Version = "0.1.0"
	// Name is the name of the executable.
	Name = "specmon"
)

// RootConfig is the configuration of the root command.
type RootConfig struct {
	Verbose        bool     `flag:"verbose"          short:"v" desc:"verbose output"`
	Quiet          bool     `flag:"quiet"            short:"q" desc:"quiet output"`
	Decompose      bool     `flag:"decompose"        short:"d" desc:"decompose rules"`
	LogLevel       string   `flag:"log-level"        short:"l" desc:"log level"`
	Role           string   `flag:"role"             short:"r" desc:"role"`
	Defines        []string `flag:"defines"          short:"D" desc:"define preprocessor variables"`
	SpecPath       string   `flag:"spec-path"        short:"s" desc:"specification path"`
	CPUProfilePath string   `flag:"cpu-profile-path" short:"c" desc:"cpu profile path"`
	MemProfilePath string   `flag:"mem-profile-path" short:"m" desc:"memory profile path"`
	TruncateArgs   int64    `flag:"truncate-args" desc:"Max length of logged arguments within facts. Default is -1 for no limit."`
}

// DefaultRootConfig returns the default configuration of the root command.
func DefaultRootConfig() *RootConfig {
	return &RootConfig{
		LogLevel:  "error",
		Decompose: true,
	}
}

// RunE is the main function of the root command.
// The command parses a specification, and if requested,
// performs a filtering and decomposition of the rules.
func (c *RootConfig) RunE() error {
	rules, selectedRules, decompRules, err := ProcessRules(c.SpecPath, c.Role, c.Decompose, c.Defines)
	if err != nil {
		return err
	}

	if c.Quiet {
		return nil
	}

	bold := color.New(color.Bold).SprintfFunc()

	fmt.Printf("\n%s: %s (%d %s)\n", bold("Specification"), c.SpecPath, len(rules), utils.Pluralize("rule", len(rules)))
	if c.Role != "" {
		fmt.Printf("%s: %s (%d %s)\n", bold("Selected role"), c.Role, len(selectedRules), utils.Pluralize("rule", len(selectedRules)))
	}
	if c.Decompose {
		fmt.Printf("%s: %d %s\n", bold("Decomp result"), len(decompRules), utils.Pluralize("rule", len(decompRules)))
	}
	fmt.Println()

	for _, r := range decompRules {
		fmt.Println(utils.Indent(r.String(), 2))
	}

	return nil
}

// PersistentPreRunE is the pre-run hook for the root command.
// It is executed before any command is run.
func (c *RootConfig) PersistentPreRunE() error {
	if err := c.setupLogLevel(); err != nil {
		return err
	}

	if c.CPUProfilePath != "" {
		if err := c.setupCPUProfiling(); err != nil {
			return err
		}
	}

	return nil
}

// PersistentPostRunE is the post-run hook for the root command.
// It is executed after any command is run.
func (c *RootConfig) PersistentPostRunE() error {
	if c.CPUProfilePath != "" {
		pprof.StopCPUProfile()
	}

	if c.MemProfilePath != "" {
		if err := c.setupMemoryProfiling(); err != nil {
			return err
		}
	}

	return nil
}

// setupLogLevel sets the log level based on the configuration.
func (c *RootConfig) setupLogLevel() error {
	level, err := log.ParseLevel(c.LogLevel)
	if err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}
	log.SetLevel(level)

	if c.Quiet {
		log.SetLevel(log.PanicLevel)
	}

	return nil
}

// setupCPUProfiling starts CPU profiling if a path is provided.
func (c *RootConfig) setupCPUProfiling() error {
	f, err := os.Create(c.CPUProfilePath)
	if err != nil {
		return fmt.Errorf("cannot create CPU profile: %w", err)
	}

	if !c.Quiet {
		fmt.Printf("writing CPU profile to %s\n\n", c.CPUProfilePath)
	}

	if err := pprof.StartCPUProfile(f); err != nil {
		return fmt.Errorf("cannot start CPU profile: %w", err)
	}

	return nil
}

// setupMemoryProfiling writes the memory profile to the given path.
func (c *RootConfig) setupMemoryProfiling() error {
	f, err := os.Create(c.MemProfilePath)
	if err != nil {
		return fmt.Errorf("cannot create memory profile: %w", err)
	}

	if !c.Quiet {
		fmt.Printf("writing memory profile to %s\n\n", c.MemProfilePath)
	}

	if err := pprof.WriteHeapProfile(f); err != nil {
		return fmt.Errorf("cannot write memory profile: %w", err)
	}
	defer f.Close()

	return nil
}

// NewRootCmd creates a new root command.
func NewRootCmd() *cobra.Command {
	rootConfig := DefaultRootConfig()

	rootCmd := &cobra.Command{
		Use:   Name,
		Short: "SpecMon",
		Long:  "SpecMon is a runtime specification monitor using multiset-rewrite rules",
		RunE: func(_ *cobra.Command, args []string) error {
			rootConfig.SpecPath = args[0]

			return rootConfig.RunE()
		},
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			return rootConfig.PersistentPreRunE()
		},
		PersistentPostRunE: func(_ *cobra.Command, _ []string) error {
			return rootConfig.PersistentPostRunE()
		},
		Version: Version,
		Args:    cobra.ExactArgs(1),
	}

	// SilenceUsage is set to true to prevent Cobra from automatically printing
	// the usage when an error is returned from RunE.
	rootCmd.SilenceUsage = true

	addFlagsFromStruct(rootCmd, rootConfig)

	return rootCmd
}

// Root creates the root command and adds the subcommands.
func Root() *cobra.Command {
	rootCmd := NewRootCmd()
	rootCmd.AddCommand(
		NewMonitorCmd(),
		NewRewriteCmd(),
	)

	return rootCmd
}
