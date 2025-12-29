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
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/fatih/color"
	"github.com/specmon/specmon/rule"
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
<<<<<<< Updated upstream
	Verbose        bool   `flag:"verbose"          short:"v" desc:"verbose output"`
	Quiet          bool   `flag:"quiet"            short:"q" desc:"quiet output"`
	Decompose      bool   `flag:"decompose"        short:"d" desc:"decompose rules"`
	LogLevel       string `flag:"log-level"        short:"l" desc:"log level"`
	Role           string `flag:"role"             short:"r" desc:"role"`
	SpecPath       string `flag:"spec-path"        short:"s" desc:"specification path"`
	CPUProfilePath string `flag:"cpu-profile-path" short:"c" desc:"cpu profile path"`
	MemProfilePath string `flag:"mem-profile-path" short:"m" desc:"memory profile path"`
=======
	Verbose        bool     `flag:"verbose"          short:"v" desc:"verbose output"`
	Quiet          bool     `flag:"quiet"            short:"q" desc:"quiet output"`
	Decompose      bool     `flag:"decompose"        short:"d" desc:"decompose rules"`
	LogLevel       string   `flag:"log-level"        short:"l" desc:"log level"`
	Role           string   `flag:"role"             short:"r" desc:"role"`
	RuleFilter     string   `flag:"rule"                       desc:"show only rules from the given base rule name"`
	Defines        []string `flag:"defines"          short:"D" desc:"define preprocessor variables"`
	SpecPath       string   `flag:"spec-path"        short:"s" desc:"specification path"`
	CPUProfilePath string   `flag:"cpu-profile-path" short:"c" desc:"cpu profile path"`
	MemProfilePath string   `flag:"mem-profile-path" short:"m" desc:"memory profile path"`
>>>>>>> Stashed changes
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
	rules, selectedRules, decompRules, err := ProcessRules(c.SpecPath, c.Role, c.Decompose)
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

	order, grouped := groupDecomposedRules(selectedRules, decompRules)
	if c.RuleFilter != "" {
		order = []string{c.RuleFilter}
	}
	if c.Verbose {
		if c.RuleFilter != "" && len(grouped[c.RuleFilter]) == 0 {
			return fmt.Errorf("no rules found for base name %q", c.RuleFilter)
		}
		for i, base := range order {
			group := grouped[base]
			if len(group) == 0 {
				continue
			}

			fmt.Printf("=== %s (%d %s) ===\n\n", ruleColor(i).Sprint(base), len(group), utils.Pluralize("rule", len(group)))
			for _, r := range group {
				fmt.Println(utils.Indent(colorizeRuleString(r.String(), ruleColor(i)), 2))
				fmt.Println()
			}
		}
	} else {
		if c.RuleFilter != "" && len(grouped[c.RuleFilter]) == 0 {
			return fmt.Errorf("no rules found for base name %q", c.RuleFilter)
		}
		fmt.Println("Rules:")
		maxLen := 0
		for _, base := range order {
			if len(base) > maxLen {
				maxLen = len(base)
			}
		}
		for i, base := range order {
			group := grouped[base]
			if len(group) == 0 {
				continue
			}
			fmt.Printf("  %-*s : %d %s\n", maxLen, ruleColor(i).Sprint(base), len(group), utils.Pluralize("rule", len(group)))
		}
		fmt.Println("\nUse --verbose or -v for detailed rule listing")
	}

	return nil
}

func groupDecomposedRules(baseRules []*rule.Rule, decompRules []*rule.Rule) ([]string, map[string][]*rule.Rule) {
	baseNames := make([]string, 0, len(baseRules))
	baseSet := make(map[string]struct{}, len(baseRules))
	for _, r := range baseRules {
		baseNames = append(baseNames, r.Name)
		baseSet[r.Name] = struct{}{}
	}

	order := append([]string{}, baseNames...)
	orderSet := make(map[string]struct{}, len(baseNames))
	for _, name := range baseNames {
		orderSet[name] = struct{}{}
	}

	grouped := make(map[string][]*rule.Rule)
	for _, r := range decompRules {
		base := findBaseName(r.Name, baseNames)
		if base == "" {
			base = r.Name
		}

		grouped[base] = append(grouped[base], r)
		if _, ok := orderSet[base]; !ok {
			order = append(order, base)
			orderSet[base] = struct{}{}
		}
	}

	return order, grouped
}

func findBaseName(ruleName string, baseNames []string) string {
	best := ""
	for _, base := range baseNames {
		if ruleName == base || strings.HasPrefix(ruleName, base+rule.ComponentSep) {
			if len(base) > len(best) {
				best = base
			}
		}
	}

	return best
}

func ruleColor(index int) *color.Color {
	palette := []color.Attribute{
		color.FgCyan,
		color.FgGreen,
		color.FgYellow,
		color.FgMagenta,
		color.FgBlue,
		color.FgRed,
	}
	if color.NoColor || len(palette) == 0 {
		return color.New()
	}
	return color.New(palette[index%len(palette)])
}

func colorizeRuleString(ruleStr string, c *color.Color) string {
	if c == nil || color.NoColor {
		return ruleStr
	}

	lines := strings.Split(ruleStr, "\n")
	if len(lines) == 0 {
		return ruleStr
	}

	const prefix = "rule "
	if strings.HasPrefix(lines[0], prefix) {
		rest := strings.TrimPrefix(lines[0], prefix)
		nameEnd := len(rest)
		if idx := strings.IndexAny(rest, "[:"); idx != -1 {
			nameEnd = idx
		}
		name := rest[:nameEnd]
		lines[0] = prefix + c.Sprint(name) + rest[nameEnd:]
	}

	return strings.Join(lines, "\n")
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
	)

	return rootCmd
}
