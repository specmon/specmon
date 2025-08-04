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
	"context"
	"fmt"
	"os"
	"reflect"

	"github.com/specmon/specmon/parser"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/utils"
	"github.com/spf13/cobra"
)

// ProcessRules parses the rules from the given path and returns the original, the selected and the decomposed rules.
func ProcessRules(specPath, role string, decompose bool) ([]*rule.Rule, []*rule.Rule, []*rule.Rule, error) {
	rules, err := parser.ParseRules(context.Background(), specPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot process rules: %w", err)
	}

	selectedRules := rule.Rules(rules).FilterByRole(role)

	var decompRules []*rule.Rule
	if decompose {
		for _, r := range selectedRules {
			if !r.NoDecomp() {
				decompRules = append(decompRules, rule.Translate(r)...)
			} else {
				decompRules = append(decompRules, r)
			}
		}
	} else {
		decompRules = selectedRules
	}

	return rules, selectedRules, decompRules, nil
}

// addFlagsFromStruct adds flags to the given command from the given struct.
func addFlagsFromStruct(cmd *cobra.Command, cfg interface{}) {
	t := reflect.TypeOf(cfg)
	v := reflect.ValueOf(cfg)

	// If cfg is a pointer, get the type of the value it points to
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
		v = v.Elem()
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldValue := v.Field(i)

		flag := field.Tag.Get("flag")
		short := field.Tag.Get("short")
		desc := field.Tag.Get("desc")

		switch fieldValue.Kind() {
		case reflect.Bool:
			value := fieldValue.Bool()
			// Type is already known due to reflection.
			cmd.PersistentFlags().BoolVarP(fieldValue.Addr().Interface().(*bool), flag, short, value, desc)
		case reflect.String:
			value := fieldValue.String()
			// Type is already known due to reflection.
			cmd.PersistentFlags().StringVarP(fieldValue.Addr().Interface().(*string), flag, short, value, desc) // Set default value
		default:
			// Ignore unsupported fields
		}
	}
}

// getEventSource returns the event source file.
// If the standard input is connected, it returns os.Stdin.
func getEventSource(file string) (*os.File, error) {
	if utils.IsStdinConnected() {
		return os.Stdin, nil
	}

	return os.Open(file)
}

// getOutputFile returns the output file.
// If the file is empty or "-", it returns os.Stdout.
func getOutputFile(file string) (*os.File, error) {
	if file == "" || file == "-" {
		return os.Stdout, nil
	}

	return os.Create(file)
}
