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
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/specmon/specmon/parser"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/utils"
	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"
)

// ProcessRules parses the rules from the given path and returns the original, the selected and the decomposed rules.
func ProcessRules(specPath, role string, decompose bool, defines []string) ([]*rule.Rule, []*rule.Rule, []*rule.Rule, error) {
	rules, err := parser.ParseFile(context.Background(), specPath, defines)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot process rules: %w", err)
	}

	selectedRules := rule.Rules(rules).FilterByRole(role)

	var decompRules []*rule.Rule
	if decompose {
		for _, r := range selectedRules {
			if !r.NoDecomp() && !r.HasHints() && !r.HasTriggers() {
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
		case reflect.Slice:
			if fieldValue.Type().Elem().Kind() == reflect.String {
				// Handle []string type
				cmd.PersistentFlags().StringSliceVarP(fieldValue.Addr().Interface().(*[]string), flag, short, nil, desc)
			}
		default:
			// Ignore unsupported fields
		}
	}
}

// createSocketServer creates a TCP server and returns a multiplexed reader that handles multiple client connections.
func createSocketServer(address string) (io.ReadCloser, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("cannot listen on %s: %w", address, err)
	}

	log.Infof("SpecMon rewrite listening on %s for incoming events...\n", address)

	// Create a multiplexed reader that will merge events from all connections
	multiplexer := newMultiplexedReader(listener)
	return multiplexer, nil
}

// multiplexedReader handles multiple concurrent connections and merges their event streams.
type multiplexedReader struct {
	listener  net.Listener
	eventChan chan []byte
	closeChan chan struct{}
	closeOnce sync.Once
}

func newMultiplexedReader(listener net.Listener) *multiplexedReader {
	mr := &multiplexedReader{
		listener:  listener,
		eventChan: make(chan []byte, 1000), // Buffer for events
		closeChan: make(chan struct{}),
	}

	// Start accepting connections in the background
	go mr.acceptConnections()

	return mr
}

func (mr *multiplexedReader) acceptConnections() {
	for {
		select {
		case <-mr.closeChan:
			return
		default:
			conn, err := mr.listener.Accept()
			if err != nil {
				select {
				case <-mr.closeChan:
					return // Listener was closed, expected error
				default:
					log.Fatalf("Error accepting connection: %v\n", err)
					continue
				}
			}

			log.Infof("Client connected from %s\n", conn.RemoteAddr())

			// Handle each connection in its own goroutine
			go mr.handleConnection(conn)
		}
	}
}

func (mr *multiplexedReader) handleConnection(conn net.Conn) {
	defer conn.Close()
	defer log.Infof("Client %s disconnected\n", conn.RemoteAddr())

	scanner := bufio.NewScanner(conn)
	// Increase buffer size to handle very large cryptographic events
	scanner.Buffer(make([]byte, 8*1024*1024), 8*1024*1024) // 8MB buffer
	for scanner.Scan() {
		line := scanner.Bytes()
		// Make a copy since scanner reuses the underlying buffer
		event := make([]byte, len(line))
		copy(event, line)

		select {
		case mr.eventChan <- event:
			// Event sent successfully
		case <-mr.closeChan:
			return // Multiplexer is being closed
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading from client %s: %v (continuing...)\n", conn.RemoteAddr(), err)
		// Don't return immediately on scanner errors - they might be recoverable
		// or due to large events. Continue processing other events.
	}
}

func (mr *multiplexedReader) Read(p []byte) (n int, err error) {
	select {
	case event := <-mr.eventChan:
		// Add newline back since we need it for event parsing
		event = append(event, '\n')
		if len(event) > len(p) {
			return 0, fmt.Errorf("buffer too small for event")
		}
		copy(p, event)
		return len(event), nil
	case <-mr.closeChan:
		return 0, io.EOF
	}
}

func (mr *multiplexedReader) Close() error {
	mr.closeOnce.Do(func() {
		mr.listener.Close()
		close(mr.closeChan)
	})
	return nil
}

// getOutputFile returns the output file.
// If the file is empty or "-", it returns os.Stdout.
func getOutputFile(file string) (*os.File, error) {
	if file == "" || file == "-" {
		return os.Stdout, nil
	}

	return os.Create(file)
}

// openInputReader implements unified -in semantics for both monitor and rewrite.
// Cases:
// - "" (empty): use stdin if connected, else error,
// - "-": stdin,
// - "host:port": start a TCP server and read from accepted clients (multiplexed),
// - any other: treat as file path.
func openInputReader(in string) (io.ReadCloser, error) {
	// Default: no -in provided
	if in == "" {
		if utils.IsStdinConnected() {
			return os.Stdin, nil
		}
		return nil, fmt.Errorf("stdin not connected; provide -in or pipe data")
	}

	// Explicit stdin
	if in == "-" {
		return os.Stdin, nil
	}

	// host:port detection (listen/server mode)
	if looksLikeHostPort(in) {
		return createSocketServer(in)
	}

	// Otherwise, treat as file
	return os.Open(in)
}

func looksLikeHostPort(s string) bool {
	// Basic check: exactly one ':' and port numeric
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return false
	}
	if parts[1] == "" {
		return false
	}
	for _, ch := range parts[1] {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
