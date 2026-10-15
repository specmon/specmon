// Copyright (C) 2025-2026 CISPA Helmholtz Center for Information Security
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
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/specmon/specmon/parser"
	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/utils"
	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"
)

// RuleSets contains each stage of rule processing.
type RuleSets struct {
	Parsed     []*rule.Rule
	Selected   []*rule.Rule
	Executable []*rule.Rule
}

// ProcessRules parses, selects, and optionally decomposes rules from the given path.
func ProcessRules(ctx context.Context, specPath, role string, decompose bool, defines []string) (RuleSets, error) {
	rules, err := parser.ParseFile(ctx, specPath, defines)
	if err != nil {
		return RuleSets{}, fmt.Errorf("cannot process rules: %w", err)
	}

	selectedRules := rule.Rules(rules).FilterByRole(role).DropUnusedRHSFacts()

	executableRules := selectedRules
	if decompose {
		executableRules, err = selectedRules.Translate()
		if err != nil {
			return RuleSets{}, err
		}
	}

	return RuleSets{
		Parsed:     rules,
		Selected:   selectedRules,
		Executable: executableRules,
	}, nil
}

// signalContext returns a context that the first SIGINT or SIGTERM
// cancels. The signals are then released, so that a second one ends the
// process at once, also while a write blocks.
func signalContext(ctx context.Context) (context.Context, context.CancelFunc) {
	signalCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	context.AfterFunc(signalCtx, stop)
	return signalCtx, stop
}

// addFlagsFromStruct adds flags to the given command from the given struct.
func addFlagsFromStruct(cmd *cobra.Command, cfg any) {
	t := reflect.TypeOf(cfg)
	v := reflect.ValueOf(cfg)

	// If cfg is a pointer, get the type of the value it points to
	if t.Kind() == reflect.Pointer {
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
		case reflect.Int:
			value := int(fieldValue.Int())
			cmd.PersistentFlags().IntVarP(fieldValue.Addr().Interface().(*int), flag, short, value, desc)
		case reflect.Int64:
			if fieldValue.Type() == reflect.TypeFor[time.Duration]() {
				value := time.Duration(fieldValue.Int())
				cmd.PersistentFlags().DurationVarP(fieldValue.Addr().Interface().(*time.Duration), flag, short, value, desc)
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
	listener net.Listener
	reader   *io.PipeReader
	writer   *io.PipeWriter
	workers  sync.WaitGroup
	clients  clientConnections
}

type clientConnections struct {
	sync.Mutex
	closed bool
	active map[net.Conn]struct{}
}

func newMultiplexedReader(listener net.Listener) *multiplexedReader {
	reader, writer := io.Pipe()
	mr := &multiplexedReader{
		listener: listener,
		reader:   reader,
		writer:   writer,
		clients: clientConnections{
			active: make(map[net.Conn]struct{}),
		},
	}

	// Start accepting connections in the background
	mr.workers.Add(1)
	go mr.acceptConnections()

	return mr
}

func (mr *multiplexedReader) acceptConnections() {
	defer mr.workers.Done()

	for {
		conn, err := mr.listener.Accept()
		if err != nil {
			// After Close, the pipe is closed and this has no effect.
			_ = mr.writer.CloseWithError(fmt.Errorf("accept connection: %w", err))
			return
		}

		if !mr.clients.add(conn) {
			_ = conn.Close()
			return
		}

		log.Infof("Client connected from %s\n", conn.RemoteAddr())
		mr.workers.Add(1)
		go mr.handleConnection(conn)
	}
}

func (mr *multiplexedReader) handleConnection(conn net.Conn) {
	defer func() {
		_ = conn.Close()
		mr.clients.remove(conn)
		mr.workers.Done()
		log.Infof("Client %s disconnected\n", conn.RemoteAddr())
	}()

	scanner := bufio.NewScanner(conn)
	// Increase buffer size to handle very large cryptographic events
	scanner.Buffer(make([]byte, 8*1024*1024), 8*1024*1024) // 8MB buffer
	for scanner.Scan() {
		event := append([]byte(nil), scanner.Bytes()...)
		event = append(event, '\n')
		if _, err := mr.writer.Write(event); err != nil {
			return
		}
	}

	if err := scanner.Err(); err != nil {
		log.Warnf("Error reading from client %s: %v, continuing with other clients\n", conn.RemoteAddr(), err)
	}
}

func (mr *multiplexedReader) Read(p []byte) (n int, err error) {
	return mr.reader.Read(p)
}

func (mr *multiplexedReader) Close() error {
	if !mr.clients.closeAll() {
		return nil
	}

	_ = mr.reader.Close()
	_ = mr.writer.Close()
	closeErr := mr.listener.Close()
	mr.workers.Wait()
	return closeErr
}

func (clients *clientConnections) add(conn net.Conn) bool {
	clients.Lock()
	defer clients.Unlock()
	if clients.closed {
		return false
	}
	clients.active[conn] = struct{}{}
	return true
}

func (clients *clientConnections) remove(conn net.Conn) {
	clients.Lock()
	defer clients.Unlock()
	delete(clients.active, conn)
}

func (clients *clientConnections) closeAll() bool {
	clients.Lock()
	if clients.closed {
		clients.Unlock()
		return false
	}
	clients.closed = true
	active := make([]net.Conn, 0, len(clients.active))
	for conn := range clients.active {
		active = append(active, conn)
	}
	clients.Unlock()

	for _, conn := range active {
		_ = conn.Close()
	}
	return true
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
