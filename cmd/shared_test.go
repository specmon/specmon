// Copyright (C) 2026 CISPA Helmholtz Center for Information Security
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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProcessRulesDropsFactsUnusedBySelectedRules(t *testing.T) {
	specPath := filepath.Join(t.TempDir(), "roles.spthy")
	spec := `theory Roles
begin

rule Client [role="client"]:
  [ ClientState(m) ] --> [ DeadOutput(len(hash(m))), ServerState(m) ]

rule Server [role="server"]:
  [ ServerState(m) ] --> [ ServerState(m) ]

end
`
	if err := os.WriteFile(specPath, []byte(spec), 0o600); err != nil {
		t.Fatalf("write test specification: %v", err)
	}

	rules, err := ProcessRules(context.Background(), specPath, "client", false, nil)
	if err != nil {
		t.Fatalf("ProcessRules: %v", err)
	}
	if len(rules.Selected) != 1 || fmt.Sprint(rules.Selected[0].RHS) != "[Compute_(len(hash(m)))]" {
		t.Fatalf("selected rules = %v", rules.Selected)
	}
}

func TestMacroAnnotationAdmission(t *testing.T) {
	for _, attribute := range []string{"trigger", "hint"} {
		t.Run(attribute, func(t *testing.T) {
			path := writeMonitorSpec(t, fmt.Sprintf(`macros: bad(x) = not(x, x)
rule R [%s=[<recv(bad(x)), r>]]: [ State(x) ] --> []`, attribute))
			config := MonitorConfig{In: writeMonitorInput(t, nil)}
			err := config.RunE(monitorTestCommand(), []string{path})
			if err == nil || !strings.Contains(err.Error(), "not(x, x) has 2 arguments, want 1") {
				t.Fatalf("monitor load = %v, want the expanded macro's arity error", err)
			}
		})
	}
}

type failingListener struct {
	err error
}

func (l *failingListener) Accept() (net.Conn, error) { return nil, l.err }
func (l *failingListener) Close() error              { return nil }
func (l *failingListener) Addr() net.Addr            { return nil }

func TestMultiplexedReaderCloseSettlesConnections(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	reader := newMultiplexedReader(listener)
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	line := strings.Repeat("event", 1000)
	writeResult := make(chan error, 1)
	go func() {
		_, err := io.WriteString(client, line+"\n")
		writeResult <- err
	}()

	var got strings.Builder
	buffer := make([]byte, 31)
	for !strings.HasSuffix(got.String(), "\n") {
		n, err := reader.Read(buffer)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		got.Write(buffer[:n])
	}
	if got.String() != line+"\n" {
		t.Fatalf("Read returned a changed event of length %d", got.Len())
	}
	if err := <-writeResult; err != nil {
		t.Fatalf("write event: %v", err)
	}

	if err := reader.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	readResult := make(chan error, 1)
	go func() {
		_, err := client.Read(make([]byte, 1))
		readResult <- err
	}()
	select {
	case err := <-readResult:
		if err == nil {
			t.Fatal("active client remained open after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("active client did not settle after Close")
	}
}

func TestMultiplexedReaderReturnsListenerFailures(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("listener failed")
	reader := newMultiplexedReader(&failingListener{err: wantErr})
	defer reader.Close()

	_, err := reader.Read(make([]byte, 1))
	if !errors.Is(err, wantErr) {
		t.Fatalf("Read error = %v, want listener failure", err)
	}
}

func TestGeneratedStateNameCollisionCommands(t *testing.T) {
	const source = `rule Seed [trigger=[<seed(x), <>>]]: [] --> [Seed(x)]
rule Seed2 [trigger=[<seed2(x), <>>]]: [] --> [Seed2(x)]
rule R: [Seed(y)] --> [Final(f(g(y, '0')))]
rule R_g: [Seed2(z)] --> [Final2(k(y()))]
rule After [trigger=[<after(a), <>>]]: [Final(a)] --> []
rule After2 [trigger=[<after2(a), <>>]]: [Final2(a)] --> []`
	path := writeMonitorSpec(t, source)
	if _, err := ProcessRules(context.Background(), path, "", false, nil); err != nil {
		t.Fatalf("without decomposition: %v", err)
	}
	for _, run := range []func() error{
		func() error {
			c := DefaultRootConfig()
			c.SpecPath = path
			c.Quiet = true
			return c.RunE(context.Background())
		},
		func() error {
			c := MonitorConfig{In: writeMonitorInput(t, nil)}
			command := monitorTestCommand()
			command.Flags().Bool("decompose", true, "")
			return c.RunE(command, []string{path})
		},
		func() error {
			c := RewriteConfig{In: writeMonitorInput(t, nil)}
			command := monitorTestCommand()
			command.Flags().Bool("decompose", true, "")
			return c.RunE(command, []string{path})
		},
	} {
		if err := run(); err == nil || !strings.Contains(err.Error(), "both generate the fact") {
			t.Fatalf("command error = %v", err)
		}
	}
}
