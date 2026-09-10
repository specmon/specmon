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
	"sync"
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

type testListener struct {
	connections chan net.Conn
	closed      chan struct{}
	closeOnce   sync.Once
}

func newTestListener() *testListener {
	return &testListener{
		connections: make(chan net.Conn, 1),
		closed:      make(chan struct{}),
	}
}

func (l *testListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *testListener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
	})
	return nil
}

func (l *testListener) Addr() net.Addr {
	return testAddr("test")
}

type failingListener struct {
	err error
}

func (l *failingListener) Accept() (net.Conn, error) { return nil, l.err }
func (l *failingListener) Close() error              { return nil }
func (l *failingListener) Addr() net.Addr            { return testAddr("failing") }

type testAddr string

func (a testAddr) Network() string { return string(a) }
func (a testAddr) String() string  { return string(a) }

func TestMultiplexedReaderCloseSettlesConnections(t *testing.T) {
	t.Parallel()

	listener := newTestListener()
	reader := newMultiplexedReader(listener)
	server, client := net.Pipe()
	defer client.Close()
	listener.connections <- server

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
