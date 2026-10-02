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
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// rewriteSignalChildEnv holds the arguments with which the test binary
// runs the root command as a child process.
const rewriteSignalChildEnv = "SPECMON_TEST_REWRITE_SIGNAL_ARGS"

// TestRewriteEndsOnSecondSignalWhileOutputBlocks runs the rewrite command
// in a child process whose output is not read, so that a write blocks,
// and checks that a second SIGTERM ends it.
func TestRewriteEndsOnSecondSignalWhileOutputBlocks(t *testing.T) {
	if args := os.Getenv(rewriteSignalChildEnv); args != "" {
		root := Root()
		root.SetArgs(strings.Split(args, "\n"))
		_ = root.Execute()
		os.Exit(0)
	}

	dir := t.TempDir()
	spec := filepath.Join(dir, "rewrite.spthy")
	rules := `theory RewriteSignal
begin

rule Rewrite [no-decomp, trigger=[<monitorTestEvent(), r>]]:
  [ ] --[ PPEvent(<monitorTestRewrittenEvent(), r>) ]-> [ ]

end
`
	if err := os.WriteFile(spec, []byte(rules), 0o600); err != nil {
		t.Fatalf("write rewrite theory: %v", err)
	}
	// The output of these events exceeds any pipe buffer.
	input := writeMonitorInput(t, bytes.Repeat(monitorEventLine(t, monitorTestEventName), 20000))

	child := exec.Command(os.Args[0], "-test.run=^TestRewriteEndsOnSecondSignalWhileOutputBlocks$") //nolint:gosec // The test binary runs itself.
	child.Env = append(os.Environ(), rewriteSignalChildEnv+"="+strings.Join([]string{"rewrite", "--in", input, spec}, "\n"))
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatalf("child output: %v", err)
	}
	if err := child.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- child.Wait()
	}()
	exited := false
	t.Cleanup(func() {
		if !exited {
			_ = child.Process.Kill()
			<-done
		}
	})

	// The first output line shows that the command handles signals. The
	// rest is not read, so the command blocks in a write.
	if _, err := bufio.NewReader(stdout).ReadString('\n'); err != nil {
		t.Fatalf("read the first output line: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	for range 2 {
		if err := child.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatalf("signal child: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	select {
	case <-done:
		exited = true
	case <-time.After(10 * time.Second):
		t.Fatal("the rewrite command blocked in a write did not end after a second SIGTERM")
	}
}
