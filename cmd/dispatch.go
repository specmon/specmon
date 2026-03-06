package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

// FindFirstNonFlag returns the index and value of the first non-flag token in argv.
// It treats a standalone "--" as end-of-flags and returns the following token if present.
// The returned index is the index in argv of that token (or -1 if none).
func FindFirstNonFlag(argv []string) (int, string) {
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			if i+1 < len(argv) {
				return i + 1, argv[i+1]
			}
			return -1, ""
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return i, a
	}
	return -1, ""
}

// DispatchExternal inspects argv for a candidate subcommand (first non-flag token).
// If the token is not a built-in subcommand of the provided cobra root command,
// DispatchExternal will look for an executable named "specmon-<candidate>" on PATH.
// If such an executable is found it attempts to replace the current process with it
// (syscall.Exec). If exec fails it falls back to spawning the child process,
// wiring stdin/stdout/stderr, forwarding SIGINT/SIGTERM and propagating the child's
// exit code. DispatchExternal returns true if an external program was found and
// dispatched (the function may not return if exec replacement succeeds or when the
// child process exits), and false if no external program was applicable/found.
func DispatchExternal(root *cobra.Command, argv []string) bool {
	idx, candidate := FindFirstNonFlag(argv)
	if candidate == "" {
		return false
	}

	// If candidate matches a built-in subcommand or alias, don't dispatch externally.
	for _, c := range root.Commands() {
		if c == nil {
			continue
		}
		if c.Name() == candidate {
			return false
		}
		for _, a := range c.Aliases {
			if a == candidate {
				return false
			}
		}
	}
	if candidate == "help" {
		return false
	}

	// Look for an executable named "<Name>-<candidate>" on PATH.
	exeName := fmt.Sprintf("%s-%s", Name, candidate)
	var foundPath string
	if p := os.Getenv("PATH"); p != "" {
		for _, dir := range strings.Split(p, string(os.PathListSeparator)) {
			if dir == "" {
				dir = "."
			}
			candidatePath := filepath.Join(dir, exeName)
			info, err := os.Stat(candidatePath)
			if err != nil {
				continue
			}
			if info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
				if abs, err := filepath.Abs(candidatePath); err == nil {
					foundPath = abs
				} else {
					foundPath = candidatePath
				}
				break
			}
		}
	}
	if foundPath == "" {
		return false
	}

	// Build argv for the external process: argv0 should be "specmon-<candidate>" and
	// the arguments are everything following the candidate token.
	childArgs := []string{}
	if idx >= 0 && idx+1 < len(argv) {
		childArgs = argv[idx+1:]
	}
	argv0 := fmt.Sprintf("%s-%s", Name, candidate)
	argvList := append([]string{argv0}, childArgs...)

	// Try to replace current process (POSIX syscall.Exec).
	if err := syscall.Exec(foundPath, argvList, os.Environ()); err == nil {
		// On success this does not return.
		return true
	} else {
		// Exec failed: fall back to spawn-and-wait with a helpful message.
		fmt.Fprintf(os.Stderr, "exec failed (%v), falling back to spawn-and-wait\n", err)
	}

	// Spawn fallback: start child, wire stdio, forward signals, wait and propagate exit code.
	child := exec.Command(foundPath, childArgs...)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.Env = os.Environ()

	if err := child.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start external command %s: %v\n", foundPath, err)
		// Conventional exit code for command not found / cannot execute.
		os.Exit(127)
	}

	// Forward SIGINT/SIGTERM to the child so interactive commands behave correctly.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		for s := range sigCh {
			_ = child.Process.Signal(s)
		}
	}()

	if err := child.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "external command failed: %v\n", err)
		os.Exit(1)
	}
	if child.ProcessState != nil {
		os.Exit(child.ProcessState.ExitCode())
	}
	// Shouldn't reach here, but exit success just in case.
	os.Exit(0)
	return true
}
