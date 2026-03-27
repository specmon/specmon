package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
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

// findExecutableOnPath attempts to locate an executable named exeName on PATH.
// On Windows it defers to exec.LookPath (respects PATHEXT). On POSIX it performs
// a manual scan and returns an absolute path when found.
func findExecutableOnPath(exeName string) (string, error) {
	if runtime.GOOS == "windows" {
		// exec.LookPath handles PATHEXT on Windows.
		return exec.LookPath(exeName)
	}

	// POSIX: manual scan of PATH entries and require execute bit.
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
					return abs, nil
				}
				return candidatePath, nil
			}
		}
	}
	return "", fmt.Errorf("not found")
}

// spawnAndWait runs the command at path with args, wires stdio, forwards signals,
// waits for it to finish, and exits the current process with the child's exit code.
// It does not return.
func spawnAndWait(path string, args []string) {
	child := exec.Command(path, args...)
	child.Stdin = os.Stdin
	child.Stdout = os.Stdout
	child.Stderr = os.Stderr
	child.Env = os.Environ()

	if err := child.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start external command %s: %v\n", path, err)
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
	os.Exit(0)
}

// DispatchExternal inspects argv for a candidate subcommand (first non-flag token).
// If the token is not a built-in subcommand of the provided cobra root command,
// DispatchExternal will look for an executable named "<Name>-<candidate>" on PATH.
//
// On POSIX systems it will prefer to replace the current process using syscall.Exec
// (git-like). On Windows it will spawn the external process and wait, wiring stdio
// and propagating the exit code. In both cases the function returns true if an
// external program was found and dispatched; otherwise it returns false.
func DispatchExternal(root *cobra.Command, argv []string) bool {
	// Locate candidate token
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

	// External program name
	exeName := fmt.Sprintf("%s-%s", Name, candidate)

	// Try to find the external executable
	path, err := findExecutableOnPath(exeName)
	if err != nil {
		return false
	}

	// Build argv for external: argv0 should be "<Name>-<candidate>", args are the remainder
	childArgs := []string{}
	if idx >= 0 && idx+1 < len(argv) {
		childArgs = argv[idx+1:]
	}
	argv0 := fmt.Sprintf("%s-%s", Name, candidate)
	argvList := append([]string{argv0}, childArgs...)

	// Windows: spawn-and-wait (exec replacement unavailable)
	if runtime.GOOS == "windows" {
		// Use exec.Command and Run to wait and capture exit code
		child := exec.Command(path, childArgs...)
		child.Stdin = os.Stdin
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		child.Env = os.Environ()

		if err := child.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			fmt.Fprintf(os.Stderr, "failed to execute external command %s: %v\n", path, err)
			os.Exit(127)
		}
		if child.ProcessState != nil {
			os.Exit(child.ProcessState.ExitCode())
		}
		os.Exit(0)
		return true
	}

	// POSIX: try syscall.Exec first to replace current process (git-like)
	if err := syscall.Exec(path, argvList, os.Environ()); err == nil {
		// successful exec does not return
		return true
	}

	// Exec failed: fall back to spawn-and-wait.
	fmt.Fprintf(os.Stderr, "exec failed (%v), falling back to spawn-and-wait\n", err)
	spawnAndWait(path, childArgs)
	// spawnAndWait does not return
	return true
}
