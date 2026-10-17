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

package utils

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Indent indents a string by n spaces.
func Indent(s string, n int) string {
	var b strings.Builder
	for line := range strings.SplitSeq(s, "\n") {
		b.WriteString(strings.Repeat(" ", n))
		b.WriteString(line)
		b.WriteString("\n")
	}

	return b.String()
}

const NumberLinesIndent = 1

func NumberLines(s string, offset int) string {
	lines := strings.Split(s, "\n")
	first, last := offset, offset+len(lines)
	maxLen := max(len(strconv.Itoa(first)), len(strconv.Itoa(last)))

	var b strings.Builder
	for i, line := range lines {
		d := strconv.Itoa(offset + i + 1)
		indent := maxLen - len(d) + NumberLinesIndent
		b.WriteString(strings.Repeat(" ", indent))
		b.WriteString(d)
		b.WriteString(" │ ")
		b.WriteString(line)
		b.WriteString("\n")
	}

	return b.String()
}

// IsStdinConnected returns true if stdin is connected to a pipe or file.
func IsStdinConnected() bool {
	fi, _ := os.Stdin.Stat()

	return (fi.Mode() & os.ModeCharDevice) == 0
}

// Unique returns a slice with unique elements.
// The order of the elements is preserved.
func Unique[F fmt.Stringer](vals []F) []F {
	M := make(map[string]bool)
	var result []F

	for _, val := range vals {
		if _, ok := M[val.String()]; !ok {
			M[val.String()] = true
			result = append(result, val)
		}
	}

	return result
}

// BytesToInt converts an unsigned byte magnitude to an int64.
// An empty byte slice is converted to 0.
func BytesToInt(b []byte, order binary.ByteOrder) (int64, error) {
	if len(b) > 8 {
		return 0, fmt.Errorf("byte slice too long to convert to int64: %d", len(b))
	}

	var padded [8]byte
	var value uint64
	switch order {
	case binary.LittleEndian:
		copy(padded[:], b)
		value = binary.LittleEndian.Uint64(padded[:])
	case binary.BigEndian:
		copy(padded[8-len(b):], b)
		value = binary.BigEndian.Uint64(padded[:])
	default:
		value = order.Uint64(PadWithByteOrder(b, order, 8))
	}
	if value > math.MaxInt64 {
		return 0, fmt.Errorf("byte magnitude exceeds int64: %d", value)
	}

	return int64(value), nil
}

// IntToBytes encodes an int64 as its deterministic two's-complement bit pattern.
func IntToBytes(i int64, order binary.ByteOrder) []byte {
	var buf [8]byte
	order.PutUint64(buf[:], uint64(i)) //nolint:gosec // Preserve the two's-complement bit pattern.

	return buf[:]
}

// PadWithByteOrder pads a byte slice to the right (little endian) or left (big endian) with zeros.
// If the byte slice is already longer than the specified length, it is returned as is.
func PadWithByteOrder(s []byte, order binary.ByteOrder, length int) []byte {
	if len(s) >= length {
		return s
	}

	padded := make([]byte, length)
	if order == binary.LittleEndian {
		copy(padded, s)
	} else {
		copy(padded[length-len(s):], s)
	}

	return padded
}

func Pluralize(s string, n int) string {
	if n == 1 {
		return s
	}

	return s + "s"
}

func KillProcess(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("pid must be a positive integer, got %d", pid)
	}

	// Find the process by PID
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process with pid %d: %w", pid, err)
	}

	// Send SIGKILL to forcefully terminate the process
	if err := process.Signal(syscall.SIGKILL); err != nil {
		return fmt.Errorf("failed to send SIGKILL to process with pid %d: %w", pid, err)
	}

	return nil
}

func MedianDuration(numbers []time.Duration) float64 {
	slices.Sort(numbers)
	middle := len(numbers) / 2
	if len(numbers)%2 == 0 {
		return float64(numbers[middle-1]+numbers[middle]) / 2
	}

	return float64(numbers[middle])
}
