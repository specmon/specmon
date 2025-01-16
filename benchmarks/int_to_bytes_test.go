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

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

// Original function using bytes.Buffer.
func IntToBytesOriginal(i int, order binary.ByteOrder) ([]byte, error) {
	b := new(bytes.Buffer)
	err := binary.Write(b, order, int64(i))
	if err != nil {
		return nil, fmt.Errorf("cannot convert constant to bytes: %w", err)
	}

	return b.Bytes(), nil
}

// Optimized function using direct byte manipulation.
func IntToBytesOptimized(i int, order binary.ByteOrder) []byte {
	var buf [8]byte
	// Convert the int to uint64 explicitly using int64 to handle negative values correctly.
	//nolint:gosec
	order.PutUint64(buf[:], uint64(int64(i)))

	return buf[:]
}

// Benchmark for the original function.
func BenchmarkIntToBytesOriginal(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, err := IntToBytesOriginal(n, binary.BigEndian)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark for the optimized function.
func BenchmarkIntToBytesOptimized(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_ = IntToBytesOptimized(n, binary.BigEndian)
	}
}

func main() {
	// Example usage
	bytes, err := IntToBytesOriginal(12345678, binary.BigEndian)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Original:", bytes)
	}

	optimizedBytes := IntToBytesOptimized(12345678, binary.BigEndian)
	fmt.Println("Optimized:", optimizedBytes)
}
