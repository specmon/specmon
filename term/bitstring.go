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

package term

// This function parses / matches bitstrings.
// It takes three arguments:
// - binding b
// - bitstring a
// - bitstring spec s
//
// THe bitstring spec has the following format:
//
// "a:length|b:length|..."
//
// Here a and b can either be matched to existing values in the binding b
// or they can be newly assigned.
// The length is either an integer constant or it is bound either in
// the binding b or the new binding being constructed. If it is a bitstring
// it is interpreted as an integer.
//
// a and b above can also either be integers or bitstrings.
// A bitstring starts with 0x followed by the bytes.

/*
func MatchBitstring(b Binding, a []byte, s string) (Binding, error) {
	// If the specification is empty, it doesn't match anything.
	if s == "" {
		log.Infof("matchBytestring: empty specification doesn't match anything\n")
		return nil, fmt.Errorf("matchBytestring: no match (empty specification)")
	}

	n := Binding{}
	currentPos := 0

	// Iterate over the different sections in the specification.
	sections := strings.Split(s, "|")
	for i, sec := range sections {
		// Split a section into their content and their length.
		component := strings.Split(sec, ":")
		if len(component) != 2 {
			return nil, fmt.Errorf("matchBytestring: invalid section %s", sec)
		}
		content := component[0]
		length := component[1]

		var lengthInt int

		// Length can either be
		// 1. an integer
		if val, err := strconv.ParseInt(length, 10, 64); err == nil {
			lengthInt = int(val)

			// -1 (till the end) is allowed if it is the last section
			if lengthInt == -1 {
				if i < len(sections)-1 {
					return nil, fmt.Errorf("matchBytestring: length of -1 only allowed in last section")
				}
				// Set length to the remaining bytes in the string
				lengthInt = len(a[currentPos:])
			}

			// 2. a variable
		} else {
			// Check if content is a variable in the binding n.
			if val, ok := n[*NewVariable(length)]; ok {
				if bval, ok := val.(*Constant); ok {
					// Expect that numbers are stored in little-endian byte-order.
					// However, SetBytes assumes big-endian, hence the bytes are reversed.
					lengthBig := big.NewInt(0).SetBytes(reverse(bval.Value.([]byte)))
					if !lengthBig.IsInt64() {
						return nil, fmt.Errorf("matchBytestring: length larger than 64 bits (overflow)")
					}
					lengthInt = int(lengthBig.Int64())
				}

				// Check if content is a variable in the binding b.
			} else if cst, ok := b[*NewVariable(length)]; ok {
				if c, ok := cst.(*Constant); ok {
					value, err := c.AsInt()
					if err != nil {
						return nil, err
					}
					lengthInt = value
				} else {
					return nil, fmt.Errorf("Required ")
				}

				//  Content refers to an unbound variable
			} else {
				return nil, fmt.Errorf("matchBytestring: unbound variable (length) %s", length)
			}
		}

		// Ensure that the length of the input is not exceeded.
		// Go checks bounds on slices by using the capacitiy of the slice (cap) and not the length len(a)
		// which will result in reading uninitialized values if it is not accounted for.
		if currentPos+lengthInt > len(a) {
			return nil, fmt.Errorf("matchBytestring: input bytestring to short (got %d, expected %d)", len(a), currentPos+lengthInt)
		}

		// Content can either be
		// 1. an bitstring
		if strings.HasPrefix(content, "0x") {
			val, err := hex.DecodeString(strings.TrimPrefix(content, "0x"))
			if err != nil {
				return nil, fmt.Errorf("matchBytestring: invalid bytestring %s", content)
			}

			// Check if val is exactly lengthInt long.
			if len(val) != lengthInt {
				return nil, fmt.Errorf("matchBytestring: bitstring spec with wrong length (got %d, expected %d)", len(val), lengthInt)
			}

			// MATCH: Check if passed bitstring a matches this section.
			if bytes.Equal(a[currentPos:currentPos+lengthInt], val) {
				log.Infof("matchBytestring: (%d, %d) matches %x", currentPos, currentPos+lengthInt, val)
			} else {
				log.Infof("matchBytestring: (%d, %d) doesn't match (expected %x, got %x)", currentPos, currentPos+lengthInt, val, a[currentPos:currentPos+lengthInt])
				return nil, fmt.Errorf("matchBytestring: no match")
			}
			// 2. an integer
		} else if val, err := strconv.ParseInt(content, 10, 64); err == nil {
			// Check if lengthInt is larger than 8 (integers are only supported up to 64 bits).
			if lengthInt > 8 {
				return nil, fmt.Errorf("matchBytestring: integers are only supported up to 64 bits (got %d bytes, expected %d bytes)", lengthInt, 8)
			}

			// MATCH: Check if passed integer a matches this section.
			// Expect that numbers are stored in little-endian byte-order.
			// However, SetBytes assumes big-endian, hence the bytes are reversed.
			bytes := a[currentPos : currentPos+lengthInt]
			aBig := big.NewInt(0).SetBytes(reverse(bytes))
			// Already checked above, but nevertheless check it.
			if !aBig.IsInt64() {
				return nil, fmt.Errorf("matchBytestring: integer larger than 64 bits (overflow)")
			}
			aInt := int64(aBig.Int64())

			if aInt == val {
				log.Infof("matchBytestring: (%d, %d) matches %d", currentPos, currentPos+lengthInt, val)
			} else {
				log.Infof("matchBytestring: (%d, %d) doesn't match (expected %d, got %d)", currentPos, currentPos+lengthInt, val, aInt)
				return nil, fmt.Errorf("matchBytestring: no match")
			}
			// 3. a variable
		} else {
			// Check if content is a variable in the binding n.
			if val, ok := n[*NewVariable(content)]; ok {
				if bval, ok := val.(*Constant); ok {
					// MATCH: Variable is bound in n.
					if bytes.Equal(a[currentPos:currentPos+lengthInt], bval.Value.([]byte)) {
						log.Infof("matchBytestring: (%d, %d) matches %x", currentPos, currentPos+lengthInt, val)
					} else {
						log.Infof("matchBytestring: (%d, %d) doesn't match (expected %x, got %x)", currentPos, currentPos+lengthInt, val, a[currentPos:currentPos+lengthInt])
						return nil, fmt.Errorf("matchBytestring: no match")
					}
				}
				// Check if content is a variable in the binding b.
			} else if _, ok := b[Variable{Name: content}]; ok {
				// MATCH: Variable is bound in b.
				// TODO: Need to add support for bytestrings to first.
				log.Warnf("matchBytestring: not implemented\n")
			} else {
				// EXTRACT and BIND
				log.Infof("matchBytestring: bound %s to %x", content, a[currentPos:currentPos+lengthInt])
				n[*NewVariable(content)] = NewConstantBytes(a[currentPos : currentPos+lengthInt])
			}
		}

		currentPos += lengthInt
	}

	return n, nil
}

func reverse(bytes []byte) []byte {
	s := make([]byte, len(bytes))
	copy(s, bytes)

	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}

	return s
}

func bytesToInt(bytes []byte) int {
	result := 0
	for i := 0; i < 4; i++ {
		result = result << 8
		result += int(bytes[i])

	}

	return result
}
*/
