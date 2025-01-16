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

import (
	"errors"
	"fmt"

	"github.com/specmon/specmon/utils"
)

type FormatType string

const (
	CatFunctionName string = "cat"

	FormatIntType    FormatType = "int"
	FormatByteType   FormatType = "byte"
	FormatStringType FormatType = "string"
)

var (
	ErrVariableInField   = errors.New("field contains a variable")
	ErrSliceTooShort     = errors.New("byte slice too short")
	ErrByteConversion    = errors.New("cannot convert bytes to constant")
	ErrVariableRedefined = errors.New("variable already defined")
	ErrConstantsNoMatch  = errors.New("constants do not match")
	ErrFunctioInField    = errors.New("field can only contain variable or constant")
	ErrFieldLength       = errors.New("invalid field length specifier")
)

/*
type FormatError struct {
	field *Function
	msg   string
}

func (e FormatError) Error() string {
	if e.msg != "" {
		return fmt.Sprintf("cannot parse format field '%s': %s", e.field, e.msg)
	}

	return fmt.Sprintf("cannot parse format field '%s'", e.field)
}
*/

func ParseFormat(fields []*Function, s []byte) (*Binding, error) {
	b := NewBinding()
	var n int

	for i, f := range fields {
		// Apply already parsed bindings to the format string.
		g := Must(AsFunction(f.Subst(b)))

		length, err := getFieldLength(g)
		if err != nil {
			return nil, err
		}

		// If the field contains a variable, it must be the last field in the format string.
		if length < 0 {
			if i < len(fields)-1 {
				// return nil, FormatError{g, "field contains a variable"}
				return nil, ErrVariableInField
			}

			length = len(s) - n
		}

		// Check if the bitstring is long enough to contain the field.
		if n+length > len(s) {
			return nil, ErrSliceTooShort
		}

		// Read 'length' bytes from the byte slice and convert to a constant based on format type.
		c, err := FormatTypeToConstant(FormatType(g.Name), s[n:n+length])
		if err != nil {
			return nil, ErrByteConversion
		}

		// If the field contains a variable, bind it to the constant.
		// Otherwise, check if the constant matches the expected value.
		switch t := g.Args[0].(type) {
		case *Variable:
			if _, ok := b.Get(t); ok {
				return nil, ErrVariableRedefined
			}

			b.Set(t, c)
		case *Constant[int], *Constant[[]byte], *Constant[string]:
			if !t.Equal(c) {
				return nil, ErrConstantsNoMatch
			}
		default:
			return nil, ErrFunctioInField
		}

		// Move to the next field in the byte slice.
		n += length
	}

	return b, nil
}

// BytesToConstant converts a byte slice to a constant of type T.
func BytesToConstant[T ConstantConstraint](s []byte) (*Constant[T], error) {
	var result T

	switch v := any(&result).(type) {
	case *int:
		i, err := utils.BytesToInt(s, internalByteOrder())
		if err != nil {
			return nil, fmt.Errorf("cannot convert %s to int: %w", s, err)
		}

		*v = i
	case *[]byte:
		*v = s
	case *string:
		*v = string(s)
	default:
		return nil, fmt.Errorf("unsupported type: %T", v)
	}

	return NewConstant[T](result), nil
}

// Constructs a byte sequence out of a format string and a binding.
func FormatToBytes(fields []*Function, b *Binding) ([]byte, error) {
	var result []byte

	for _, f := range fields {
		g := Must(AsFunction(f.Subst(b)))

		if !IsGround(g) {
			// return nil, fmt.Errorf("non-ground binding %s for %s", b, g)
			return nil, errors.New("non-ground binding")
		}

		var err error
		var value []byte

		switch FormatType(g.Name) {
		case FormatIntType, FormatByteType:
			value, err = AsBytes(g.Args[0])
			if err != nil {
				// return nil, fmt.Errorf("cannot convert %s to bytes: %w", g.Args[0], err)
				return nil, errors.New("cannot convert to bytes")
			}
		case FormatStringType:
			value = []byte(Must(AsConstant[string](g.Args[0])).Value)
		}

		if len(g.Args) == 2 {
			length, err := AsInt(g.Args[1])
			if err != nil {
				// return nil, fmt.Errorf("invalid length specifier %s: %w", g.Args[1], err)
				return nil, errors.New("invalid length specifier")
			}
			if length != len(value) {
				// return nil, fmt.Errorf("length specifier %d does not match actual length %d", length, len(value))
				return nil, errors.New("length specifier does not match actual length")
			}
		}

		result = append(result, value...)
	}

	return result, nil
}

// getFieldLength returns the length of the field specified by f.
// If the field contains a variable, -1 is returned.
func getFieldLength(f *Function) (int, error) {
	var length int

	// Field contains a length specifier.
	if len(f.Args) == 2 {
		// Variables in length spcifier should already been replaced at this point.
		b, err := AsInt(f.Args[1])
		if err != nil {
			return length, ErrFieldLength
		}

		return b, nil
	}

	// Field contains no length specifier.
	// Try to convert the field to a byte slice and report its length.
	if b, err := AsBytes(f.Args[0]); err == nil {
		return len(b), nil
	}

	// Field contains a variable.
	// It must be the last field in the format string.
	if _, err := AsVariable(f.Args[0]); err == nil {
		return -1, nil
	}

	return 0, ErrFieldLength
}

// FormatTypeToConstant converts a byte slice to a constant based on the format type.
func FormatTypeToConstant(t FormatType, s []byte) (Term, error) {
	switch t {
	case FormatIntType:
		return BytesToConstant[int](s)
	case FormatByteType:
		return BytesToConstant[[]byte](s)
	case FormatStringType:
		return BytesToConstant[string](s)
	}

	return nil, fmt.Errorf("unsupported format type: %s", t)
}
