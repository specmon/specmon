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
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"slices"
	"strconv"
	"strings"

	"github.com/specmon/specmon/data"
	"github.com/specmon/specmon/utils"
)

const (
	ConstantType      = "constant"
	VariableType      = "variable"
	FunctionType      = "function"
	PairFunctionName  = "pair"
	SliceFunctionName = "slice"
	ReverseFuncName   = "reverse"
	ExpFunctionName   = "exp"
	AndFunctionName   = "and"
	OrFunctionName    = "or"
	AddFunctionName   = "add"
	XorFunctionName   = "xor"
	BinaryArity       = 2
	TernaryArity      = 3

	PublicPrefix = "$"
)

var ReservedNames = data.NewSet[string](
	PairFunctionName,
	SliceFunctionName,
	CatFunctionName,
	AddFunctionName,
	AndFunctionName,
	OrFunctionName,
	XorFunctionName,
	string(FormatIntType),
	string(FormatStringType),
	string(FormatByteType))

var (
	ErrConstantConversion = errors.New("cannot convert term to constant")
	ErrVariableConversion = errors.New("cannot convert term to variable")
	ErrFunctionConversion = errors.New("cannot convert term to function")
	ErrIntConversion      = errors.New("cannot convert term to int")

	ErrTermByteConversion = errors.New("cannot convert to byte slice")

	ErrNameOrArgMismatch      = errors.New("name or number of arguments do not match")
	ErrExpectedFormat         = errors.New("expected format")
	ErrInvalidFormatFunc      = errors.New("invalid format: expected function")
	ErrConstantByteConversion = errors.New("cannot convert constant to bytes")
	ErrInvalidFormat          = errors.New("invalid format")
	ErrOccursCheckFailed      = errors.New("occurs check failed")
	ErrUnknownType            = errors.New("unknown type")

	ErrInvalidFormatFunction = errors.New("invalid format: expected byte(), string(), int()")

	ErrUnaryArity   = errors.New("expected arity 1")
	ErrBinaryArity  = errors.New("expected arity 2")
	ErrTernaryArity = errors.New("expected arity 3")
	ErrInvalidType  = errors.New("invalid type for arithmetic function")
)

type Term interface {
	fmt.Stringer
	Equal(t Term) bool
	GetType() string
	fromWeakTerm(w WeakTerm) error
	JSON() string

	Unify(other Term) (*Binding, error)
	Subst(b *Binding) Term

	Hash() uint64
}

type ConversionError struct {
	from Term
	to   Term
}

func (t *ConversionError) Error() string {
	return fmt.Sprintf("cannot convert '%s' to %s'", t.from, t.to)
}

type ConstantConstraint interface {
	int | string | []byte
}

type Constant[T ConstantConstraint] struct {
	Value T      `json:"value"`
	Type  string `json:"type"`
}

type Variable struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Function struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Args []Term `json:"args"`
}

func (c *Constant[T]) GetType() string { return c.Type }
func (v *Variable) GetType() string    { return v.Type }
func (f *Function) GetType() string    { return f.Type }

func NewConstant[T ConstantConstraint](value T) *Constant[T] {
	return &Constant[T]{
		Value: value,
		Type:  ConstantType,
	}
}

func NewVariable(name string) *Variable {
	return &Variable{
		Name: name,
		Type: VariableType,
	}
}

func NewFunction(name string, args []Term) *Function {
	if name == "" {
		panic("function name cannot be empty")
	}

	return &Function{
		Name: name,
		Type: FunctionType,
		Args: args,
	}
}

func (c *Constant[T]) Equal(t Term) bool {
	b1, err := AsBytes(c)
	if err != nil {
		return false
	}

	b2, err := AsBytes(t)
	if err != nil {
		return false
	}

	return bytes.Equal(b1, b2)
}

func (v *Variable) Equal(t Term) bool {
	v2, err := AsVariable(t)
	if err != nil {
		return false
	}

	return v.Type == v2.Type &&
		v.Name == v2.Name
}

func (f *Function) Equal(a Term) bool {
	t2, err := AsFunction(a)
	if err != nil {
		return false
	}

	if f.Type != t2.Type || f.Name != t2.Name || len(f.Args) != len(t2.Args) {
		return false
	}

	for i := range f.Args {
		if !f.Args[i].Equal(t2.Args[i]) {
			return false
		}
	}

	return true
}

func (c *Constant[T]) String() string {
	switch t := any(&c.Value).(type) {
	case *int:
		return strconv.Itoa(*t)
	case *string:
		return fmt.Sprintf("'%s'", *t)
	case *[]byte:
		return fmt.Sprintf("0x%x", *t)
	default:
		return "invalid type"
	}
}

func (v *Variable) String() string {
	return v.Name
}

func (f *Function) String() string {
	openDelim, closeDelim := "(", ")"
	fName := f.Name
	if f.Name == PairFunctionName {
		openDelim, closeDelim = "<", ">"
		fName = ""
	}

	if f.Args == nil {
		return fmt.Sprintf("%s%s%s", fName, openDelim, closeDelim)
	}

	var str string
	for i, arg := range f.Args {
		switch {
		case arg == nil:
			str += "nil, "
		case i == len(f.Args)-1:
			str += arg.String()
		default:
			str += fmt.Sprintf("%s, ", arg)
		}
	}
	str = strings.TrimSuffix(str, ", ")

	return fmt.Sprintf("%s%s%s%s", fName, openDelim, str, closeDelim)
}

func (c *Constant[T]) Hash() uint64 {
	h := fnv.New64a()

	h.Write([]byte(c.Type))

	switch v := any(c.Value).(type) {
	case int:
		buf := utils.IntToBytes(v, binary.LittleEndian)
		h.Write(buf)
	case string:
		h.Write([]byte(v))
	case []byte:
		h.Write(v)
	}

	return h.Sum64()
}

func (v *Variable) Hash() uint64 {
	h := fnv.New64a()

	h.Write([]byte(v.Name))
	h.Write([]byte(v.Type))

	return h.Sum64()
}

func (f *Function) Hash() uint64 {
	h := fnv.New64a()
	h.Write([]byte(f.Name))
	h.Write([]byte(f.Type))

	for _, arg := range f.Args {
		hash := arg.Hash()
		var buf [8]byte
		binary.LittleEndian.PutUint64(buf[:], hash)
		h.Write(buf[:])
	}

	return h.Sum64()
}

func toJSONString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}

	return string(b)
}

func (c *Constant[T]) JSON() string {
	return toJSONString(c)
}

// MarshalJSON implements the json.Marshaler interface.
// The value is converted to a string as otherwise the
// default marshalling would convert a []byte value to base64.
func (c *Constant[T]) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(struct {
		Value string `json:"value"`
		Type  string `json:"type"`
	}{strings.Trim(c.String(), "'"), c.Type})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal constant to JSON: %w", err)
	}

	return b, nil
}

func (v *Variable) JSON() string {
	return toJSONString(v)
}

func (f *Function) JSON() string {
	return toJSONString(f)
}

func (c *Constant[T]) fromWeakTerm(w WeakTerm) error {
	if w.Type != ConstantType {
		return fmt.Errorf("expected type '%s', got '%s'", ConstantType, w.Type)
	}

	t, ok := w.Value.(T)
	if !ok {
		return fmt.Errorf("cannot convert '%v' into constant", w.Value)
	}

	c.Value = t
	c.Type = w.Type

	return nil
}

func (v *Variable) fromWeakTerm(w WeakTerm) error {
	if w.Type != VariableType {
		return fmt.Errorf("expected type '%s', got '%s'", VariableType, w.Type)
	}
	v.Name = w.Name
	v.Type = w.Type

	return nil
}

func (f *Function) fromWeakTerm(w WeakTerm) error {
	if w.Type != FunctionType {
		return fmt.Errorf("expected type '%s', got '%s'", FunctionType, w.Type)
	}
	f.Name = w.Name
	f.Type = w.Type

	for _, arg := range w.Args {
		switch arg.Type {
		case ConstantType:
			switch r := arg.Value.(type) {
			// These types can be safely cast to int.
			case int8, int16, int32, int:
				c := NewConstant[int](r.(int))
				f.Args = append(f.Args, c)
				// This can only be safely cast if int coincides to int64.
			case int64:
				if int64(int(r)) != r {
					return fmt.Errorf("integer overflow on %d", r)
				}
				c := NewConstant[int](int(r))
				f.Args = append(f.Args, c)
				// These can only be safely cast if they are basically integers.
			case float32:
				if float32(int(r)) != r {
					return fmt.Errorf("floats are not supported, got %f", r)
				}
				c := NewConstant[int](int(r))
				f.Args = append(f.Args, c)
			case float64:
				if float64(int(r)) != r {
					return fmt.Errorf("floats are not supported, got %f", r)
				}
				c := NewConstant[int](int(r))
				f.Args = append(f.Args, c)
			case string:
				if strings.HasPrefix(r, "0x") {
					bytes, err := hex.DecodeString(r[2:])
					if err == nil {
						c := NewConstant[[]byte](bytes)
						f.Args = append(f.Args, c)

						continue
					}
				}

				c := NewConstant[string](r)
				f.Args = append(f.Args, c)
			case []byte:
				c := NewConstant[[]byte](r)
				f.Args = append(f.Args, c)
			case nil:
				c := NewConstant[[]byte](nil)
				f.Args = append(f.Args, c)
			default:
				return fmt.Errorf("unsupported type of %v", r)
			}
		case VariableType:
			var v Variable
			if err := v.fromWeakTerm(arg); err != nil {
				return err
			}
			f.Args = append(f.Args, &v)
		case FunctionType:
			var tp Function
			if err := tp.fromWeakTerm(arg); err != nil {
				return err
			}
			f.Args = append(f.Args, &tp)
		default:
			return fmt.Errorf("unknown type '%s'", arg.Type)
		}
	}

	return nil
}

func AsConstant[T ConstantConstraint](t Term) (*Constant[T], error) {
	c, ok := t.(*Constant[T])

	if !ok {
		// return nil, &ConversionError{t, c}
		return nil, ErrConstantConversion
	}

	return c, nil
}

func AsVariable(t Term) (*Variable, error) {
	v, ok := t.(*Variable)

	if !ok {
		// return nil, &ConversionError{t, v}
		return nil, ErrVariableConversion
	}

	return v, nil
}

func AsFunction(t Term) (*Function, error) {
	f, ok := t.(*Function)

	if !ok {
		// return nil, &ConversionError{t, f}
		return nil, ErrFunctionConversion
	}

	return f, nil
}

func AsInt(t Term) (int, error) {
	switch c := any(t).(type) {
	case *Constant[int]:
		return c.Value, nil
	case *Constant[[]byte]:
		v, err := utils.BytesToInt(c.Value, internalByteOrder())
		if err != nil {
			// return 0, fmt.Errorf("cannot convert constant to int: %w", err)
			return 0, ErrIntConversion
		}

		return v, nil
	}

	return 0, ErrIntConversion
}

func AsBytes(t Term) ([]byte, error) {
	switch c := any(t).(type) {
	case *Constant[int]:
		return utils.IntToBytes(c.Value, internalByteOrder()), nil
	case *Constant[string]:
		return []byte(c.Value), nil
	case *Constant[[]byte]:
		return c.Value, nil
	}

	// return nil, fmt.Errorf("cannot convert '%s' to byte slice", t)
	return nil, ErrTermByteConversion
}

func Must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}

	return v
}

func (v *Variable) IsPublic() bool {
	return strings.HasPrefix(v.Name, PublicPrefix)
}

func (f *Function) UnmarshalJSON(data []byte) error {
	var w WeakTerm
	if err := json.Unmarshal(data, &w); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return f.fromWeakTerm(w)
}

type WeakTerm struct {
	Name  string     `json:"name,omitempty"`
	Type  string     `json:"type,omitempty"`
	Value any        `json:"value,omitempty"`
	Args  []WeakTerm `json:"args,omitempty"`
}

func Vars(t Term) []*Variable {
	var vars []*Variable

	switch t.GetType() {
	case FunctionType:
		t := Must(AsFunction(t))
		for _, arg := range t.Args {
			vars = append(vars, Vars(arg)...)
		}
	case VariableType:
		v := Must(AsVariable(t))
		vars = append(vars, v)
	}

	return vars
}

func IsGround(t Term) bool {
	return len(Vars(t)) == 0
}

// Substitute variable x in g with t.
func Subst(x Variable, t, g Term) Term {
	// log.Printf("%s[ %v -> %s ]", g, x, t)

	switch g.GetType() {
	case VariableType:
		v := Must(AsVariable(g))
		if v.Name == x.Name {
			return t
		}
	case FunctionType:
		o := Must(AsFunction(g))

		var u Function
		u.Name = o.Name
		u.Type = o.Type

		for _, arg := range o.Args {
			u.Args = append(u.Args, Subst(x, t, arg))
		}

		return &u
	case ConstantType:
		return g
	}

	return g
}

// Apply binding b to term g.
func SubstBinding(b *Binding, g Term) Term {
	next := g

	b.Iterate(func(x, t Term) bool {
		next = Replace(x, t, next)

		return true
	})

	return next
}

func (c *Constant[T]) Unify(t Term) (*Binding, error) {
	return Unify(c, t)
}

func (v *Variable) Unify(t Term) (*Binding, error) {
	return Unify(v, t)
}

func (f *Function) Unify(t Term) (*Binding, error) {
	return Unify(f, t)
}

// Since `Subst` only replaces variables, the type of
// constant values is preserved.
func (c *Constant[T]) Subst(b *Binding) Term {
	return SubstBinding(b, c)
}

func (v *Variable) Subst(b *Binding) Term {
	return SubstBinding(b, v)
}

func (f *Function) Subst(b *Binding) Term {
	return SubstBinding(b, f)
}

func Unify(t1, t2 Term) (*Binding, error) {
	b := NewBinding()

	a1, err := Evaluate(t1)
	if err != nil {
		log.Fatal(err)

		return nil, err
	}

	a2, err := Evaluate(t2)
	if err != nil {
		log.Fatal(err)

		return nil, err
	}

	err = unify(a1, a2, b)

	return b, err
}

type UnificationError struct {
	t1  Term
	t2  Term
	msg string
}

func (e *UnificationError) Error() string {
	if e.msg != "" {
		return fmt.Sprintf("cannot unify '%s' and '%s': %s", e.t1, e.t2, e.msg)
	}

	return fmt.Sprintf("cannot unify '%s' and '%s'", e.t1, e.t2)
}

func unify(a1, a2 Term, b *Binding) error {
	// Fast path: check types first before expensive Equal()
	t1Type := a1.GetType()
	t2Type := a2.GetType()

	// Early termination for obviously incompatible types
	if t1Type == ConstantType && t2Type == ConstantType {
		// For constants, Equal is relatively cheap, do it early
		if !a1.Equal(a2) {
			return ErrConstantsNoMatch
		}
		return nil
	}

	// For functions, check name/arity before full equality
	if t1Type == FunctionType && t2Type == FunctionType {
		f1 := Must(AsFunction(a1))
		f2 := Must(AsFunction(a2))

		// Quick rejection: name or arity mismatch
		if f1.Name != f2.Name || len(f1.Args) != len(f2.Args) {
			return ErrNameOrArgMismatch
		}

		// Now check full equality (which recurses into args)
		if a1.Equal(a2) {
			return nil
		}

		// Not equal but compatible, continue with unification
		for i := range f1.Args {
			if err := unify(f1.Args[i], f2.Args[i], b); err != nil {
				return err
			}
		}
		return nil
	}

	// For other combinations, do standard equality check
	if a1.Equal(a2) {
		return nil
	}

	switch {
	case t1Type == FunctionType && t2Type == FunctionType:
		// Already handled above
		return nil
	case t1Type == FunctionType && t2Type == VariableType:
		// Swap the order of the terms and try again.
		return unify(a2, a1, b)
	case t1Type == FunctionType && t2Type == ConstantType:
		// A function is unifiable with a constant if
		// - the function is a format and
		// - the evaluated format is equal to the constant.
		f, _ := AsFunction(a1)

		if f.Name != CatFunctionName {
			// return &UnificationError{a1, a2, "expected format"}
			return ErrExpectedFormat
		}

		fields := make([]*Function, len(f.Args))
		for i, t := range f.Args {
			r, err := AsFunction(t)
			if err != nil {
				// return &UnificationError{a1, a2, "invalid format: expected function"}
				return ErrInvalidFormat
			}
			fields[i] = r
		}

		bytes, err := AsBytes(a2)
		if err != nil {
			// return &UnificationError{a1, a2, "cannot convert constant to bytes"}
			return ErrConstantByteConversion
		}

		formatBinding, err := ParseFormat(fields, bytes)
		if err != nil {
			// FIXME: err.Error() allocates a significant amount of memory.
			// return &UnificationError{a1, a2, err.Error()}
			// return &UnificationError{a1, a2, "invalid format"}
			return ErrInvalidFormat
		}

		formatBinding.Iterate(func(k, v Term) bool {
			b.Set(k, v)

			return true
		})

		return nil
	case t1Type == ConstantType && (t2Type == FunctionType || t2Type == VariableType):
		// Swap the order of the terms and try again.
		return unify(a2, a1, b)
	case t1Type == VariableType:
		v := Must(AsVariable(a1))

		if slices.Contains(Vars(a2), v) {
			// return &UnificationError{a1, a2, "occurs check failed"}
			return ErrOccursCheckFailed
		}

		b.Iterate(func(x, t Term) bool {
			b.Set(x, Subst(*v, a2, t))

			return true
		})

		b.Set(v, a2)
	case t1Type == ConstantType && t2Type == ConstantType:
		// Already handled at the top with early termination
		return nil
	default:
		return ErrUnknownType
	}

	return nil
}

// Unify t or its subterms with g and replace it by h with the binding applied.
func UnifyReplace(t, g, h Term) Term {
	// If t is not a function, we don't need to replace anything.
	f, err := AsFunction(t)
	if err != nil {
		return t
	}

	// The order is important here:
	// We want a binding from the variables in g to the ones in t.
	if b, err := Unify(g, t); err == nil {
		return SubstBinding(b, h)
	}

	u := NewFunction(f.Name, make([]Term, len(f.Args)))
	for i, s := range f.Args {
		u.Args[i] = UnifyReplace(s, g, h)
	}

	return u
}

func UnifyReplaceRecursive(t, g, h Term) Term {
	current := t

	// Keep applying replacements until no more changes occur
	for {
		previous := current
		current = UnifyReplace(current, g, h)

		// If no changes occurred, we're done
		if current.Equal(previous) {
			break
		}
	}

	return current
}

// Find a (sub)term g of t such that p(g) holds and replace it with r(g) in t.
// Note: t == g is allowed.
func FindReplaceBy(t Term, p func(Term) bool, r func(Term) Term) Term {
	if p(t) {
		return r(t)
	}

	f, err := AsFunction(t)
	if err != nil {
		return t
	}

	var modified bool
	var args []Term // Delay allocation
	for i, s := range f.Args {
		transformed := FindReplaceBy(s, p, r)
		if transformed != s {
			if !modified {
				// Allocate on first modification
				args = make([]Term, len(f.Args))
				copy(args, f.Args) // Copy existing terms up to i
				modified = true
			}
		}
		if modified {
			args[i] = transformed
		}
	}

	if !modified {
		return t
	}

	return NewFunction(f.Name, args)
}

// Replace replaces all occurrences of x with g in t.
// Note: t == x is allowed.
func Replace(x, g, t Term) Term {
	return FindReplaceBy(t, func(s Term) bool {
		return s.Equal(x)
	}, func(_ Term) Term {
		return g
	})
}

// ReplaceSubterms replaces all occurrences of x with g in t.
// Note: t == x is disallowed.
func ReplaceSubterms(x, g, t Term) Term {
	return FindReplaceBy(t, func(s Term) bool {
		return s.Equal(x) && !s.Equal(t)
	}, func(_ Term) Term {
		return g
	})
}

func ReplaceBinding(t Term, b *Binding) Term {
	return FindReplaceBy(t, func(s Term) bool {
		_, ok := b.Get(s)

		return ok && !s.Equal(t)
	}, func(s Term) Term {
		v, _ := b.Get(s)

		return v
	})
}

func ReplaceFormats(t Term) Term {
	s, err := Evaluate(t)
	if err != nil {
		panic(err)
	}

	return s
}

func Evaluate(t Term) (Term, error) {
	f, err := AsFunction(t)
	if err != nil {
		return t, nil
	}

	newArgs, modified, err := evaluateArguments(f.Args)
	if err != nil {
		return nil, err
	}

	switch f.Name {
	case CatFunctionName:
		return handleCatFunction(f, newArgs, modified)
	case AddFunctionName, AndFunctionName, OrFunctionName, XorFunctionName:
		return handleArithmeticFunction(f, newArgs, modified)
	case SliceFunctionName:
		return handleSliceFunction(f, newArgs, modified)
	case ReverseFuncName:
		return handleReverseFunction(f, newArgs, modified)
	default:
		if !modified {
			return t, nil
		}

		return NewFunction(f.Name, newArgs), nil
	}
}

// evaluateArguments evaluates each argument and checks if any have changed.
// Returns the new arguments, a boolean indicating if any argument changed, and any error encountered.
func evaluateArguments(args []Term) ([]Term, bool, error) {
	modified := false
	var newArgs []Term // Initialize newArgs as nil; allocate only on modification

	for i, arg := range args {
		evaluatedArg, err := Evaluate(arg)
		if err != nil {
			return nil, false, err
		}

		// Check if there's a change
		if !evaluatedArg.Equal(arg) {
			if !modified {
				// If modified for the first time, allocate newArgs and copy existing values
				newArgs = make([]Term, len(args))
				copy(newArgs, args) // Copy original args up to current index
				modified = true
			}
			newArgs[i] = evaluatedArg
		} else if modified {
			// If already modified but current arg is equal, just copy the original
			newArgs[i] = arg
		}
	}

	if !modified {
		// If no modifications were made, return the original args
		return args, false, nil
	}

	return newArgs, true, nil
}

func handleCatFunction(f *Function, args []Term, modified bool) (Term, error) {
	fields := make([]*Function, len(f.Args))

	var err error
	for i, a := range args {
		fields[i], err = AsFunction(a)
		if err != nil {
			return nil, ErrInvalidFormatFunction
		}
	}

	bytes, err := FormatToBytes(fields, NewBinding())
	if err != nil {
		if modified {
			return NewFunction(f.Name, args), nil
		}

		return f, nil
	}

	return NewConstant[[]byte](bytes), nil
}

func handleArithmeticFunction(f *Function, args []Term, modified bool) (Term, error) {
	if len(f.Args) != BinaryArity {
		return nil, ErrBinaryArity
	}

	left, err := AsInt(args[0])
	if err != nil {
		if modified {
			return NewFunction(f.Name, args), nil
		}

		return f, nil
	}

	right, err := AsInt(args[1])
	if err != nil {
		if modified {
			return NewFunction(f.Name, args), nil
		}

		return f, nil
	}

	var result int
	switch f.Name {
	case AddFunctionName:
		result = left + right
	case AndFunctionName:
		result = left & right
	case OrFunctionName:
		result = left | right
	case XorFunctionName:
		result = left ^ right
	}

	// Result type is the same as the type of the first argument.
	switch ft := args[0].(type) {
	case *Constant[int]:
		return NewConstant[int](result), nil
	case *Constant[[]byte]:
		b := utils.IntToBytes(result, internalByteOrder())

		return NewConstant[[]byte](b[:len(ft.Value)]), nil
	default:
		return nil, ErrInvalidType
	}
}

func handleSliceFunction(f *Function, args []Term, modified bool) (Term, error) {
	if len(args) != TernaryArity {
		return nil, ErrTernaryArity
	}

	data, err := AsBytes(args[0])
	if err != nil {
		if modified {
			return NewFunction(f.Name, args), nil
		}
		return f, nil
	}

	start, err := AsInt(args[1])
	if err != nil {
		if modified {
			return NewFunction(f.Name, args), nil
		}
		return f, nil
	}

	end, err := AsInt(args[2])
	if err != nil {
		if modified {
			return NewFunction(f.Name, args), nil
		}
		return f, nil
	}

	dataLen := len(data)

	// Resolve start index
	resolvedStart := start
	if resolvedStart < 0 {
		resolvedStart = dataLen + resolvedStart
	}

	// Resolve end index
	resolvedEnd := end
	if end == 0 { // Special case: 0 means "until the end"
		resolvedEnd = dataLen
	} else if end < 0 {
		resolvedEnd = dataLen + end
	}

	// Clamp indices to the bounds of the data slice
	if resolvedStart < 0 {
		resolvedStart = 0
	}
	if resolvedStart > dataLen {
		resolvedStart = dataLen
	}

	if resolvedEnd < 0 {
		resolvedEnd = 0
	}
	if resolvedEnd > dataLen {
		resolvedEnd = dataLen
	}

	// If start is after end, return an empty slice
	if resolvedStart >= resolvedEnd {
		return NewConstant[[]byte]([]byte{}), nil
	}

	return NewConstant[[]byte](data[resolvedStart:resolvedEnd]), nil
}

func handleReverseFunction(f *Function, args []Term, modified bool) (Term, error) {
	if len(args) != 1 {
		return nil, ErrUnaryArity
	}

	arg := args[0]

	originalBytes, err := AsBytes(arg)
	if err != nil {
		// If the argument cannot be converted to bytes (e.g., it's a variable),
		// return the function call, possibly with an evaluated argument.
		if modified {
			return NewFunction(f.Name, args), nil
		}
		return f, nil
	}

	// Slices.Reverse is in-place, so we must copy the data first
	// to avoid modifying the original constant's value.
	reversedBytes := make([]byte, len(originalBytes))
	copy(reversedBytes, originalBytes)
	slices.Reverse(reversedBytes)

	// Preserve the original constant type.
	switch arg.(type) {
	case *Constant[int]:
		// The size of the byte slice is preserved, so this conversion is safe.
		newValue, _ := utils.BytesToInt(reversedBytes, internalByteOrder())
		return NewConstant[int](newValue), nil
	case *Constant[string]:
		return NewConstant[string](string(reversedBytes)), nil
	case *Constant[[]byte]:
		return NewConstant[[]byte](reversedBytes), nil
	default:
		// This case should not be reached if AsBytes succeeds, but as a fallback.
		if modified {
			return NewFunction(f.Name, args), nil
		}
		return f, nil
	}
}

type Terms []Term

func (ts Terms) Vars() []*Variable {
	var vars []*Variable

	for _, t := range ts {
		vars = append(vars, Vars(t)...)
	}

	return vars
}

func AsTerms[T Term](ts []T) []Term {
	terms := make([]Term, len(ts))

	for i, t := range ts {
		terms[i] = t
	}

	return terms
}

func (ts Terms) Subst(b *Binding) Terms {
	terms := make(Terms, len(ts))

	for i := range ts {
		terms[i] = ts[i].Subst(b)
	}

	return terms
}

func internalByteOrder() binary.ByteOrder {
	return binary.LittleEndian
}
