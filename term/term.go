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

package term

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/specmon/specmon/data"
	"github.com/specmon/specmon/utils"
)

const (
	ConstantType       = "constant"
	VariableType       = "variable"
	FunctionType       = "function"
	IntConstantKind    = "int"
	StringConstantKind = "string"
	BytesConstantKind  = "bytes"
	PairFunctionName   = "pair"
	SliceFunctionName  = "slice"
	ReverseFuncName    = "reverse"
	ExpFunctionName    = "exp"
	AndFunctionName    = "and"
	OrFunctionName     = "or"
	XorFunctionName    = "xor"
	NotFunctionName    = "not"
	AddFunctionName    = "add"
	UnaryArity         = 1
	BinaryArity        = 2
	TernaryArity       = 3

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
	NotFunctionName,
	ReverseFuncName,
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
	ErrEvaluation             = errors.New("term evaluation failed")

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
	int64 | string | []byte
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

// evaluatableFunctions contains function names that Evaluate() can reduce to constants.
var evaluatableFunctions = map[string]bool{
	CatFunctionName:   true,
	AddFunctionName:   true,
	AndFunctionName:   true,
	OrFunctionName:    true,
	XorFunctionName:   true,
	NotFunctionName:   true,
	SliceFunctionName: true,
	ReverseFuncName:   true,
}

func (c *Constant[T]) GetType() string { return c.Type }
func (v *Variable) GetType() string    { return v.Type }
func (f *Function) GetType() string    { return f.Type }

// MayEvalToConstant returns true if this function could potentially
// evaluate to a constant value via Evaluate().
// Returns false for unknown functions since Evaluate() doesn't reduce them.
func (f *Function) MayEvalToConstant() bool {
	if f == nil {
		return false
	}
	return evaluatableFunctions[f.Name]
}

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
	// Fast path: when t is a Constant of the same generic
	// instantiation (T) compare typed values directly. Avoids the
	// AsBytes allocation each side otherwise pays (utils.IntToBytes
	// for int64 constants, []byte(string) for string constants), which
	// dominated Fact.Equal cost in the hot config-dedup / conflictSet
	// paths.
	if other, ok := any(t).(*Constant[T]); ok {
		switch v1 := any(c.Value).(type) {
		case int64:
			v2 := any(other.Value).(int64)
			return v1 == v2
		case string:
			v2 := any(other.Value).(string)
			return v1 == v2
		case []byte:
			v2 := any(other.Value).([]byte)
			return bytes.Equal(v1, v2)
		}
	}

	// Slow path: t has a different ConstantConstraint instantiation
	// (e.g. comparing *Constant[int64] to *Constant[[]byte]). Fall back
	// to byte-wise equality through AsBytes so heterogeneous constants
	// that share a byte representation still compare equal.
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

// EqualWithKind compares terms recursively without coercing constant kinds.
// Constants must have the same kind and equal values. Nil and empty byte
// slices compare equal, as they do with Term.Equal.
func EqualWithKind(left, right Term) bool {
	switch l := left.(type) {
	case *Function:
		r, ok := right.(*Function)
		return ok && l.Type == r.Type && l.Name == r.Name && slices.EqualFunc(l.Args, r.Args, EqualWithKind)
	case *Constant[int64]:
		_, ok := right.(*Constant[int64])
		return ok && l.Equal(right)
	case *Constant[string]:
		_, ok := right.(*Constant[string])
		return ok && l.Equal(right)
	case *Constant[[]byte]:
		_, ok := right.(*Constant[[]byte])
		return ok && l.Equal(right)
	default:
		return left.Equal(right)
	}
}

func (c *Constant[T]) String() string {
	switch t := any(&c.Value).(type) {
	case *int64:
		return strconv.FormatInt(*t, 10)
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

// Hash returns a 64-bit FNV-1a digest of the constant's type tag and
// value bytes. Recomputed on every call - terms are mutable through
// exported fields (Value), so any cache would risk going stale on
// post-construction mutation. The recompute is one FNV pass over a
// short byte slice; profiling showed a lazy cache wins at most a few
// percent while introducing a data race (concurrent calls racing on
// the cache write).
func (c *Constant[T]) Hash() uint64 {
	h := fnv.New64a()

	h.Write([]byte(c.Type))

	switch v := any(c.Value).(type) {
	case int64:
		buf := utils.IntToBytes(v, binary.LittleEndian)
		h.Write(buf)
	case string:
		h.Write([]byte(v))
	case []byte:
		h.Write(v)
	}

	return h.Sum64()
}

// Hash returns a 64-bit FNV-1a digest of the variable's name and type
// tag. Recomputed on every call; see Constant.Hash for rationale.
func (v *Variable) Hash() uint64 {
	h := fnv.New64a()

	h.Write([]byte(v.Name))
	h.Write([]byte(v.Type))

	return h.Sum64()
}

// Hash returns a 64-bit FNV-1a digest of the function's name, type
// tag, and the recursively-hashed args. Recomputed on every call; see
// Constant.Hash for rationale.
//
// Cost note: a deeply nested Function costs O(total subterms) FNV
// work per call. In the monitor hot path each Function is built from
// freshly-constructed args and hashed once via Fact.Hash, which IS
// cached on the fact wrapper (rule/fact.go). Variables that recur
// across many facts are cheap to rehash because their hash input is
// just (name, type) bytes.
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
func (c *Constant[T]) MarshalJSON() ([]byte, error) {
	var kind string
	var value any
	switch v := any(c.Value).(type) {
	case int64:
		kind = IntConstantKind
		value = strconv.FormatInt(v, 10)
	case string:
		kind = StringConstantKind
		value = v
	case []byte:
		kind = BytesConstantKind
		if v != nil {
			value = "0x" + hex.EncodeToString(v)
		}
	}

	b, err := json.Marshal(struct {
		Type      string `json:"type"`
		ConstKind string `json:"const_kind"`
		Value     any    `json:"value"`
	}{c.Type, kind, value})
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
	f.Args = make([]Term, 0, len(w.Args))

	for i, arg := range w.Args {
		switch arg.Type {
		case ConstantType:
			constant, err := constantFromWeakTerm(arg)
			if err != nil {
				return fmt.Errorf("argument %d: %w", i, err)
			}
			f.Args = append(f.Args, constant)
		case VariableType:
			var v Variable
			if err := v.fromWeakTerm(arg); err != nil {
				return fmt.Errorf("argument %d: %w", i, err)
			}
			f.Args = append(f.Args, &v)
		case FunctionType:
			var tp Function
			if err := tp.fromWeakTerm(arg); err != nil {
				return fmt.Errorf("argument %d: %w", i, err)
			}
			f.Args = append(f.Args, &tp)
		default:
			return fmt.Errorf("argument %d: unknown type '%s'", i, arg.Type)
		}
	}

	return nil
}

func constantFromWeakTerm(w WeakTerm) (Term, error) {
	if w.Type != ConstantType {
		return nil, fmt.Errorf("expected type '%s', got '%s'", ConstantType, w.Type)
	}

	switch w.ConstKind {
	case IntConstantKind:
		if !w.valuePresent {
			return nil, errors.New("missing typed integer value")
		}
		var spelling string
		switch value := w.Value.(type) {
		case string:
			spelling = value
		case json.Number:
			spelling = value.String()
		default:
			return nil, fmt.Errorf("typed integer has incompatible value %T", w.Value)
		}
		integer, err := parseCanonicalInt(spelling)
		if err != nil {
			return nil, fmt.Errorf("invalid typed integer %q: %w", spelling, err)
		}
		return NewConstant(integer), nil
	case StringConstantKind:
		if !w.valuePresent {
			return nil, errors.New("missing typed string value")
		}
		value, ok := w.Value.(string)
		if !ok {
			return nil, fmt.Errorf("typed string has incompatible value %T", w.Value)
		}
		return NewConstant(value), nil
	case BytesConstantKind:
		if !w.valuePresent {
			return nil, errors.New("missing typed bytes value")
		}
		if w.Value == nil {
			return NewConstant[[]byte](nil), nil
		}
		value, ok := w.Value.(string)
		if !ok {
			return nil, fmt.Errorf("typed bytes have incompatible value %T", w.Value)
		}
		decoded, err := decodeTypedBytes(value)
		if err != nil {
			return nil, err
		}
		return NewConstant(decoded), nil
	case "":
		return legacyConstant(w)
	default:
		return nil, fmt.Errorf("unknown const_kind %q", w.ConstKind)
	}
}

func legacyConstant(w WeakTerm) (Term, error) {
	if !w.valuePresent || w.Value == nil {
		return NewConstant[[]byte](nil), nil
	}

	switch value := w.Value.(type) {
	case json.Number:
		integer, err := strconv.ParseInt(value.String(), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid legacy integer %q: %w", value, err)
		}
		return NewConstant(integer), nil
	case string:
		if decoded, err := decodeTypedBytes(value); err == nil {
			return NewConstant(decoded), nil
		}
		return NewConstant(value), nil
	default:
		return nil, fmt.Errorf("unsupported legacy constant value %T", w.Value)
	}
}

// parseCanonicalInt accepts only the spelling that strconv.FormatInt
// produces: no plus sign, no leading zeroes and no -0.
func parseCanonicalInt(value string) (int64, error) {
	integer, err := strconv.ParseInt(value, 10, 64)
	if err == nil && strconv.FormatInt(integer, 10) != value {
		err = errors.New("non-canonical decimal integer")
	}
	return integer, err
}

func decodeTypedBytes(value string) ([]byte, error) {
	if !strings.HasPrefix(value, "0x") || len(value)%2 != 0 {
		return nil, errors.New("typed bytes require an even lowercase 0x prefix")
	}
	decoded, err := hex.DecodeString(value[2:])
	if err != nil {
		return nil, fmt.Errorf("invalid typed bytes: %w", err)
	}
	if decoded == nil {
		decoded = []byte{}
	}
	return decoded, nil
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

func AsInt(t Term) (int64, error) {
	switch c := any(t).(type) {
	case *Constant[int64]:
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
	case *Constant[int64]:
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
	w, err := decodeWeakTerm(data)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	return f.fromWeakTerm(w)
}

// WeakTerm is a term as it is decoded from JSON. SpecMon encodes terms
// through their own MarshalJSON methods, not through WeakTerm: since Value
// is omitted when it is nil, a WeakTerm of typed nil bytes encodes without
// its value and does not decode again.
type WeakTerm struct {
	Name      string     `json:"name,omitempty"`
	Type      string     `json:"type,omitempty"`
	ConstKind string     `json:"const_kind,omitempty"`
	Value     any        `json:"value,omitempty"`
	Args      []WeakTerm `json:"args,omitempty"`

	valuePresent bool
}

// setValue decodes a JSON value that json.Unmarshal has already validated
// into w.Value: a string, null, or a number kept exact as json.Number.
func (w *WeakTerm) setValue(data []byte) error {
	w.valuePresent = true
	switch data[0] {
	case '"':
		contents := data[1 : len(data)-1]
		if bytes.IndexByte(contents, '\\') < 0 && utf8.Valid(contents) {
			w.Value = string(contents)
			return nil
		}
		var decoded string
		if err := json.Unmarshal(data, &decoded); err != nil {
			return fmt.Errorf("decode string value: %w", err)
		}
		w.Value = decoded
	case 'n':
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		w.Value = json.Number(data)
	default:
		return errors.New("unsupported JSON value type")
	}
	return nil
}

func (w *WeakTerm) UnmarshalJSON(data []byte) error {
	decoded, err := decodeWeakTerm(data)
	if err != nil {
		return err
	}
	*w = decoded
	return nil
}

// weakTermJSON is the wire form of a term. It has no UnmarshalJSON method,
// so a single json.Unmarshal validates and decodes a whole term tree once.
// Calling json.Unmarshal per nesting level would validate and scan every
// subtree again at each level.
//
// Duplicate members in one object are unsupported. encoding/json decodes a
// repeated "args" array into the elements of the earlier one, so fields
// that the later elements omit are merged rather than replaced.
type weakTermJSON struct {
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	ConstKind string          `json:"const_kind"`
	Value     json.RawMessage `json:"value"`
	Args      []weakTermJSON  `json:"args"`
}

func decodeWeakTerm(data []byte) (WeakTerm, error) {
	var decoded weakTermJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return WeakTerm{}, err
	}
	return decoded.weakTerm()
}

// weakTerm converts the arguments, in order, before the node's own value,
// so a value fault in an argument is reported before one in its parent.
func (d *weakTermJSON) weakTerm() (WeakTerm, error) {
	w := WeakTerm{Name: d.Name, Type: d.Type, ConstKind: d.ConstKind}
	if d.Args != nil {
		w.Args = make([]WeakTerm, len(d.Args))
		for i := range d.Args {
			arg, err := d.Args[i].weakTerm()
			if err != nil {
				return WeakTerm{}, err
			}
			w.Args[i] = arg
		}
	}
	if d.Value != nil {
		if err := w.setValue(d.Value); err != nil {
			return WeakTerm{}, err
		}
	}
	return w, nil
}

// VarCount returns the number of variables contained in t.
// Cheaper than len(Vars(t)) because it avoids allocating the slice.
func VarCount(t Term) int {
	return countVars(t)
}

// AppendVars appends the variables found in t to vars and returns the
// resulting slice. Useful when collecting variables from several terms
// into a single pre-sized slice.
func AppendVars(vars []*Variable, t Term) []*Variable {
	return appendVars(vars, t)
}

func countVars(t Term) int {
	if t == nil {
		return 0
	}
	switch t.GetType() {
	case FunctionType:
		f := Must(AsFunction(t))
		total := 0
		for _, arg := range f.Args {
			total += countVars(arg)
		}
		return total
	case VariableType:
		return 1
	default:
		return 0
	}
}

func appendVars(vars []*Variable, t Term) []*Variable {
	if t == nil {
		return vars
	}
	switch t.GetType() {
	case FunctionType:
		f := Must(AsFunction(t))
		for _, arg := range f.Args {
			vars = appendVars(vars, arg)
		}
	case VariableType:
		vars = append(vars, Must(AsVariable(t)))
	}
	return vars
}

// Vars returns the variables contained in t. The result slice is
// pre-sized via VarCount so the recursive walk does not reallocate.
func Vars(t Term) []*Variable {
	count := countVars(t)
	if count == 0 {
		return nil
	}
	vars := make([]*Variable, 0, count)
	return appendVars(vars, t)
}

// occurs reports whether v appears in t. Used by the unification
// occurs-check; short-circuits without allocating, unlike
// slices.Contains(Vars(t), v). Variables are identified by name, as in
// bindings and substitution.
func occurs(v *Variable, t Term) bool {
	switch n := t.(type) {
	case *Variable:
		return v.Name == n.Name
	case *Function:
		for _, arg := range n.Args {
			if occurs(v, arg) {
				return true
			}
		}
	}
	return false
}

func IsGround(t Term) bool {
	return VarCount(t) == 0
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

// Apply binding b to term g. When every key in b is a Variable (the
// common case), uses a single recursive walk that replaces variables
// from a map lookup and returns the original subtree unchanged when
// no replacements fire. Otherwise falls back to the generic
// per-binding Replace loop.
//
// The fast path does not follow chains: for b = {x->y, y->1} and g = x,
// the result is y, not 1. Callers that need chained resolution should
// call b.ComputeFixpoint() before SubstBinding. The fallback path is
// also chain-blind in the sense that it depends on map iteration order,
// so its old behaviour on chained bindings was non-deterministic.
func SubstBinding(b *Binding, g Term) Term {
	if b == nil || b.Empty() {
		return g
	}
	if bindingAllVariables(b) {
		return substVars(b, g)
	}

	next := g

	b.Iterate(func(x, t Term) bool {
		next = Replace(x, t, next)

		return true
	})

	return next
}

// substVars is the fast path for SubstBinding when every key in b is a
// Variable: a single recursive walk that returns the original Function
// subtree when none of its args changed.
func substVars(b *Binding, g Term) Term {
	switch t := g.(type) {
	case *Variable:
		if v, ok := b.Get(t); ok {
			return v
		}
		return t
	case *Function:
		var modified bool
		var args []Term

		for i, arg := range t.Args {
			sub := substVars(b, arg)
			if sub == arg {
				continue
			}
			if !modified {
				args = make([]Term, len(t.Args))
				copy(args, t.Args)
				modified = true
			}
			args[i] = sub
		}

		if !modified {
			return t
		}

		return NewFunction(t.Name, args)
	default:
		return g
	}
}

func bindingAllVariables(b *Binding) bool {
	all := true
	b.Iterate(func(k, _ Term) bool {
		if _, ok := k.(*Variable); !ok {
			all = false
			return false
		}
		return true
	})
	return all
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
	err := evaluateAndUnify(t1, t2, b)
	return b, err
}

// UnifyAll unifies the terms of ts1 with those of ts2 pairwise into one
// binding, so that a variable that occurs in several of them is bound
// consistently. Unequal lengths return ErrNameOrArgMismatch.
func UnifyAll(ts1, ts2 []Term) (*Binding, error) {
	if len(ts1) != len(ts2) {
		return nil, ErrNameOrArgMismatch
	}
	b := NewBinding()
	for i := range ts1 {
		if err := evaluateAndUnify(ts1[i], ts2[i], b); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// evaluateAndUnify evaluates t1 and t2 and unifies the results into b.
func evaluateAndUnify(t1, t2 Term, b *Binding) error {
	a1, err := Evaluate(t1)
	if err != nil {
		return fmt.Errorf("%w for %s: %w", ErrEvaluation, t1, err)
	}
	a2, err := Evaluate(t2)
	if err != nil {
		return fmt.Errorf("%w for %s: %w", ErrEvaluation, t2, err)
	}
	return unify(a1, a2, b)
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

		// A field variable that is already bound must match the parsed
		// value.
		var conflict error
		formatBinding.Iterate(func(k, v Term) bool {
			if prev, ok := b.Get(k); ok && !prev.Equal(k) {
				conflict = unify(prev, v, b)
				return conflict == nil
			}
			b.Set(k, v)

			return true
		})

		return conflict
	case t1Type == ConstantType && (t2Type == FunctionType || t2Type == VariableType):
		// Swap the order of the terms and try again.
		return unify(a2, a1, b)
	case t1Type == VariableType:
		v := Must(AsVariable(a1))

		// A variable that is already bound is unified with its value.
		// Rebinding it would drop the constraint of its earlier occurrence.
		// A variable bound to itself counts as unbound.
		if prev, ok := b.Get(v); ok && !prev.Equal(v) {
			return unify(prev, a2, b)
		}
		// Bind v to the value of a bound variable, not to the variable,
		// so that no chain or cycle of variables forms.
		if w, ok := a2.(*Variable); ok {
			if value, ok := b.Get(w); ok && !value.Equal(w) {
				return unify(v, value, b)
			}
		}

		// A ground value cannot contain v. Otherwise the bindings so far
		// are applied first, so that the occurs check also sees v through
		// a variable that is already bound.
		if !IsGround(a2) {
			a2 = SubstBinding(b, a2)
			if occurs(v, a2) {
				// return &UnificationError{a1, a2, "occurs check failed"}
				return ErrOccursCheckFailed
			}
		}

		// Substitute a2 for v in the values bound so far. A ground value
		// cannot contain v. Skipping it avoids copying every bound
		// function term for each new variable.
		b.Iterate(func(x, t Term) bool {
			if !IsGround(t) {
				b.Set(x, Subst(*v, a2, t))
			}

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

	args := make([]Term, len(f.Args))
	for i, s := range f.Args {
		args[i] = UnifyReplace(s, g, h)
	}

	return NewFunction(f.Name, args)
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

func ReplaceFormats(t Term) (Term, error) {
	s, err := Evaluate(t)
	if err != nil {
		return nil, fmt.Errorf("%w for %s: %w", ErrEvaluation, t, err)
	}

	return s, nil
}

func Evaluate(t Term) (Term, error) {
	f, err := AsFunction(t)
	if err != nil {
		return t, nil
	}
	switch f.Name {
	case AddFunctionName, AndFunctionName, OrFunctionName, XorFunctionName:
		if len(f.Args) != BinaryArity {
			return nil, ErrBinaryArity
		}
	case NotFunctionName:
		if len(f.Args) != UnaryArity {
			return nil, ErrUnaryArity
		}
	}

	newArgs, modified, err := evaluateArguments(f.Args)
	if err != nil {
		return nil, err
	}

	switch f.Name {
	case CatFunctionName:
		return handleCatFunction(f, newArgs, modified)
	case AddFunctionName:
		return handleAddFunction(f, newArgs, modified)
	case AndFunctionName, OrFunctionName, XorFunctionName:
		return handleBitwiseFunction(f, newArgs, modified)
	case NotFunctionName:
		return handleNotFunction(f, newArgs, modified)
	case SliceFunctionName:
		return handleSliceFunction(f, newArgs, modified)
	case ReverseFuncName:
		return handleReverseFunction(f, newArgs, modified)
	default:
		return unevaluated(f, newArgs, modified), nil
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

// unevaluated returns the residual of f: f itself, or a copy with the
// evaluated arguments if evaluation changed any of them.
func unevaluated(f *Function, args []Term, modified bool) Term {
	if modified {
		return NewFunction(f.Name, args)
	}
	return f
}

// operandsKnown reports whether every argument is a ground term that is not
// a call, so that an operation on them can be evaluated.
func operandsKnown(args []Term) bool {
	return !slices.ContainsFunc(args, func(arg Term) bool { return !IsGround(arg) || arg.GetType() == FunctionType })
}

func handleCatFunction(f *Function, args []Term, modified bool) (Term, error) {
	fields := make([]*Function, len(f.Args))

	var err error
	symbolic := false
	for i, a := range args {
		fields[i], err = AsFunction(a)
		if err != nil {
			return nil, ErrInvalidFormatFunction
		}
		// A field that holds a call which is neither evaluable nor observed
		// keeps the concatenation symbolic, as for the other operations.
		symbolic = symbolic || slices.ContainsFunc(fields[i].Args, func(arg Term) bool { return arg.GetType() == FunctionType })
	}
	if symbolic {
		return unevaluated(f, args, modified), nil
	}

	bytes, err := FormatToBytes(fields, NewBinding())
	if err != nil {
		if candidate := unevaluated(f, args, modified); !IsGround(candidate) {
			return candidate, nil
		}
		return nil, fmt.Errorf("%w: invalid format construction: %w", ErrEvaluation, err)
	}

	return NewConstant[[]byte](bytes), nil
}

func handleAddFunction(f *Function, args []Term, modified bool) (Term, error) {
	if !operandsKnown(args) {
		return unevaluated(f, args, modified), nil
	}

	left, err := AsInt(args[0])
	if err != nil || left < 0 {
		return nil, fmt.Errorf("%w: invalid left add operand", ErrEvaluation)
	}
	right, err := AsInt(args[1])
	if err != nil || right < 0 {
		return nil, fmt.Errorf("%w: invalid right add operand", ErrEvaluation)
	}
	if right > math.MaxInt64-left {
		return nil, fmt.Errorf("%w: add overflow", ErrEvaluation)
	}

	return NewConstant(left + right), nil
}

func handleBitwiseFunction(f *Function, args []Term, modified bool) (Term, error) {
	if !operandsKnown(args) {
		return unevaluated(f, args, modified), nil
	}

	left, err := bitwisePattern(args[0])
	if err != nil {
		return nil, err
	}
	right, err := bitwisePattern(args[1])
	if err != nil {
		return nil, err
	}

	var result uint64
	switch f.Name {
	case AndFunctionName:
		result = left & right
	case OrFunctionName:
		result = left | right
	case XorFunctionName:
		result = left ^ right
	}

	// bitwisePattern accepted args[0], so it is an int64 or a bytes constant.
	if first, ok := args[0].(*Constant[[]byte]); ok {
		b := utils.IntToBytes(int64(result), internalByteOrder())
		return NewConstant(b[:len(first.Value)]), nil
	}
	return NewConstant(int64(result)), nil
}

func bitwisePattern(t Term) (uint64, error) {
	switch value := t.(type) {
	case *Constant[int64]:
		return uint64(value.Value), nil //nolint:gosec // Preserve the two's-complement bit pattern.
	case *Constant[[]byte]:
		if len(value.Value) > 8 {
			return 0, ErrInvalidType
		}
		padded := utils.PadWithByteOrder(value.Value, internalByteOrder(), 8)
		return internalByteOrder().Uint64(padded), nil
	default:
		return 0, ErrInvalidType
	}
}

func handleNotFunction(f *Function, args []Term, modified bool) (Term, error) {
	if !operandsKnown(args) {
		return unevaluated(f, args, modified), nil
	}

	switch value := args[0].(type) {
	case *Constant[int64]:
		return NewConstant(^value.Value), nil
	case *Constant[[]byte]:
		result := make([]byte, len(value.Value))
		for i, b := range value.Value {
			result[i] = ^b
		}
		return NewConstant(result), nil
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
		return unevaluated(f, args, modified), nil
	}

	start, err := AsInt(args[1])
	if err != nil {
		return unevaluated(f, args, modified), nil
	}

	end, err := AsInt(args[2])
	if err != nil {
		return unevaluated(f, args, modified), nil
	}

	dataLen := int64(len(data))

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

	return NewConstant[[]byte](data[int(resolvedStart):int(resolvedEnd)]), nil
}

func handleReverseFunction(f *Function, args []Term, modified bool) (Term, error) {
	if len(args) != UnaryArity {
		return nil, ErrUnaryArity
	}

	arg := args[0]

	originalBytes, err := AsBytes(arg)
	if err != nil {
		// If the argument cannot be converted to bytes (e.g., it's a variable),
		// return the function call, possibly with an evaluated argument.
		return unevaluated(f, args, modified), nil
	}

	// Slices.Reverse is in-place, so we must copy the data first
	// to avoid modifying the original constant's value.
	reversedBytes := make([]byte, len(originalBytes))
	copy(reversedBytes, originalBytes)
	slices.Reverse(reversedBytes)

	// Preserve the original constant type.
	switch arg.(type) {
	case *Constant[int64]:
		// Reinterpret the reversed two's-complement bit pattern as a signed value.
		newValue := int64(internalByteOrder().Uint64(reversedBytes)) //nolint:gosec
		return NewConstant(newValue), nil
	case *Constant[string]:
		return NewConstant[string](string(reversedBytes)), nil
	case *Constant[[]byte]:
		return NewConstant[[]byte](reversedBytes), nil
	default:
		// This case should not be reached if AsBytes succeeds, but as a fallback.
		return unevaluated(f, args, modified), nil
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

// SplitPair returns a pair's two components, or nil components for any
// other shape. It does not validate the components themselves.
func SplitPair(t Term) (Term, Term) {
	f, err := AsFunction(t)
	if err != nil || f == nil || f.Name != PairFunctionName || len(f.Args) != 2 {
		return nil, nil
	}
	return f.Args[0], f.Args[1]
}

// ContainsComputation reports whether t contains a function other than
// a reserved constructor or evaluator.
func ContainsComputation(t Term) bool {
	fn, ok := t.(*Function)
	return ok && fn != nil && (!ReservedNames.Contains(fn.Name) || slices.ContainsFunc(fn.Args, ContainsComputation))
}

// builtinArities records fixed arities. Cat and format fields have their
// own argument rules.
var builtinArities = map[string]int{
	AddFunctionName:   BinaryArity,
	AndFunctionName:   BinaryArity,
	OrFunctionName:    BinaryArity,
	XorFunctionName:   BinaryArity,
	NotFunctionName:   UnaryArity,
	ReverseFuncName:   UnaryArity,
	SliceFunctionName: TernaryArity,
}

// BuiltinArity returns the fixed arity of a built-in, when it has one.
func BuiltinArity(name string) (int, bool) {
	arity, ok := builtinArities[name]
	return arity, ok
}
