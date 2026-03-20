package rule_test

import (
	"testing"

	"github.com/specmon/specmon/rule"
	"github.com/specmon/specmon/term"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeRule(rhs []term.Term) *rule.Rule {
	r := rule.NewRule()
	r.Name = "R"
	r.LHS = []*rule.Fact{rule.NewFact("In", []term.Term{term.NewVariable("x")}, rule.LinearFact)}
	r.RHS = []*rule.Fact{rule.NewFact("Out", rhs, rule.LinearFact)}
	return r
}

func makeRuleWithLHS(lhs, rhs []term.Term) *rule.Rule {
	r := rule.NewRule()
	r.Name = "R"
	r.LHS = []*rule.Fact{rule.NewFact("In", lhs, rule.LinearFact)}
	r.RHS = []*rule.Fact{rule.NewFact("Out", rhs, rule.LinearFact)}
	return r
}

func TestNameGenerator_VariablesPreserved(t *testing.T) {
	t.Parallel()
	r := makeRule([]term.Term{
		term.NewFunction("hash", []term.Term{term.NewVariable("m")}),
	})
	g := rule.NewNameGenerator(r)
	got := g.NameForTerm(term.NewVariable("m"))
	assert.Equal(t, "m", got)
}

func TestNameGenerator_PublicVarSanitized(t *testing.T) {
	t.Parallel()
	r := makeRule([]term.Term{
		term.NewFunction("hash", []term.Term{term.NewVariable("$secret")}),
	})
	g := rule.NewNameGenerator(r)
	got := g.NameForTerm(term.NewVariable("$secret"))
	assert.Equal(t, "secret", got)
}

func TestNameGenerator_FreshVarSanitized(t *testing.T) {
	t.Parallel()
	r := makeRule([]term.Term{
		term.NewFunction("hash", []term.Term{term.NewVariable("~k")}),
	})
	g := rule.NewNameGenerator(r)
	got := g.NameForTerm(term.NewVariable("~k"))
	assert.Equal(t, "k", got)
}

func TestNameGenerator_StructuralNames(t *testing.T) {
	t.Parallel()
	m := term.NewVariable("m")
	hashM := term.NewFunction("hash", []term.Term{m})
	lenHashM := term.NewFunction("len", []term.Term{hashM})

	r := makeRule([]term.Term{lenHashM})
	g := rule.NewNameGenerator(r)

	assert.Equal(t, "h_m", g.NameForTerm(hashM))
	assert.Equal(t, "l_h_m", g.NameForTerm(lenHashM))
}

func TestNameGenerator_DeepTermsUseStructuralNames(t *testing.T) {
	t.Parallel()
	// depth 3: enc(hash(len(x)))
	x := term.NewVariable("x")
	lenX := term.NewFunction("len", []term.Term{x})
	hashLenX := term.NewFunction("hash", []term.Term{lenX})
	encHashLenX := term.NewFunction("enc", []term.Term{hashLenX})

	r := makeRule([]term.Term{encHashLenX})
	g := rule.NewNameGenerator(r)

	got := g.NameForTerm(encHashLenX)
	assert.Equal(t, "e_h_l_x", got)
}

func TestNameGenerator_LateDeepTerm(t *testing.T) {
	t.Parallel()
	// Create a rule with no deep terms, then call NameForTerm on a deep term
	// that wasn't seen during collection. Should still get a structural name.
	r := makeRule([]term.Term{term.NewVariable("x")})
	g := rule.NewNameGenerator(r)

	x := term.NewVariable("x")
	lenX := term.NewFunction("len", []term.Term{x})
	hashLenX := term.NewFunction("hash", []term.Term{lenX})
	encHashLenX := term.NewFunction("enc", []term.Term{hashLenX})

	require.NotPanics(t, func() {
		got := g.NameForTerm(encHashLenX)
		assert.Equal(t, "e_h_l_x", got)
	})
}

func TestNameGenerator_AbbrevCollision(t *testing.T) {
	t.Parallel()
	x := term.NewVariable("x")
	hashX := term.NewFunction("hash", []term.Term{x})
	hmacX := term.NewFunction("hmac", []term.Term{x})

	r := rule.NewRule()
	r.Name = "R"
	r.LHS = []*rule.Fact{rule.NewFact("In", []term.Term{x}, rule.LinearFact)}
	r.RHS = []*rule.Fact{rule.NewFact("Out", []term.Term{hashX, hmacX}, rule.LinearFact)}
	g := rule.NewNameGenerator(r)

	name1 := g.NameForTerm(hashX)
	name2 := g.NameForTerm(hmacX)
	assert.NotEqual(t, name1, name2)
	// Sorted alphabetically: hash gets "h", hmac gets "hm".
	assert.Equal(t, "h_x", name1)
	assert.Equal(t, "hm_x", name2)
}

// TestNameGenerator_CollisionWithUserVariable verifies that generated names
// do not shadow user variables. Repro from Codex finding #1:
// In(m, h_m) -> Out(len(hash(m)), h_m) must not produce h_m for hash(m).
func TestNameGenerator_CollisionWithUserVariable(t *testing.T) {
	t.Parallel()
	m := term.NewVariable("m")
	hm := term.NewVariable("h_m")
	hashM := term.NewFunction("hash", []term.Term{m})
	lenHashM := term.NewFunction("len", []term.Term{hashM})

	r := makeRuleWithLHS(
		[]term.Term{m, hm},
		[]term.Term{lenHashM, hm},
	)
	g := rule.NewNameGenerator(r)

	// hash(m) must NOT get "h_m" because that's already a user variable.
	hashName := g.NameForTerm(hashM)
	assert.NotEqual(t, "h_m", hashName, "generated name must not collide with user variable h_m")
	assert.Equal(t, "h_m_0", hashName)

	// The user variable h_m keeps its original name.
	assert.Equal(t, "h_m", g.NameForTerm(hm))
}

// TestNameGenerator_DeepStructuralNameAvoidsUserVariableCollision verifies that
// deep structural names do not shadow user variables.
func TestNameGenerator_DeepStructuralNameAvoidsUserVariableCollision(t *testing.T) {
	t.Parallel()
	t0 := term.NewVariable("t0")
	lenT0 := term.NewFunction("len", []term.Term{t0})
	hashLenT0 := term.NewFunction("hash", []term.Term{lenT0})
	encHashLenT0 := term.NewFunction("enc", []term.Term{hashLenT0})

	r := makeRuleWithLHS(
		[]term.Term{t0},
		[]term.Term{encHashLenT0, t0},
	)
	g := rule.NewNameGenerator(r)

	deepName := g.NameForTerm(encHashLenT0)
	assert.NotEqual(t, "t0", deepName, "deep name must not collide with user variable t0")
	assert.Equal(t, "e_h_l_t0", deepName)

	// The user variable t0 keeps its name.
	assert.Equal(t, "t0", g.NameForTerm(t0))
}

// TestNameGenerator_Deterministic verifies that the same rule always produces
// the same generated names.
func TestNameGenerator_Deterministic(t *testing.T) {
	t.Parallel()
	m := term.NewVariable("m")
	hashM := term.NewFunction("hash", []term.Term{m})
	lenHashM := term.NewFunction("len", []term.Term{hashM})

	for range 10 {
		r := makeRule([]term.Term{lenHashM})
		g := rule.NewNameGenerator(r)
		assert.Equal(t, "h_m", g.NameForTerm(hashM))
		assert.Equal(t, "l_h_m", g.NameForTerm(lenHashM))
	}
}

// TestNameGenerator_OrderIndependent verifies that reordering RHS facts does
// not change generated names.
func TestNameGenerator_OrderIndependent(t *testing.T) {
	t.Parallel()
	x := term.NewVariable("x")
	hashX := term.NewFunction("hash", []term.Term{x})
	hmacX := term.NewFunction("hmac", []term.Term{x})

	// Order A: hash before hmac.
	rA := rule.NewRule()
	rA.Name = "R"
	rA.LHS = []*rule.Fact{rule.NewFact("In", []term.Term{x}, rule.LinearFact)}
	rA.RHS = []*rule.Fact{rule.NewFact("Out", []term.Term{hashX, hmacX}, rule.LinearFact)}
	gA := rule.NewNameGenerator(rA)

	// Order B: hmac before hash.
	rB := rule.NewRule()
	rB.Name = "R"
	rB.LHS = []*rule.Fact{rule.NewFact("In", []term.Term{x}, rule.LinearFact)}
	rB.RHS = []*rule.Fact{rule.NewFact("Out", []term.Term{hmacX, hashX}, rule.LinearFact)}
	gB := rule.NewNameGenerator(rB)

	assert.Equal(t, gA.NameForTerm(hashX), gB.NameForTerm(hashX))
	assert.Equal(t, gA.NameForTerm(hmacX), gB.NameForTerm(hmacX))
}

// TestNameGenerator_OrderIndependentWithCollision verifies stability when
// suffix allocation is needed. Repro from Codex follow-up finding:
// In(m, m_0, h_m) -> Out(hash(m), hash(m_0)) must produce the same names
// regardless of whether hash(m) or hash(m_0) appears first in the RHS.
func TestNameGenerator_OrderIndependentWithCollision(t *testing.T) {
	t.Parallel()
	m := term.NewVariable("m")
	m0 := term.NewVariable("m_0")
	hm := term.NewVariable("h_m")
	hashM := term.NewFunction("hash", []term.Term{m})
	hashM0 := term.NewFunction("hash", []term.Term{m0})

	lhs := []term.Term{m, m0, hm}

	// Order A: hash(m) before hash(m_0).
	rA := makeRuleWithLHS(lhs, []term.Term{hashM, hashM0})
	gA := rule.NewNameGenerator(rA)

	// Order B: hash(m_0) before hash(m).
	rB := makeRuleWithLHS(lhs, []term.Term{hashM0, hashM})
	gB := rule.NewNameGenerator(rB)

	assert.Equal(t, gA.NameForTerm(hashM), gB.NameForTerm(hashM),
		"hash(m) name must be stable across RHS orderings")
	assert.Equal(t, gA.NameForTerm(hashM0), gB.NameForTerm(hashM0),
		"hash(m_0) name must be stable across RHS orderings")
}

func TestNameGenerator_LongStructuralNamesAreCompacted(t *testing.T) {
	t.Parallel()

	r := makeRule([]term.Term{
		term.NewFunction("f", []term.Term{
			term.NewVariable("somelongvar"),
			term.NewVariable("anotherlongvar"),
			term.NewVariable("thirdlongvar"),
		}),
	})
	g := rule.NewNameGenerator(r)

	name := g.NameForTerm(term.NewFunction("f", []term.Term{
		term.NewVariable("somelongvar"),
		term.NewVariable("anotherlongvar"),
		term.NewVariable("thirdlongvar"),
	}))

	assert.LessOrEqual(t, len(name), 30)
	assert.Equal(t, "f0", name)
}

func TestNameGenerator_LongStructuralCollisionStillCapped(t *testing.T) {
	t.Parallel()

	longTerm := term.NewFunction("f", []term.Term{
		term.NewVariable("somelongvar"),
		term.NewVariable("anotherlongvar"),
		term.NewVariable("thirdlongvar"),
	})

	baseRule := makeRule([]term.Term{longTerm})
	baseGen := rule.NewNameGenerator(baseRule)
	baseName := baseGen.NameForTerm(longTerm)

	collisionRule := makeRuleWithLHS(
		[]term.Term{term.NewVariable(baseName)},
		[]term.Term{longTerm},
	)
	collisionGen := rule.NewNameGenerator(collisionRule)
	collisionName := collisionGen.NameForTerm(longTerm)

	assert.NotEqual(t, baseName, collisionName)
	assert.LessOrEqual(t, len(collisionName), 30)
	assert.Equal(t, "f1", collisionName)
}

func TestNameGenerator_LongDeepNamesAreCompacted(t *testing.T) {
	t.Parallel()

	longHash := term.NewFunction("hash", []term.Term{
		term.NewVariable("somelongvar"),
		term.NewVariable("anotherlongvar"),
		term.NewVariable("thirdlongvar"),
	})
	deepTerm := term.NewFunction("hmac", []term.Term{
		longHash,
		term.NewConstant[[]byte]([]byte{0x01}),
	})

	r := makeRule([]term.Term{deepTerm})
	g := rule.NewNameGenerator(r)

	assert.Equal(t, "h0", g.NameForTerm(longHash))
	name := g.NameForTerm(deepTerm)
	assert.Equal(t, "hm0", name)
}

// TestNameGenerator_LongCommonPrefixFunctionsCapped verifies that compact names
// stay within maxGeneratedNameLen even when two function names share a long
// common prefix, forcing shortestUniquePrefix to return a lengthy abbreviation.
func TestNameGenerator_LongCommonPrefixFunctionsCapped(t *testing.T) {
	t.Parallel()
	x := term.NewVariable("x")
	// Two functions that share a 28-char prefix, diverging only at the end.
	f1 := term.NewFunction("abcdefghijklmnopqrstuvwxyzAA", []term.Term{x})
	f2 := term.NewFunction("abcdefghijklmnopqrstuvwxyzBB", []term.Term{x})

	r := rule.NewRule()
	r.Name = "R"
	r.LHS = []*rule.Fact{rule.NewFact("In", []term.Term{x}, rule.LinearFact)}
	r.RHS = []*rule.Fact{rule.NewFact("Out", []term.Term{f1, f2}, rule.LinearFact)}
	g := rule.NewNameGenerator(r)

	name1 := g.NameForTerm(f1)
	name2 := g.NameForTerm(f2)
	assert.NotEqual(t, name1, name2)
	assert.LessOrEqual(t, len(name1), 30, "compact name for f1 exceeds cap")
	assert.LessOrEqual(t, len(name2), 30, "compact name for f2 exceeds cap")
}

func TestSanitizeName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input    string
		expected string
	}{
		{"m", "m"},
		{"$secret", "secret"},
		{"~k", "k"},
		{"$$double", "double"},
		{"~$mixed", "mixed"},
		{"", "x"},
		{"$", "x"},
		{"~", "x"},
		{"hello_world", "hello_world"},
		{"a-b", "ab"},
		{"foo.bar", "foobar"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			// sanitizeName is not exported, so test indirectly via NameForTerm
			// on a variable with the given name.
			r := makeRule([]term.Term{term.NewVariable("dummy")})
			g := rule.NewNameGenerator(r)
			got := g.NameForTerm(term.NewVariable(tt.input))
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestTermKeyInjectivity(t *testing.T) {
	t.Parallel()
	// A variable named "f(x)" and a function f(x) should produce different
	// names, ensuring the type-prefixed termKey prevents cross-type collisions.
	x := term.NewVariable("x")
	funcFX := term.NewFunction("f", []term.Term{x})
	varFX := term.NewVariable("f(x)")

	r := rule.NewRule()
	r.Name = "R"
	r.LHS = []*rule.Fact{rule.NewFact("In", []term.Term{x}, rule.LinearFact)}
	r.RHS = []*rule.Fact{rule.NewFact("Out", []term.Term{funcFX, varFX}, rule.LinearFact)}
	g := rule.NewNameGenerator(r)

	funcName := g.NameForTerm(funcFX)
	varName := g.NameForTerm(varFX)
	assert.NotEqual(t, funcName, varName)
}
