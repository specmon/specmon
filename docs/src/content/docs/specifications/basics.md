---
title: Specification Basics
description: Learn the fundamentals of writing SpecMon specifications
---

SpecMon specifications are written in Tamarin's protocol modeling language, extended with features for runtime monitoring. This page covers the fundamentals you need to write specifications.

For comprehensive Tamarin documentation, see the [Tamarin manual](https://tamarin-prover.com/manual/).

## Theory structure

A specification is called a *theory* and is contained in a `.spthy` file:

```tamarin
theory MyProtocol
begin

// Declarations, rules, and lemmas go here

end
```

## Multiset-rewrite rules

Rules are the core of any specification. They define how the system state evolves by consuming and producing *facts*.

```tamarin
rule RuleName:
  [ InputFact1(x), InputFact2(y) ]   // Prerequisites (consumed)
--[ ActionFact(x, y) ]->              // Actions (logged for properties)
  [ OutputFact1(x), OutputFact2(y) ]  // Results (produced)
```

**Components:**
- **Left-hand side**: Facts that must exist and are consumed when the rule fires
- **Action facts**: Events logged in the trace for security properties
- **Right-hand side**: Facts produced when the rule fires

### Example: Key generation

```tamarin
rule Generate_Key:
  [ Fr(~k) ]              // Fresh randomness
--[ NewKey(~k) ]->        // Log key generation
  [ !LongTermKey(~k) ]    // Produce persistent key
```

- `Fr(~k)` is a built-in fact providing fresh random values
- The `~` prefix marks a fresh variable
- The `!` prefix marks a persistent fact (not consumed when used)

## Facts

Facts represent state in the protocol. They can be:

**Linear facts** — Consumed when used:
```tamarin
[ Message(m) ]  // Exists once, consumed when rule fires
```

**Persistent facts** — Remain available after use:
```tamarin
[ !Key(k) ]  // Prefixed with !, can be used multiple times
```

**Built-in facts:**
- `Fr(~x)` — Fresh random value
- `In(m)` — Message received from the network
- `Out(m)` — Message sent to the network

## Variables

Variables follow naming conventions:

| Prefix | Meaning | Example |
|--------|---------|---------|
| `~` | Fresh (random) value | `~nonce`, `~key` |
| `$` | Public constant | `$Server`, `$Alice` |
| `#` | Temporal variable (timepoint) | `#i`, `#j` |
| none | Regular variable | `msg`, `x` |

## Built-in functions

Tamarin provides cryptographic primitives:

```tamarin
builtins: hashing, signing, asymmetric-encryption, symmetric-encryption
```

This enables functions like:
- `h(m)` — Hash
- `sign(m, sk)` — Signature
- `verify(sig, m, pk)` — Signature verification
- `aenc(m, pk)` — Asymmetric encryption
- `adec(c, sk)` — Asymmetric decryption
- `senc(m, k)` — Symmetric encryption
- `sdec(c, k)` — Symmetric decryption

## Security properties (lemmas)

Lemmas specify security properties using first-order logic over traces:

```tamarin
lemma secrecy:
  "All x #i. Secret(x)@i ==> not(Ex #j. K(x)@j)"
```

This reads: "For all values `x` and timepoints `#i`, if `Secret(x)` occurred at time `i`, then there is no timepoint `#j` where the adversary knows `x`."

### Common patterns

**Secrecy:**
```tamarin
lemma key_secrecy:
  "All k #i. SecretKey(k)@i ==> not(Ex #j. K(k)@j)"
```

**Authentication:**
```tamarin
lemma authentication:
  "All a b m #i. Received(b, m)@i ==> Ex #j. Sent(a, m)@j & j < i"
```

**Uniqueness:**
```tamarin
lemma unique_session:
  "All x #i #j. Session(x)@i & Session(x)@j ==> #i = #j"
```
## Next steps

- [**SpecMon Annotations**](/specifications/annotations/) — Advanced features like triggers and hints
- [**Creating Unified Models**](/specifications/unified-models/) — Write specifications that work with both Tamarin and SpecMon
- [**Encoding Message Formats**](/specifications/message-formats/) — Map abstract terms to concrete bytes