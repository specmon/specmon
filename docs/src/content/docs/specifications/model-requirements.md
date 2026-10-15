---
title: Model Requirements
description: What SpecMon requires of a model, what it checks when the model is loaded, and what it does not check
---

SpecMon loads the model, and with `--rewrite-with` the rewrite model, before it reads the first event. A rule
whose application could not be well defined is rejected at that point with an error that names the rule. A rule
that is well defined but can match only unusual events is reported with a warning. Some properties are checked
only when a rule is applied, and some not at all.

## Checked when a model is loaded

A model is rejected (`cannot create monitor: …`, or `cannot create rewrite monitor: …` for the rewrite model) if
one of these conditions does not hold. The checks apply to the rules that are monitored: for the main model, after
role selection, after conclusions that no rule consumes are dropped, and after decomposition, so a dropped
conclusion is not checked. The rewrite model of `--rewrite-with` is checked as parsed, without role selection or
dropping.

- **Triggers and hints** are event pairs `<call(…), result>` whose first component is a function.
- **Hint rules** have at least one premise.
- **Restrictions** `Eq`, `Equal`, `Neq`, `NotEqual` and `Unequal` have exactly two operands.
- **Rewrite outputs**: every `PPEvent` action has exactly one argument, written as a pair `<event, result>`. The
  first component may be a variable, a pair-headed call or an ordinary call. Explicit built-in names are rejected.
  A dynamically bound non-call or built-in head fails output processing in standalone and integrated rewriting.
- **Evaluable functions** have the right number of arguments: `add`, `and`, `or` and `xor` two, `not` and
  `reverse` one, `slice` three. Every argument of `cat` is an `int`, `byte` or `string` field with one or two
  arguments.
- **Premises are parsed on their own.** A premise must match a fact without values from the trigger or hint.
  A premise contains no `add`, `and`, `or` or `xor`, not even with constant operands, since these are only
  evaluated over known operands and never parsed. No variable of a premise stands at a position that parsing
  cannot extract (see below), even if another premise or another argument of the same premise binds it:
  SpecMon evaluates the arguments of a premise before any of them binds, and it matches the premises in an
  order that depends on the facts.
- **Every variable can be bound.** A variable of a premise, an action (including a restriction operand) or a
  conclusion must occur in a premise or in the pattern that selects the rule: its trigger, all triggers of a rule
  with several triggers, or, for a rule with hints, each hint on its own, since hints are alternatives. Then every
  application is ground.
- **Epsilon rules** (rules without triggers and hints) have a linear premise, and no epsilon rule has a premise
  that an epsilon step can produce: a conclusion of an epsilon rule, or of a rule with a computation, whose end rule
  produces it in the split form.

## Warnings when a model is loaded

Matching extracts values from a fact or an event only at some positions of a pattern: a variable, the value of a
format field that has a length, that is an `int` field (eight bytes) or that is the last field of its `cat`, and a
length that an earlier field of the same `cat` binds. At every other position, inside an evaluated function, in a
length, and in a `byte` or `string` field without length before the last field, the variable's value must be known
before the pattern is matched. In a premise, such a variable is rejected (above). Admission accounts for values that premise matching can bind and, for later triggers, values bound by earlier triggers. Another occurrence of the variable in the same pattern does not bind it
in time.

If a variable of a trigger or hint is not bound in time, the pattern matches only a term that contains the
evaluable subterm itself, which events normally do not. SpecMon then prints a warning on stderr, whatever the log
level, and loads the model:

```text
warning: rule R: variable a is not bound when matching needs its value (inside an evaluated function, in a field
length or in a byte or string field without length before the last field of a cat), so the pattern matches only
terms that contain such a subterm unevaluated
```

Bare rule inspection also prints nonfatal warnings for the displayed executable rules, including with `-q`.
Quiet mode suppresses rule display, not warnings. Inspection does not apply the full monitor admission
checks.

| Rule | Result |
|---|---|
| trigger `<recv(cat(byte(a, '4'), byte(b))), r>` | no warning: `a` has a length, `b` is the last field |
| trigger `<recv(cat(int(l, '1'), byte(x, l), byte(rest))), r>` | no warning: the length `l` is parsed first |
| trigger `<recv(cat(byte(a), byte(b))), r>`, nothing else binds `a` | warning for `a`: parsing cannot tell where its field ends |
| the same trigger with the premise `Key(a)` | no warning: `a` is substituted before the event is parsed |
| trigger `<recv(a, cat(byte(a), byte(b))), r>` | warning for `a`: the other argument does not bind it in time |
| premise `Key(x)`, trigger `<h(slice(x, '1', '5')), r>` | no warning |
| trigger `<h(slice(x, '1', '5')), r>`, nothing else binds `x` | warning for `x` |
| trigger `<recv(cat(int(n), byte(rest))), r>` | no warning: an `int` field without length takes eight bytes |
| trigger `<recv(a, b), r>`, conclusion `Out(cat(byte(a), byte(b)))` | no warning: a `cat` that is only constructed may have fields without length anywhere |
| premise `Msg(cat(byte(a), byte(rest)))`, `a` bound only by the hint or trigger | rejected: the premise cannot be parsed on its own |
| premises `Key(a)` and `Msg(cat(byte(a), byte(rest)))` | rejected: `Msg` cannot be parsed on its own, although `Key` binds `a` |
| premise `Counter(add(n, '1'))` | rejected: `add` is only evaluated. Write `[ Counter(c) ] --[ Eq(c, add(n, '1')) ]->` |
| `z` occurs only in a conclusion | rejected: `variable z of its conclusions cannot be bound by matching` |

The same distinction appears in [Encoding Message Formats](/specifications/message-formats/): a length is needed to
parse a field, not to construct it.

## Checked when a rule is applied

- A restriction that does not hold ends that candidate only. If no branch survives the event, the event is
  rejected.
- Every term of an application can be evaluated. An addition that overflows, an operand of the wrong type or a
  format that cannot be constructed ends the run with an error, and so does an epsilon rule that is still
  applicable after the epsilon step.
- The internal invariants, such as that an application is ground and that a consumed fact exists, end the run with
  an error. Admitted models are not expected to reach them. See the limits below.
- Input events are event pairs with a call. Anything else ends the run with an error.
- `specmon rewrite` requires that all rewrite rules that accept one event emit the same events.

## Not checked

- That a trigger, hint or format can match the events that the instrumentation actually emits: function names,
  arities and byte layouts are compared only when events arrive.
- That the monitoring view of a model corresponds to its verification view.
- The size of the set of configurations, which grows with the alternatives that the model allows.
- Two rule shapes that loading does not reject yet, although applying them fails: a rule with both triggers and
  hints, and a premise that contains a function other than a parsable format (a linear premise with the trigger's
  call makes the deletion of that premise fail).
