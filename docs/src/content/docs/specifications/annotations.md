---
title: SpecMon Annotations
description: Rule annotations for triggers, hints, and role selection
---

SpecMon extends Tamarin's rule syntax with annotations that control how rules are processed during monitoring. These annotations let you align runtime events with symbolic terms without changing the core protocol logic.

## How rules apply

SpecMon processes an incoming event stream and matches each event against rule annotations. In practice:
- **Triggers** define which concrete events can apply a rule and how return values are bound.
- **Hints** are a lookahead mechanism used by start rules to decide whether a rule is worth pursuing for the current event.
- Rules that contain function applications and have **no trigger or hint** are **automatically decomposed** into trigger- and hint-annotated rules.

If you add a `trigger` or `hint` yourself, SpecMon will use the rule as written and will not decompose it.

## Triggers

A trigger specifies which event causes a rule to fire and how the return value is bound:

```tamarin
rule Encrypt [trigger=[<senc(~k, $m), c>]]:
  [ In($m), !Ltk(~k) ]
--[ Encrypted($m, c) ]->
  [ Out(senc(~k, $m)) ]
```

The trigger `<senc(~k, $m), c>` matches a runtime event where `senc` is called on `~k` and `$m`, and binds the result to `c`.
When the rule is applied, the function term `senc(~k, $m)` is replaced with its return value.

SpecMon also supports multiple triggers per rule. This is useful for modeling paired enter/leave events and rules that should only fire after all required calls have been seen.

## Hints

Hints are a lookahead mechanism used by start rules. They indicate which triggers the rule expects next, so the monitor can decide whether the rule is worth pursuing for the current event.

```tamarin
rule Send_Start [hint=[<h($m), hm>, <senc(~k, $m), c>]]:
  [ In($m), !Ltk(~k) ]
  -->
  [ ... ]
```

In practice, hints are generated automatically during decomposition. You typically only write them when you need a custom decomposition strategy.

## Rule decomposition

Tamarin rules can contain nested function terms like `h(senc(~k, $m))`, but they do not specify the order in which these computations occur. Runtime traces *do* have an order, and the monitor needs to connect each observable call with the right symbolic term.

SpecMon handles this by **decomposing** rules that contain function applications. A rule without a `trigger` or `hint` is decomposed automatically into:
- A **start rule** annotated with `hint` (lookahead)
- One or more **mid rules** each annotated with a single `trigger`
- An **end rule** that completes the original conclusion (often with no trigger)

### Example: decomposition and dependencies

Given the rule:

```tamarin
rule Send:
  [ In($m), !Ltk(~k) ] --> [ Out(h(senc(~k, $m)), h($m)) ]
```

Two computations can happen independently (`h($m)` and `senc(~k, $m)`), and `h(senc(~k, $m))` depends on the encryption result. Decomposition makes those dependencies explicit with triggers like:

```tamarin
<h($m), hm>
<senc(~k, $m), c>
<h(c), hc>
```

:::note[Why hints matter]
Because `h($m)` and `senc(~k, $m)` can occur in either order, the monitor would otherwise need to explore many interleavings. **Hints** let the monitor look ahead at the incoming event and choose the matching path, avoiding an exponential blowup in the number of rule variants.
:::

## `role` — Filter rules by protocol role

The `role` attribute restricts rules to specific protocol participants:

```tamarin
rule ClientSend [role=client]:
  [ ClientState(x) ]
--[ Send(x) ]->
  [ Out(x) ]

rule ServerReceive [role=server]:
  [ In(x) ]
--[ Receive(x) ]->
  [ ServerState(x) ]
```

When running SpecMon with `--role client`, only rules with `role=client` (or no role attribute) are active.

**Usage:**

```bash
specmon monitor --role client protocol.spthy
```

## Best practices

- Prefer automatic decomposition; it produces correct triggers and hints for nested terms.
- When writing manual triggers, ensure the function names and argument shapes match the runtime events you emit.
- Use hints when a rule has multiple independent computations to avoid ambiguous interleavings.

## Next steps

- [**Creating Unified Models**](/specifications/unified-models/) — Write specifications that work with both Tamarin and SpecMon
- [**Encoding Message Formats**](/specifications/message-formats/) — Define concrete message formats
- [**Event Format**](/reference/event-format/) — Understand the event stream structure
