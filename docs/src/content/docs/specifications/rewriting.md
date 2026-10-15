---
title: Event Rewriting
description: Rewrite low-level event traces into SpecMon events
---

SpecMon's rewrite mode rewrites low-level function-call traces into higher-level events that match your specification. It consumes incoming events, applies rewrite rules, and emits new events via `PPEvent(...)`. This is useful for normalizing library call sequences and aligning concrete APIs with Tamarin-style function symbols.

## Overview

Unlike monitoring mode (which checks for violations), rewrite mode:
- Emits only the events produced by `PPEvent(...)` actions
- Rejects input events that are not matched by any rule
- Focuses on trace normalization, not property checking

If an event should be ignored, you must add an explicit rule that consumes it without emitting `PPEvent(...)`.

## Use cases

### Normalize library call chains

Rewrite multi-step APIs like `hash.New`/`hash.Write`/`hash.Sum` into a single abstract event `<h(x), hx>`:

```tamarin
theory RewriteHash
begin

// Create a digest object
rule DigestNew [trigger=[<hash_New_Enter(tid), <>>,
                         <hash_New_Leave(tid), <d>>]]:
  [ ] --> [ DigestNew(d) ]

// Accumulate input
rule DigestWrite [trigger=[<hash_Write_Enter(tid, d, x), <>>,
                           <hash_Write_Leave(tid, d, x), <>>]]:
  [ DigestNew(d) ] --> [ DigestState(d, x) ]

// Finalize and emit the abstract hash event
rule DigestSum [trigger=[<hash_Sum_Enter(tid, d), <>>,
                         <hash_Sum_Leave(tid, d), <hx>>]]:
  [ DigestState(d, x) ] --[ PPEvent(<h(x), hx>) ]-> [ ]

end
```

This makes the hash computation visible as a single abstract event the monitor can use in rules.

### Rename or shorten functions

Map verbose implementation calls to simpler specification names:

```tamarin
theory Rename
begin

rule Blake2sSum [trigger=[<blake2s_Sum256_Enter(tid, x), <>>,
                          <blake2s_Sum256_Leave(tid, x), <y>>]]:
  [ ] --[ PPEvent(<h(x), y>) ]-> [ ]

end
```

### Ignore irrelevant events

If a function call is not relevant for monitoring, consume it and emit nothing:

```tamarin
theory Ignore
begin

rule IgnoreEvent [trigger=[<runtime_Trace_Enter(tid, x), <>>,
                           <runtime_Trace_Leave(tid, x), <>>]]:
  [ ] --> [ ]

end
```

For command-line usage, see the [**CLI Reference**](/reference/cli/).

## Writing rewrite rules

Rewrite rules use the same rule syntax, but they *consume incoming events via triggers* and *emit output via `PPEvent(...)` actions*. Rules with triggers are used as written and are not decomposed.

### Basic rewrite rule

```tamarin
rule MapCall [trigger=[<foo_Enter(tid, x), <>>,
                       <foo_Leave(tid, x), <y>>]]:
  [ ] --[ PPEvent(<f(x), y>) ]-> [ ]
```

- Triggers match incoming events
- `PPEvent(<f(x), y>)` emits the rewritten event

Some instrumentation emits separate `Enter` and `Leave` events for a call. This is common when arguments may be overwritten after the call returns. The `Enter` event captures the input arguments, and the `Leave` event captures the return value so the rewrite rule can bind both safely.

### Stateful transformations

Use facts to maintain state across events:

```tamarin
rule Initialize [trigger=[<init_Enter(tid, id), <>>,
                          <init_Leave(tid, id), <>>]]:
  [ ] --> [ State(id, '0') ]

rule Process [trigger=[<step_Enter(tid, id, payload), <>>,
                       <step_Leave(tid, id, payload), <out>>]]:
  [ State(id, counter) ]
  -->
  [ State(id, add(counter, '1')), PPEvent(<processed(id, counter, payload), out>) ]
```

### Filtering or ignoring events

Input events must be matched by a rule; otherwise the trace is rejected. To ignore an event, add a rule that consumes the trigger and emits no `PPEvent(...)`.

### Aggregating events

Combine multiple low-level events into one abstract event:

```tamarin
rule Collect_Parts [trigger=[<part1_Leave(tid, id, a), <>>,
                             <part2_Leave(tid, id, b), <>>]]:
  [ ] --[ PPEvent(<combined(id, a, b), <>>) ]-> [ ]
```

### Computations in rewrite actions

In a rewrite rule, as in a monitoring rule, a computation denotes its observed result. A trigger `<f(x), y>` binds the computation `f(x)` to the result `y`, so `f(x)` elsewhere in the rule evaluates to `y`.

The outer call of an emitted event is the exception. In `PPEvent(<g(t1, ..., tn), r>)`, the call `g(...)` names the event and is kept as written, even where it equals a trigger's computation. Its arguments `t1, ..., tn` and the result `r` are evaluated as usual. A rule can therefore pass an event through unchanged:

```tamarin
rule PassThrough [trigger=[<f(x), y>]]:
  [ ] --[ PPEvent(<f(x), y>) ]-> [ ]
```

For the event `<f(0x01), 0x02>`, this rule emits `<f(0x01), 0x02>`. A computation nested inside the outer call still denotes its result: with the same trigger, `PPEvent(<wrapped(f(x)), <>>)` emits `<wrapped(0x02), <>>`.

Rewrite events must have a function call as their first component. The outer name cannot be a built-in (`slice`, `reverse`, `cat`, `byte`, `int`, `string`, `add`, `and`, `or`, `xor` or `not`). Explicit built-in heads fail loading, and calls bound dynamically are checked when their output is consumed. Pair-headed calls remain allowed. Built-ins nested in the arguments or result evaluate normally: `PPEvent(<receive(reverse(x)), r>)` with `x = 0x0102` and `r = <>` emits `<receive(0x0201), <>>`.

Triggered and hinted rewrite rules are used as written. Standalone `rewrite` decomposes other rules unless they have `no-decomp`, so their emitted call can be replaced by an observed result. Integrated `monitor -R` loads parsed rewrite rules without this decomposition. Give rewrite rules explicit triggers when they are intended to rewrite individual input events.

### Several rules for one event

If several rules, or several matches of one rule, apply to the same event, each rule application is a separate branch. `specmon monitor --rewrite-with` keeps these branches apart: each branch passes its own events to the monitor, and a branch whose events the monitor rejects ends. The standalone `specmon rewrite` command writes a single event stream and therefore requires a deterministic rewrite. Branches that emit the same events are merged, so such events are written once. If the branches for an event emit different events, including a branch that emits none, the command fails with a `nondeterministic rewrite` error that names the event.
