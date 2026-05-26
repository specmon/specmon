---
title: Creating Unified Models
description: Write specifications that work for both Tamarin verification and SpecMon monitoring
---

Unified models are single Tamarin specifications that work for both formal verification and runtime monitoring. This eliminates specification divergence — the dangerous gap between what you prove and what you monitor.

## Why unified models?

Traditional approaches maintain separate models:

<div class="diagram">

```
┌────────────────────┐         ┌──────────────────┐
│                    │         │                  │
│ Verification Model │   ???   │ Monitoring Model │
│                    │         │                  │
└────────────────────┘         └──────────────────┘
          │                              │
          ▼                              ▼
 Mathematical proofs              Runtime checks
```

</div>

Problems with separate models:
- **Specification drift**: Models diverge as they're maintained separately
- **Semantic mismatches**: Different interpretations of protocol behavior
- **False confidence**: Proofs don't reflect what's actually monitored

Unified models solve this:

<div class="diagram">

```
┌─────────────────────────────────────────────────┐
│                                                 │
│              Unified Specification              │
│                                                 │
│                  (protocol.spthy)               │
│                                                 │
└─────────────────────────────────────────────────┘
                         │
           ┌─────────────┴─────────────┐
           │                           │
           ▼                           ▼
┌─────────────────────┐     ┌─────────────────────┐
│                     │     │                     │
│       Tamarin       │     │       SpecMon       │
│                     │     │                     │
│     Verification    │     │   Runtime Monitor   │
│                     │     │                     │
└─────────────────────┘     └─────────────────────┘
           │                           │
           ▼                           ▼

    Security proofs             Live detection

    of properties               of violations
```

</div>

## Using the preprocessor (optional)

Unified models do not require preprocessor directives. They are simply one way to keep a single specification while selecting between a **verification view** and a **monitoring view** when needed. The directives are plain text preprocessing; you enable them by passing `--defines`/`-D` when invoking tools.

### Format-string macros

In the monitoring view, macros define **format strings** that describe concrete byte layouts. In the verification view, the same macros usually expand to tuples so the adversary can access each component symbolically. See [**Encoding Message Formats**](/specifications/message-formats/) for the full format string language.

```tamarin
#ifdef SPECMON
macros:
  handshake(sender, pekI, astat, ats, mac1, mac2) =
    cat(byte('0x01', '1'), byte('0x000000', '3'),
        byte(sender, '4'), byte(pekI, '32'),
        byte(astat, '48'), byte(ats, '28'),
        byte(mac1, '16'), byte(mac2, '16'))
#else
macros:
  handshake(sender, pekI, astat, ats, mac1, mac2) =
    <sender, pekI, astat, ats, mac1, mac2>
#endif
```

This pattern keeps the rules unchanged while swapping the macro expansions based on your chosen preprocessor symbol.

### Boolean operators in `#ifdef`

Conditions accept `not`, `&`, `|`, and parentheses, matching Tamarin's preprocessor. This lets a single condition gate a section without introducing an extra positive sentinel define.

```tamarin
#ifdef not SPECMON
// Verification-only section: included unless --defines SPECMON is set.
#endif

#ifdef Properties & not Sanity
// Included when Properties is defined and Sanity is not.
#endif

#ifdef (Properties | Sanity) & not Release
// Included when at least one of Properties or Sanity is defined,
// and Release is not.
#endif
```

A bare identifier without operators continues to work as before.

### Monitoring-specific setup (optional)

Some models include monitoring-only setup rules (for example, reading keys from instrumentation events) and verification-only setup rules (for example, generating fresh keys with `Fr`). Keep these differences minimal and tightly scoped.

## Defining a preprocessor symbol

Preprocessor variables are user-defined; they have no built-in meaning. You choose any symbol name and define it via `--defines`/`-D` when running tools.

Examples:

```bash
# Monitoring view
specmon --defines SPECMON monitor wireguard.spthy

# Verification view
# (no define, or define a different symbol)
tamarin-prover --prove wireguard.spthy
```

## Testing unified models

1. Verify in Tamarin (without your monitoring define).
2. Monitor with SpecMon (with your monitoring define).
3. If one view fails, check macro arities, format strings, and any monitoring-only setup rules.

## Best practices

1. **Keep shared rules maximal**: Put core protocol behavior outside `#ifdef` blocks.
2. **Use macros for formats**: In the monitoring block, define byte layouts; in the verification block, map to tuples.
3. **Match macro arities**: Both views must accept the same arguments.
4. **Document formats**: Comment byte layouts so they stay aligned with the implementation.
5. **Test both views**: Verify with Tamarin and monitor with SpecMon on real traces.

## Next steps

- [**Encoding Message Formats**](/specifications/message-formats/) — Define concrete byte layouts
- [**SpecMon Annotations**](/specifications/annotations/) — Control rule decomposition and triggers
