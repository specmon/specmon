---
title: What is SpecMon?
description: Introduction to SpecMon — runtime monitoring of formal specifications
---

SpecMon is a runtime monitoring tool that bridges the gap between formal verification and real-world implementations. It enables you to use the same specification for both proving security properties with [Tamarin](https://tamarin-prover.com/) and monitoring live applications.

## The problem

Security protocols are often verified using formal methods, then implemented separately. This creates a dangerous gap: the verified model and the actual implementation can diverge, leaving security properties unverified in production.

<div class="diagram">

```
┌─────────────────────┐         ┌─────────────────────┐
│                     │         │                     │
│    Tamarin Model    │         │   Implementation    │
│                     │   ???   │                     │
│    (Verified ✓)     │         │   (Monitored ?)     │
│                     │         │                     │
└─────────────────────┘         └─────────────────────┘

        Different specifications = Security gap
```

</div>

## The solution

SpecMon uses **unified models** — single Tamarin specifications that work for both formal verification and runtime monitoring:

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

With unified models, what you prove is exactly what you monitor.

## How it works

1. **Write a unified specification** using Tamarin's multiset-rewrite rules, with SpecMon extensions for concrete message formats

2. **Verify with Tamarin** to prove security properties hold mathematically

3. **Instrument your application** to emit events when protocol operations occur

4. **Monitor with SpecMon** to detect violations in real-time

## Key features

**Unified models**
: Single specification for verification and monitoring — no specification divergence

**Format strings**
: Bridge symbolic Tamarin terms with concrete byte-level message formats

**Real-time monitoring**
: Process event streams and detect violations as they occur

**Role-based monitoring**
: Monitor specific protocol roles (client, server) from the same specification

**Tamarin compatibility**
: Full support for Tamarin's modeling language and preprocessor

## Next steps

- [**Installation**](/getting-started/installation/) — Get SpecMon running on your system
- [**Quick Start**](/getting-started/quick-start/) — Monitor your first protocol in minutes
- [**Specification Basics**](/specifications/basics/) — Learn the specification language
