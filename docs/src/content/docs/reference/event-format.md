---
title: Event Format
description: Structure and format of events in SpecMon's monitoring pipeline
---

SpecMon monitors applications by processing streams of events. This page describes the structure of events and how to provide them to SpecMon.

## Event structure

Events are JSON objects with a timestamp and event data:

```json
{
  "time": 1700000000000000000,
  "event": {
    "name": "function_name",
    "type": "function",
    "args": [...]
  }
}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `time` | integer | Timestamp in nanoseconds (Unix epoch) |
| `event` | object | The event data |
| `event.name` | string | Name of the operation |
| `event.type` | string | Always `"function"` |
| `event.args` | array | Arguments to the operation |

## Argument types

Arguments can be constants or nested function calls:

### Constants

Concrete values like keys, messages, or bytes:

```json
{
  "value": "0x1234abcd",
  "type": "constant"
}
```

- Hex strings (starting with `0x`) represent byte arrays
- Plain strings represent text values
- Integers can be JSON numbers or strings (go-annotate emits strings)

### Functions

Nested function calls with their own arguments:

```json
{
  "name": "hash",
  "type": "function",
  "args": [
    {"value": "0x6d657373616765", "type": "constant"}
  ]
}
```

## Common event patterns

### Function call with return value

Most events represent a function call paired with its return value using the `pair` wrapper:

```json
{
  "time": 1700000000000000000,
  "event": {
    "name": "pair",
    "type": "function",
    "args": [
      {
        "name": "hash",
        "type": "function",
        "args": [
          {"value": "0x68656c6c6f", "type": "constant"}
        ]
      },
      {"value": "0x2cf24dba...", "type": "constant"}
    ]
  }
}
```

This represents: `hash("hello") = 0x2cf24dba...`

The `pair` structure is: `<function_call, return_value>`

## Input sources

SpecMon accepts events from multiple sources:

### File input

```bash
specmon monitor protocol.spthy --in events.json
```

Or via stdin:
```bash
cat events.json | specmon monitor protocol.spthy --in -
```

Here `--in -` is optional.

### TCP socket

```bash
specmon monitor protocol.spthy --in localhost:8080
```

SpecMon listens on the socket and the application connects to send events.

## Pre-trace events

Load initial state before processing live events:

```bash
specmon monitor protocol.spthy --pre-trace setup.json --in live-events.json
```

Pre-trace events establish facts (like long-term keys) before monitoring begins.

## Requirements

1. **Use line-delimited JSON**: One JSON object per line (lines starting with `//` are ignored)
2. **Use hex encoding for bytes**: Prefix with `0x` for binary data
3. **Pair function calls with results**: Use the `pair` wrapper consistently
4. **Include timestamps**: Allow per-event timing analysis
5. **Match specification names**: Event function names should match rule triggers
6. **Handle encoding consistently**: Use the same encoding throughout

## Debugging events

### Validate format

Check that events are valid JSON:
```bash
cat events.json | jq .
```

### Inspect with verbose mode

```bash
specmon monitor --verbose protocol.spthy < events.json
```

This shows each event as it's processed and which rules fire.

### Common issues

**Events not matching rules:**
- Check function names match specification
- Verify argument order and types
- Ensure `pair` wrapper is present for function calls with results

**Timestamp issues:**
- Use nanoseconds precision
- Check for clock skew in distributed systems

**Encoding problems:**
- Use `0x` prefix for hex-encoded bytes
- Ensure consistent string encoding (UTF-8)

## Next steps

- [**Using go-annotate**](/instrumentation/go-annotate/) — Automatic Go instrumentation
- [**Using Frida**](/instrumentation/frida/) — Dynamic instrumentation
- [**CLI Commands**](/reference/cli/) — Monitor command options
