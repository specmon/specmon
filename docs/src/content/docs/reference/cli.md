---
title: CLI Reference
description: Complete command-line interface reference for SpecMon
---

SpecMon provides a command-line interface for parsing specifications, monitoring event streams, and rewriting protocol traces. This reference covers all commands, flags, and usage patterns.

## Command overview

```
specmon [global-flags] <command> [command-flags] <arguments>
```

### Command hierarchy

- **`specmon [flags] <spec-path>`** - Parse and display specification
- **`specmon monitor [flags] <spec-path>`** - Monitor event streams in real-time
- **`specmon rewrite [flags] <spec-path>`** - Rewrite function-call traces into SpecMon events

## Global flags

These flags are available for all commands:

### Output control

**`--verbose, -v`**
- **Type**: boolean
- **Default**: false
- **Description**: Enable verbose output with detailed processing information
- **Example**: `specmon --verbose monitor protocol.spthy`

**`--quiet, -q`**
- **Type**: boolean
- **Default**: false
- **Description**: Suppress all output except errors
- **Example**: `specmon --quiet protocol.spthy`

**`--log-level, -l <level>`**
- **Type**: string
- **Default**: "error"
- **Values**: "panic", "fatal", "error", "warn", "info", "debug", "trace"
- **Description**: Set logging level for internal operations
- **Example**: `specmon --log-level info monitor protocol.spthy`

### Specification processing

**`--decompose, -d`**
- **Type**: boolean
- **Default**: true
- **Description**: Enable automatic rule decomposition
- **Example**: `specmon --decompose=false protocol.spthy`

**`--role, -r <role>`**
- **Type**: string
- **Description**: Select specific protocol role for monitoring (e.g., "client", "server")
- **Example**: `specmon --role client monitor wireguard.spthy`

**`--defines, -D <var>`**
- **Type**: string array
- **Description**: Define preprocessor variables for conditional compilation
- **Example**: `specmon --defines SPECMON --defines DEBUG monitor protocol.spthy`

**`--spec-path, -s <path>`**
- **Type**: string
- **Description**: Reserved; currently ignored. Use the positional `<spec-path>` argument instead.

### Performance profiling

**`--cpu-profile-path, -c <path>`**
- **Type**: string
- **Description**: Enable CPU profiling and write profile to specified path
- **Example**: `specmon --cpu-profile-path cpu.prof monitor protocol.spthy`

**`--mem-profile-path, -m <path>`**
- **Type**: string
- **Description**: Enable memory profiling and write profile to specified path
- **Example**: `specmon --mem-profile-path mem.prof monitor protocol.spthy`

### Version information

**`--version`**
- **Description**: Display SpecMon version information
- **Example**: `specmon --version`

## Commands

### Root command: `specmon`

**Usage**: `specmon [flags] <spec-path>`

**Description**: Parse and validate a Tamarin specification file, optionally applying role selection and rule decomposition. Displays the processed rules and statistics.

**Arguments**:
- `<spec-path>` - Path to the Tamarin specification file (.spthy)

**Example**:
```bash
# Basic specification parsing
specmon protocol.spthy

# Parse with role selection and verbose output
specmon --verbose --role client protocol.spthy

# Parse without decomposition
specmon --decompose=false complex-protocol.spthy
```

**Output**:
```
Specification: protocol.spthy (15 rules)
Selected role: client (8 rules)
Decomp result: 23 rules

  rule Client_Init:
    [ Fr(~id) ] --> [ !ClientState(~id) ]

  rule Client_Send:
    [ !ClientState(id), Fr(~nonce) ]
    --[ Send(id, ~nonce) ]->
    [ Out(request(id, ~nonce)), Waiting(id, ~nonce) ]

  ...
```

### Monitor command: `specmon monitor`

**Usage**: `specmon monitor [flags] <spec-path>`

**Description**: Monitor event streams in real-time or from files, applying the specification rules to detect protocol violations and security property breaches.

**Arguments**:
- `<spec-path>` - Path to the Tamarin specification file (.spthy)

**Flags**:

**`--in, -i <source>`**
- **Type**: string
- **Default**: stdin when piped; otherwise required
- **Description**: Input source for events
- **Formats**:
  - `"-"` - Read from stdin
  - `"file.json"` - Read from file
  - `"host:port"` - Listen on TCP socket
- **Example**: `specmon monitor --in events.json protocol.spthy`

**`--out, -o <destination>`**
- **Type**: string
- **Description**: Reserved; currently ignored

**`--pre-trace, -p <path>`**
- **Type**: string
- **Description**: Pre-load events from file before processing main input stream
- **Example**: `specmon monitor --pre-trace setup.json --in live-stream.json protocol.spthy`

**`--pid, -P <pid>`**
- **Type**: integer
- **Description**: Reserved; currently ignored

**`--rewrite-with, -R <spec-path>`**
- **Type**: string
- **Description**: Use integrated rewrite mode with specified rewrite rules
- **Example**: `specmon monitor --rewrite-with transform.spthy --pre-trace init.json protocol.spthy`

**Examples**:

```bash
# Monitor from file
specmon monitor --in trace.json --verbose protocol.spthy

# Monitor from stdin with pre-trace
specmon monitor --pre-trace setup.json protocol.spthy < live-events.json

# Monitor with role selection
specmon --role server monitor --in server-events.json protocol.spthy

# Integrated rewrite monitoring
specmon monitor --rewrite-with preprocessing.spthy --pre-trace init.json --in live.json protocol.spthy

# Monitor from TCP socket
specmon monitor --in localhost:8080 --verbose protocol.spthy
```

### Integrated rewrite monitoring

Use `--rewrite-with` to apply rewrite rules before monitoring. Pre-trace events (if provided) are fed directly to the main monitor, while live events are rewritten and then monitored.

```bash
specmon monitor --rewrite-with rewrite.spthy --pre-trace init.json --in live.json protocol.spthy
```

Use the same `--role` and `--defines` for both the rewrite and monitoring rules.

### Rewrite command: `specmon rewrite`

**Usage**: `specmon rewrite [flags] <spec-path>`

**Description**: Rewrite low-level function-call traces into abstract SpecMon events using `PPEvent(...)` rules. Useful for normalizing library call chains and renaming functions.

**Arguments**:
- `<spec-path>` - Path to the Tamarin specification file containing rewrite rules

**Flags**:

**`--json, -j`**
- **Type**: boolean
- **Default**: false
- **Description**: Output events in JSON format instead of text format
- **Example**: `specmon rewrite --json transform.spthy < input.json`

**`--in, -i <source>`**
- **Type**: string
- **Default**: stdin when piped; otherwise required
- **Description**: Input source for events (same formats as monitor command)
- **Example**: `specmon rewrite --in events.json transform.spthy`

**`--out, -o <destination>`**
- **Type**: string
- **Default**: stdout
- **Description**: Output destination for transformed events
- **Example**: `specmon rewrite --out transformed.json --json transform.spthy`

**Examples**:

```bash
# Basic event rewriting
specmon rewrite transform.spthy < raw-events.json

# Rewrite with JSON output
specmon rewrite --json --out transformed.json transform.spthy < input.json

# Rewrite from file to file
specmon rewrite --in raw.json --out clean.json --json transform.spthy

# Rewrite with role selection
specmon --role preprocessor rewrite --json transform.spthy < events.json
```

## Input/output formats

### Event stream input

SpecMon accepts event streams in JSON format with the following structure:

```json
{
  "time": 1750562792862000000,
  "event": {
    "name": "function_name",
    "type": "function",
    "args": [
      {
        "name": "parameter_name",
        "type": "function|constant",
        "args": [...],
        "value": "0x..."
      }
    ]
  }
}
```

Events are read as line-delimited JSON (one event per line). Lines starting with `//` are ignored.

### Input sources

**File Input (`--in file.json`)**:
- Read events from a JSONL/NDJSON file, one event per line
- Supports large files with streaming processing

**Standard Input (`--in -`)**:
- Read events from stdin pipe
- Real-time processing as events arrive
- Suitable for shell pipelines

**TCP Socket (`--in host:port`)**:
- Listen on `host:port` and accept TCP clients streaming events
- Real-time network monitoring
- Supports multiple concurrent clients

### Output destinations

**Monitor output**:
- Prints consumed events (unless `--quiet`) and a JSON stats summary to stdout
- `--out` is reserved and currently ignored

**Rewrite output (`--out file.log`)**:
- Writes rewritten events to the specified file
- Overwrites the file if it already exists

## Role selection

Use the `--role` flag to focus monitoring on specific protocol participants:

### Common roles

**Client Role (`--role client`)**:
- Monitor only client-side protocol rules
- Optimize performance for client-specific monitoring

**Server Role (`--role server`)**:
- Monitor only server-side protocol rules
- Useful for server-side deployment monitoring

**Custom Roles**:
- Any role defined in the specification
- Multiple roles can be defined in complex protocols
- Role-specific rule filtering improves performance

### Role usage examples

```bash
# Monitor WireGuard client behavior
specmon --role client monitor --in client-events.json wireguard.spthy

# Monitor server with debugging
specmon --role server --log-level debug monitor wireguard.spthy

# Parse specification for specific role
specmon --role initiator --verbose complex-protocol.spthy
```
