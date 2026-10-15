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
- **Description**: Terminate this positive PID with `SIGKILL` after a specification violation. When the flag is omitted, SpecMon does not terminate a process. Zero and negative values are rejected.

**`--on-violation <path>`**
- **Type**: string
- **Description**: Run this executable after a specification violation. The path is executed directly and is not interpreted by a shell; a name without a slash is looked up in `PATH`.

**`--on-violation-timeout <duration>`**
- **Type**: duration
- **Default**: `5s`
- **Description**: Limit violation hook execution. Zero disables the timeout. Negative durations are rejected.

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

The rewrite rules are used as parsed: `--defines` applies to them, while
`--role` and `--decompose` apply only to the monitoring rules. Both
specifications are loaded before any event is processed.

### Violation reactions

`--on-violation` runs only when the main monitor reports a genuine
specification violation: an event after which no branch of the main monitor
survives, whatever ended the branches (see [Failure reasons](#failure-reasons)).
It does not run for malformed input, transport failures, an event that no
rewrite rule accepts, broken internal invariants, or cancellation. The hook
names one executable or script, as a path or as a name without a slash that is
looked up in `PATH`. SpecMon does not invoke a shell or parse arguments from
it, so scripts need a valid shebang.

The hook receives one newline terminated JSON object on stdin. Both hook stdout
and hook stderr are forwarded to SpecMon stderr. Payload schema version 1 is:

```json
{
  "schema_version": "1",
  "kind": "violation",
  "error_kind": "no_applicable_rule",
  "error": "no applicable rule found",
  "event_index": 2,
  "time": 123456789,
  "event": {
    "name": "input",
    "type": "function",
    "args": [
      {
        "type": "constant",
        "const_kind": "int",
        "value": "9007199254740993"
      }
    ]
  },
  "event_term": "input(9007199254740993)",
  "spec_path": "model.spthy",
  "role": "client",
  "pid": 1234,
  "rewrite_with": "rewrite.spthy",
  "stats": {
    "received": 2,
    "processed": 1,
    "total_time": 1000000,
    "avg_latency_received": 20,
    "avg_latency_processed": 25,
    "avg_processing_time": 5,
    "med_latency_received": 20,
    "med_latency_processed": 25
  },
  "failures": {
    "final": [
      {
        "monitor": "core",
        "event": 2,
        "rule": "Check",
        "category": "restriction",
        "message": "restriction violated: Eq('1', '2')",
        "branch": "5b0e2c3a9f1d4e77"
      }
    ],
    "earlier": [],
    "counts": {
      "restriction": 1
    }
  }
}
```

`event_index` is one based and counts events delivered to the main monitor,
including pre-trace events and outputs from an inline rewriter. Raw events
consumed but not emitted by the rewriter do not count. `time` is the original
event timestamp in nanoseconds. Every duration in `stats` is also measured in
nanoseconds. Optional `role`, `pid`, and `rewrite_with` fields are omitted when
they are not configured. `event_term` provides a stable readable form of the
event alongside the version 2 typed JSON event representation. `failures`
reports why branches ended. See [Failure reasons](#failure-reasons).

The hook environment inherits the SpecMon environment and replaces these
values for the current violation:

- `SPECMON_HOOK_KIND=violation`
- `SPECMON_ERROR_KIND=no_applicable_rule`
- `SPECMON_EVENT_INDEX=<index>`
- `SPECMON_PID=<pid>` when a PID is configured

An inherited `SPECMON_PID` is removed when PID termination is disabled.

After a violation, SpecMon runs the hook first and then attempts configured PID
termination. A hook startup failure, nonzero exit, or timeout is reported on
stderr but does not replace the original monitor violation or skip PID
termination. A PID termination failure is handled the same way. The command
returns the original violation with a nonzero exit status after completing the
bounded reaction sequence; its error names the index and the term of the
rejected event, for example `Error: monitor violation at event 4: no applicable
rule found <done(), <>>`. A first signal that arrives after the violation is
captured does not cancel that sequence; only `--on-violation-timeout` limits
the hook. After the hook exits, SpecMon waits at most one second for its
standard streams, which a process that the hook starts in the background may
keep open.

### Signals

On a first `SIGINT` or `SIGTERM`, `monitor` and `rewrite` stop reading input,
print `signal received, exiting` on stderr, and exit with status 0; `monitor`
also prints its statistics line. A second signal ends SpecMon at once, also
while it waits for a violation hook or for a blocked output; the PID is then not
terminated and no error line is printed.

### Failure reasons

SpecMon records why each rule candidate and branch ended, whether or not other
branches survived. When an event is rejected, it prints the records on stderr
after the hook output and before the error: every record of the rejected event,
then the most recent records of earlier events as context, and the number of
records per category. The earlier records and the counts cover the whole
invocation: the pre-trace and the input, and with `--rewrite-with` both
monitors. The same report is the `failures` field of the hook payload. A rejection by the rewriter runs no hook, so its
report appears on stderr only. So does that of `specmon rewrite`.

Failure categories can be nonzero together. Counts are cumulative across
attempted candidates, including discarded alternatives and both monitors of
an integrated pipeline. Zero categories are omitted from the human summary
and JSON counts object. Treat missing JSON counts as zero. Hint continuation
records and counts are per attempted hint binding, so identical restriction
or dead-hint records can legitimately repeat.

A record has these fields:

- `monitor`: `rewrite` for the rewriter of `--rewrite-with` or of
  `specmon rewrite`, `core` for the monitor of the protocol model.
- `event`: the index of the event, from 1, among all events that the monitor
  received. For the core monitor it is counted like the payload's
  `event_index`, so it includes the pre-trace and, with `--rewrite-with`,
  counts the rewritten events. The field `rewrite.raw_event` is then the index of the
  raw event among the raw events.
- `rewrite`: for a record of the core monitor with `--rewrite-with`, the raw
  event (`raw_event`), the rewrite alternative of that raw event
  (`alternative`, from 1) and the position of the rewritten event among the
  events it emits (`position`, from 1). Each alternative of the rejected raw
  event keeps its records. The alternatives of one raw event count their
  events from the events consumed before it, so records of different
  alternatives can have the same `event`. The field `rewrite` tells them apart.
- `rule`: the rule whose candidate failed. Omitted if no candidate exists.
- `category`: `no_candidate` (no candidate of any rule consumes the event in
  the branch), `restriction` (an `Eq` or `Neq` restriction failed),
  `evaluation` (a term of a candidate that matched the event could not be
  evaluated), `epsilon_depth` (an epsilon candidate is left after the epsilon
  step, so the successor is pruned) or `dead_hint` (a hinted start has no
  continuation that consumes the event).
- `message`: the reason in words.
- `branch`: the hash of the configuration in which the event was tried, as 16
  hexadecimal digits.

The records of the rejected event explain the rejection. Earlier records are
context. The branches of an event are tried in the order of their
configuration hashes, so the records come in the same order in every run.
SpecMon keeps all records of the current event, the 256 most recent records of
earlier events, and the counts. On stderr, control characters in a message,
which can come from the trace, are escaped, so that every record is one line.

At a rejection, SpecMon also logs, at the default level `error`, the events
that each configuration of the rejecting monitor allows: `allowed events in
configuration N` for a monitor without `--rewrite-with`. With it, `allowed raw
events in rewrite configuration N` when the rewriter rejects the raw event, and
`allowed events in core configuration N (raw event R, alternative A, position
P)` for each rewrite alternative that the core monitor rejects.

### Rewrite command: `specmon rewrite`

**Usage**: `specmon rewrite [flags] <spec-path>`

**Description**: Rewrite low-level function-call traces into abstract SpecMon events using `PPEvent(...)` rules. Useful for normalizing library call chains and renaming functions. The output is a single event stream, so the rewrite must be deterministic: if the rule applications for one event emit different events, the command fails with a `nondeterministic rewrite` error (see [**Several rules for one event**](/specifications/rewriting/#several-rules-for-one-event)).

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

If no rewrite rule accepts an event, the command stops with an error that names
the index and the term of the rejected event, for example `Error: rewrite
events: rewrite violation at event 2: no applicable rule found <zzz(), <>>`.
The events emitted before it are written first.

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
        "type": "constant",
        "const_kind": "int",
        "value": "9007199254740993"
      },
      {
        "type": "constant",
        "const_kind": "string",
        "value": "text"
      },
      {
        "type": "constant",
        "const_kind": "bytes",
        "value": "0x0102"
      }
    ]
  }
}
```

Events are read as line-delimited JSON (one event per line). Lines starting with `//` are ignored.
Typed integer strings preserve the full signed 64 bit range. Empty bytes use
`"0x"`, while nil bytes use JSON `null`. Legacy constants without `const_kind`
remain accepted when their type is unambiguous, but SpecMon emits only the
typed representation. JSON output from `specmon rewrite` uses this same format
recursively for every constant.

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
- Batches consumed-event output while events are queued, and flushes before
  waiting for more input and before statistics, violation hooks, or signal
  messages. A lone event is therefore visible while the input remains open.
- `--out` is reserved and currently ignored

**Rewrite output (`--out file.log`)**:
- Writes rewritten events to the specified file
- Overwrites the file if it already exists
- Uses canonical typed constants when `--json` is enabled

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
