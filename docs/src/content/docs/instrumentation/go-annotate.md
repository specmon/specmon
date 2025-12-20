---
title: Using go-annotate
description: Automatic instrumentation of Go applications for SpecMon monitoring
---

[go-annotate](https://github.com/specmon/go-annotate) automatically instruments Go source code to emit events for SpecMon monitoring. It uses AST transformation to inject logging calls at function entry and exit points.

## Installation

```bash
go install github.com/specmon/go-annotate@latest
```

Or build from source:

```bash
git clone https://github.com/specmon/go-annotate.git
cd go-annotate
go build
```

## Basic usage

### Instrument source files

```bash
go-annotate -import "github.com/specmon/go-annotate/log" -w main.go
```

This modifies `main.go` in place, adding instrumentation to all functions.

**Options:**
- `-import <path>` — Import path for the logging package (required)
- `-w` — Write changes back to source files (otherwise prints to stdout)
- `-exported` — Only instrument exported functions
- `-returns` — Include function return values in events
- `-timing` — Include timing information (implies `-returns`)

### Preview changes

Without `-w`, changes are printed to stdout:

```bash
go-annotate -import "github.com/specmon/go-annotate/log" main.go
```

### Instrument multiple files

```bash
go-annotate -import "github.com/specmon/go-annotate/log" -w *.go
```

## Configuration

### Environment variables

Configure logging behavior at runtime:

| Variable | Description | Values |
|----------|-------------|--------|
| `GO_ANNOTATE_LOG_TARGET` | Output destination | File path, `host:port`, or TCP sockets |
| `GO_ANNOTATE_LOG_FORMAT` | Output format | `json`, `cbor`, `text`, `debug` |

### File output

```bash
export GO_ANNOTATE_LOG_TARGET="/path/to/events.json"
export GO_ANNOTATE_LOG_FORMAT="json"
go run main.go
```

### Socket output

For real-time streaming to SpecMon:

```bash
# Terminal 1: Start SpecMon
specmon monitor protocol.spthy --in localhost:8080

# Terminal 2: Run instrumented application
export GO_ANNOTATE_LOG_TARGET="localhost:8080"
export GO_ANNOTATE_LOG_FORMAT="json"
go run main.go
```

### Output formats

| Format | Use case |
|--------|----------|
| `json` | SpecMon monitoring, general purpose |
| `cbor` | High-performance binary encoding |
| `text` | Human-readable debugging |
| `debug` | Verbose debugging output |

## Example

### Original code

```go
package main

import (
    "crypto/sha256"
    "fmt"
)

func Hash(data []byte) []byte {
    h := sha256.Sum256(data)
    return h[:]
}

func main() {
    input := []byte("hello")
    result := Hash(input)
    fmt.Printf("Hash: %x\n", result)
}
```

### After instrumentation

```go
package main

import (
	"crypto/sha256"
	"fmt"

	__log "github.com/specmon/go-annotate/log"
)

func Hash(data []byte) []byte {
	__traceID := __log.
		ID()

	__log.LogEnter(__traceID, "Hash",
		[]any{data})
	res1 := func() []byte {
		h := sha256.Sum256(data)
		return h[:]
	}()
	defer func() {
		__log.
			LogLeave(__traceID, "Hash", []any{
				data,
			}, []any{res1})
	}()
	return res1
}

func main() {
	__traceID := __log.
		ID()

	__log.LogEnter(__traceID, "main",
		[]any{})
	defer func() {
		__log.
			LogLeave(__traceID, "main", []any{}, []any{})
	}()

	input := []byte("hello")
	result := Hash(input)
	fmt.Printf("Hash: %x\n", result)
}
```

### Generated events

```json
{"time":1766155636513499000,"event":{"name":"pair","type":"function","args":[{"name":"Hash_Enter","type":"function","args":[{"type":"constant","value":"2"},{"type":"constant","value":"0x68656c6c6f"}]},{"name":"pair","type":"function"}]}}
{"time":1766155636513521000,"event":{"name":"pair","type":"function","args":[{"name":"Hash_Leave","type":"function","args":[{"type":"constant","value":"2"},{"type":"constant","value":"0x68656c6c6f"}]},{"name":"pair","type":"function","args":[{"type":"constant","value":"0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}]}]}}
```

## Integration with SpecMon

### Complete workflow

1. **Instrument your code:**
   ```bash
   go-annotate -import "github.com/specmon/go-annotate/log" -w *.go
   ```

2. **Write your specification:**
   ```tamarin
   theory MyProtocol
   begin
   
   rule Process_Hash [trigger=[<hash(data), result>]]:
     [ In(data) ]
   --[ Hashed(data, result) ]->
     [ HashResult(result) ]
   
   end
   ```

3. **Write a rewrite specification (save as `rewrite.spthy`):**
   ```tamarin
   theory MyProtocolRewrite
   begin

   rule Hash [trigger=[<Hash_Enter(tid, data), <>>,
                       <Hash_Leave(tid, data), <result>>]]:
     [ ] --[ PPEvent(<hash(data), result>) ]-> [ ]

   end
   ```

4. **Run with monitoring:**
   ```bash
   export GO_ANNOTATE_LOG_TARGET="localhost:8080"
   export GO_ANNOTATE_LOG_FORMAT="json"
   
   # Terminal 1
   specmon monitor --rewrite-with rewrite.spthy protocol.spthy --in localhost:8080
   
   # Terminal 2
   go run main.go
   ```

### Matching function names

go-annotate emits paired `*_Enter` and `*_Leave` events for each function call. Use rewrite rules to map those events to the abstract function names you use in your specification:

```tamarin
// rewrite.spthy
rule Hash [trigger=[<Hash_Enter(tid, data), <>>,
                    <Hash_Leave(tid, data), <result>>]]:
  [ ] --[ PPEvent(<hash(data), result>) ]-> [ ]
```

This keeps your monitoring specification clean and avoids depending on go-annotate’s low-level event shape.

## Troubleshooting

### No events generated

Check environment variables:
```bash
echo $GO_ANNOTATE_LOG_TARGET
echo $GO_ANNOTATE_LOG_FORMAT
```

If `GO_ANNOTATE_LOG_TARGET` is not set, logging is disabled.

### Connection refused

Ensure SpecMon is listening before starting the application:
```bash
# Start SpecMon first
specmon monitor --rewrite-with rewrite.spthy protocol.spthy --in localhost:8080 &
sleep 1
# Then start the application
go run main.go
```

### Events not matching rules

Check that:
- Function names match (including package prefix)
- Argument order matches
- Trigger syntax is correct

Use verbose mode to debug:
```bash
specmon monitor --verbose protocol.spthy --in events.json
```

## Next steps

- [**Event Format**](/reference/event-format/) — Understand event structure
- [**SpecMon Annotations**](/specifications/annotations/) — Configure triggers
- [**Quick Start**](/getting-started/quick-start/) — Complete example
