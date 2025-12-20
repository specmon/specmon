---
title: Quick Start
description: Monitor your first protocol in minutes
---

This guide walks through monitoring a tiny encryption flow. You'll write a minimal specification, instrument a small Go program, and monitor the resulting trace.

## Prerequisites

- [SpecMon installed](/getting-started/installation/)
- [Go 1.21+](https://go.dev/)
- [go-annotate](https://github.com/specmon/go-annotate) for instrumentation

## Step 1: write the specification

Create `quick-encrypt.spthy`:

```tamarin
theory QuickEncrypt

begin

functions: senc/2

rule Encrypt:
  [ In($m), Fr(~k) ] --> [ Out(senc(~k, $m)) ]

#ifdef SPECMON
// SpecMon's explicit interface to the environment.
// Tamarin has built-in intruder rules for input and randomness.
rule Fr [trigger=[<random(), k>]]:
  [ ] --> [ Fr(k) ]

rule In [trigger=[<receive(), m>]]:
  [ ] --> [ In(m) ]
#endif

end
```

Use `SPECMON` as the preprocessor symbol for the monitoring view. You can pick any symbol name and define it with `--defines`/`-D`.

## Step 2: add a rewrite specification

Create `quick-encrypt-rewrite.spthy` to map go-annotate events to the abstract calls used in the model:

```tamarin
theory QuickEncryptRewrite

begin

rule Random [trigger=[<random_Enter(tid), <>>,
                      <random_Leave(tid), <k>>]]:
  [ ] --[ PPEvent(<random(), k>) ]-> [ ]

rule Receive [trigger=[<receive_Enter(tid), <>>,
                       <receive_Leave(tid), <m>>]]:
  [ ] --[ PPEvent(<receive(), m>) ]-> [ ]

rule Encrypt [trigger=[<encrypt_Enter(tid, k, m), <>>,
                       <encrypt_Leave(tid, k, m), <c>>]]:
  [ ] --[ PPEvent(<senc(k, m), c>) ]-> [ ]

end
```

go-annotate emits `Enter` and `Leave` events for each function. Consume both so every event is matched, and bind inputs on entry and outputs on return. Return values are written as tuples: `<>>` for no return value, `<x>` for one return value, and `<x, y>` for two return values.

## Step 3: create the program

Create `crypto.go`:

```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

func random() []byte {
	key := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, key)
	return key
}

func receive() []byte {
	return []byte("hello")
}

func encrypt(key, msg []byte) []byte {
	block, _ := aes.NewCipher(key)
	iv := make([]byte, aes.BlockSize)
	stream := cipher.NewCTR(block, iv)
	out := make([]byte, len(msg))
	stream.XORKeyStream(out, msg)
	return out
}
```

Create `main.go`:

```go
package main

import "fmt"

func main() {
	msg := receive()
	key := random()
	ciphertext := encrypt(key, msg)
	fmt.Printf("ciphertext: %x\n", ciphertext)
}
```

The function names (`random`, `receive`, `encrypt`) are used by the rewrite rules to emit the abstract events in the specification.

## Step 4: instrument and run

Instrument the crypto helper functions and run the program to generate `events.json`.

```bash
go mod init quick-encrypt
go install github.com/specmon/go-annotate@latest
go-annotate -returns -import "github.com/specmon/go-annotate/log" -w crypto.go
go mod tidy
export GO_ANNOTATE_LOG_TARGET="events.json"
export GO_ANNOTATE_LOG_FORMAT="json"
go run main.go crypto.go
```

## Step 5: rewrite and monitor

Use the integrated rewrite mode to transform raw go-annotate events into SpecMon events before monitoring the trace.

```bash
specmon --defines SPECMON monitor --rewrite-with quick-encrypt-rewrite.spthy \
  --in events.json quick-encrypt.spthy
```

See [CLI reference](/reference/cli/#integrated-rewrite-monitoring) for details on integrated rewrite monitoring.

If the trace is accepted, SpecMon finishes without errors and prints a summary.

## Detecting violations

To trigger a violation, edit `events.json` and remove the `encrypt_Leave` event. The rewrite stage will drop the encryption event, and the monitor will reject the trace.

## Next steps

- [**Specification Basics**](/specifications/basics/) — Learn the full specification language
- [**SpecMon Annotations**](/specifications/annotations/) — Use advanced features like triggers
- [**Event Rewriting**](/specifications/rewriting/) — Normalize traces from real instrumentation
- [**Using go-annotate**](/instrumentation/go-annotate/) — Detailed instrumentation guide
