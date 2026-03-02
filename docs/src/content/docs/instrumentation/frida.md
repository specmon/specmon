---
title: Using Frida
description: Dynamic instrumentation with Frida for SpecMon monitoring
---

[Frida](https://frida.re/) is a dynamic instrumentation toolkit that lets you inject code into running applications. It's useful for monitoring applications written in any language, including binaries without source code.

## Installation

Install Frida tools:

```bash
pip install frida-tools
```

For specific platforms, see the [Frida documentation](https://frida.re/docs/installation/).

## Basic approach

The workflow for Frida-based monitoring:

1. **Write a Frida script** that hooks target functions and emits events
2. **Run the target application** with Frida attached
3. **Pipe events to SpecMon** for monitoring

## Event emission

Your Frida script should emit events in SpecMon's JSON format:

```javascript
function emitEvent(name, args, result) {
    const event = {
        time: Math.floor(Date.now() * 1e6),
        event: {
            name: "pair",
            type: "function",
            args: [
                {
                    name: name,
                    type: "function",
                    args: args.map(arg => ({
                        value: arg,
                        type: "constant"
                    }))
                },
                {
                    value: result,
                    type: "constant"
                }
            ]
        }
    };
    console.log(JSON.stringify(event));
}
```
See [Event Format](/reference/event-format/) for details on the expected structure.
`Date.now()` has millisecond resolution; multiplying by `1e6` yields nanoseconds with millisecond granularity.


## Hooking example: OpenSSL

### Frida script

Here's an example Frida script that hooks OpenSSL's SHA256 and HMAC functions to emit events:

```javascript
// Helper to convert bytes to hex string
function toHex(buffer) {
    if (buffer === null) return "0x";
    const bytes = new Uint8Array(buffer);
    return "0x" + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Emit SpecMon event
function emitEvent(name, args, result) {
    const event = {
        time: Math.floor(Date.now() * 1e6),
        event: {
            name: "pair",
            type: "function",
            args: [
                {
                    name: name,
                    type: "function",
                    args: args.map(arg => ({value: arg, type: "constant"}))
                },
                {value: result, type: "constant"}
            ]
        }
    };
    console.log(JSON.stringify(event));
}

// Hook OpenSSL SHA256
const SHA256 = Module.findExportByName("libcrypto.so", "SHA256");
if (SHA256) {
    Interceptor.attach(SHA256, {
        onEnter: function(args) {
            this.data = args[0].readByteArray(parseInt(args[1]));
        },
        onLeave: function(retval) {
            const result = retval.readByteArray(32);
            emitEvent("sha256", [toHex(this.data)], toHex(result));
        }
    });
}

// Hook OpenSSL HMAC
const HMAC = Module.findExportByName("libcrypto.so", "HMAC");
if (HMAC) {
    Interceptor.attach(HMAC, {
        onEnter: function(args) {
            // args: evp_md, key, key_len, data, data_len, md, md_len
            this.key = args[1].readByteArray(parseInt(args[2]));
            this.data = args[3].readByteArray(parseInt(args[4]));
        },
        onLeave: function(retval) {
            const result = retval.readByteArray(32);
            emitEvent("hmac", [toHex(this.key), toHex(this.data)], toHex(result));
        }
    });
}

console.log("Hooks installed");
```

### Running with SpecMon

Here's how to run your target application with Frida and pipe events to SpecMon:

```bash
# Run application with Frida and pipe to SpecMon
frida -l hook_crypto.js -f ./target_app 2>/dev/null | \
    specmon monitor protocol.spthy --in -
```

## Integration with SpecMon

### Direct piping

```bash
frida -l script.js -f ./app 2>/dev/null | specmon monitor spec.spthy --in -
```

### Via file

```bash
# Collect events
frida -l script.js -f ./app > events.json 2>/dev/null

# Monitor offline
specmon monitor spec.spthy --in events.json
```

### Via socket

For long-running applications:

```javascript
// In Frida script: send to socket instead of stdout
const socket = new Socket("localhost", 8080);

function emitEvent(name, args, result) {
    const event = { /* ... */ };
    socket.write(JSON.stringify(event) + "\n");
}
```

```bash
# Terminal 1: SpecMon listens
specmon monitor spec.spthy --in localhost:8080

# Terminal 2: Run with Frida
frida -l script.js -f ./app
```

## Debugging

### List available exports

```javascript
// Find functions in a library
Module.enumerateExports("libcrypto.so").forEach(function(exp) {
    if (exp.name.includes("SHA")) {
        console.log(exp.name + " @ " + exp.address);
    }
});
```

### Log function calls

```javascript
Interceptor.attach(target, {
    onEnter: function(args) {
        console.log("Called with: " + args[0] + ", " + args[1]);
    }
});
```

### Check event format

```bash
# Pretty-print events
frida -l script.js -f ./app 2>/dev/null | head -5 | jq .
```

## Best practices

1. **Handle null pointers**: Check before reading memory
2. **Use correct lengths**: Read the actual data length, not buffer capacity
3. **Test incrementally**: Verify each hook before adding more
4. **Match specification names**: Use function names that match your triggers

## Next steps

- [**Event Format**](/reference/event-format/) — Event structure reference
- [**SpecMon Annotations**](/specifications/annotations/) — Configure triggers
