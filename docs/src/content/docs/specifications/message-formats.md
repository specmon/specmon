---
title: Encoding Message Formats
description: Define how symbolic terms map to concrete byte representations
---

Format strings bridge the gap between abstract Tamarin terms and concrete byte-level message formats. They enable unified models to work with real protocol implementations.

## The abstraction gap

When verifying protocols with Tamarin, you work with symbolic terms:

```tamarin
// Abstract: a tuple of symbolic values
handshake(sender_index, ephemeral_key, encrypted_payload)
```

But real protocol implementations work with bytes:

```
| Type (1) | Reserved (3) | Sender (4) | Ephemeral Key (32) | Payload (48) |
```

Format strings bridge this gap by defining exactly how symbolic terms map to byte sequences.

## How format strings work

Format strings are defined as macros inside `#ifdef SPECMON` blocks, making them available only during monitoring while verification uses abstract representations:

```tamarin
#ifdef SPECMON
macros:
  // Monitoring: concrete byte layout
  handshake(sender, eph_key, payload) =
    cat(byte('0x01', '1'),       // Message type: 1 byte
        byte('0x000000', '3'),   // Reserved: 3 bytes
        byte(sender, '4'),       // Sender index: 4 bytes
        byte(eph_key, '32'),     // Ephemeral key: 32 bytes
        byte(payload, '48'))     // Encrypted payload: 48 bytes
#else
macros:
  // Verification: abstract tuple
  handshake(sender, eph_key, payload) = <sender, eph_key, payload>
#endif
```

During **verification**, Tamarin sees `handshake(x, y, z)` as an abstract tuple `<x, y, z>` and reasons symbolically about its contents.

During **monitoring**, SpecMon uses the format string to:
1. **Parse incoming bytes** into symbolic terms (pattern matching)
2. **Construct outgoing bytes** from symbolic terms (message building)

## Building format strings

Format strings are built using three core functions combined with `cat`:

| Function | Purpose | Example |
|----------|---------|---------|
| `byte(data, len)` | Raw bytes | `byte(key, '32')` — 32-byte key |
| `int(data, len)` | Integer (little-endian) | `int(counter, '4')` — 4-byte integer |
| `string(data, len)` | UTF-8 string | `string(name, '16')` — 16-char string |
| `cat(...)` | Concatenate fields | `cat(byte(...), int(...))` |

The length parameter is required for parsing (to know field boundaries) but optional when only constructing messages.

### Fixed-length fields

Most protocol fields have fixed sizes:

```tamarin
macros:
  header(version, flags, length) =
    cat(byte(version, '1'),    // 1 byte
        byte(flags, '1'),      // 1 byte  
        int(length, '2'))      // 2 bytes (little-endian)
```

### Variable-length fields

The **last field** in a format string can omit the length to consume remaining bytes:

```tamarin
macros:
  message(header, payload) =
    cat(byte(header, '8'),     // Fixed 8-byte header
        byte(payload))         // Variable: rest of message
```

### Nested format strings

Format strings can reference other format strings for complex structures:

```tamarin
macros:
  header(type, len) = cat(byte(type, '1'), int(len, '2')),
  
  packet(type, len, data) = 
    cat(header(type, len),     // Reuse header format
        byte(data))            // Payload
```

## Pattern matching and parsing

When SpecMon receives bytes, it uses format strings to extract symbolic values. Given the format:

```tamarin
macros:
  msg(type, id, payload) = 
    cat(byte(type, '1'), int(id, '4'), byte(payload))
```

And incoming bytes `0x02 | 0x01000000 | 0xAABBCC...`:

1. First byte `0x02` binds to `type`
2. Next 4 bytes `0x01000000` bind to `id` (interpreted as integer 1)
3. Remaining bytes bind to `payload`

This allows rules to match on symbolic values:

```tamarin
rule Process_Request:
  [ In(msg('0x01', id, payload)) ]  // Match type = 0x01
  -->
  [ Request(id, payload) ]
```

## Real-world example: WireGuard handshake

The WireGuard protocol defines a handshake initiation message with this structure:

| Field | Size | Description |
|-------|------|-------------|
| Type | 1 | Message type (0x01) |
| Reserved | 3 | Zero padding |
| Sender Index | 4 | Sender's session ID |
| Ephemeral | 32 | Ephemeral public key |
| Static | 48 | Encrypted static key |
| Timestamp | 28 | Encrypted timestamp |
| MAC1 | 16 | First MAC |
| MAC2 | 16 | Second MAC |

The format string captures this exactly:

```tamarin
#ifdef SPECMON
macros:
  handshake_init(sender, eph, static, ts, mac1, mac2) =
    cat(byte('0x01', '1'),        // Type
        byte('0x000000', '3'),    // Reserved
        byte(sender, '4'),        // Sender Index
        byte(eph, '32'),          // Ephemeral Key
        byte(static, '48'),       // Encrypted Static
        byte(ts, '28'),           // Encrypted Timestamp
        byte(mac1, '16'),         // MAC1
        byte(mac2, '16'))         // MAC2
#endif
```

This ensures:
- **Verification**: Reasons about abstract `handshake_init(...)` terms
- **Monitoring**: Parses real WireGuard packets with exact byte offsets

## Best practices

### Match the wire format exactly

Format strings must precisely match the protocol's byte layout. Misalignment causes parsing failures or incorrect matches.

```tamarin
// ❌ Wrong: missing reserved bytes
handshake(sender, key) = cat(byte(sender, '4'), byte(key, '32'))

// ✅ Correct: includes all fields
handshake(sender, key) = 
  cat(byte('0x01', '1'),      // Don't forget type byte
      byte('0x000000', '3'),  // Don't forget padding
      byte(sender, '4'), 
      byte(key, '32'))
```

### Use constants for fixed values

Protocol-defined constants (magic bytes, version numbers) should be literals:

```tamarin
macros:
  request(data) = cat(byte('0x01', '1'), byte(data))   // Type 0x01
  response(data) = cat(byte('0x02', '1'), byte(data))  // Type 0x02
```

### Handle endianness explicitly

SpecMon uses little-endian by default. Use `reverse()` for big-endian fields:

```tamarin
macros:
  // Big-endian 4-byte length field
  header(length, data) = 
    cat(byte(reverse(length), '4'), byte(data))
```

The CCS paper describes format strings with big-endian integers by default. The current implementation uses little-endian, so apply `reverse()` when you need big-endian fields.

### Document field layouts

Complex format strings benefit from inline comments:

```tamarin
macros:
  tls_record(type, version, length, fragment) =
    cat(byte(type, '1'),          // ContentType: 1 byte
        int(version, '2'),        // ProtocolVersion: 2 bytes
        int(length, '2'),         // Length: 2 bytes (max 16384)
        byte(fragment))           // Fragment: variable
```

## Relationship to built-in functions

Format strings use the same functions documented in [Built-in Functions](/reference/built-in-functions/):

- `cat()`, `byte()`, `int()`, `string()` — for building format strings
- `slice()` — for extracting parts of parsed data
- `reverse()` — for endianness conversion

## Next steps

- [**Creating Unified Models**](/specifications/unified-models/) — Use format strings in unified specifications
- [**Event Format**](/reference/event-format/) — How events are structured
