# ⚡ HTPPS — HTTPS Server From Scratch

A high-performance HTTPS server written entirely in C with **zero external dependencies**. Every layer — TCP sockets, TLS 1.2, HTTP parsing, cryptography, and a JavaScript engine — is implemented from scratch.

## Performance

Benchmarked against Nginx, Node.js, and Python (50,000 requests, concurrency 100):

| Server | Req/sec | CPU Ticks | Energy Efficiency |
|---|---|---|---|
| **HTPPS** | **21,955** | **91** | **1.0×** ⚡ |
| Nginx 1.26 | 22,724 | 197 | 2.16× more CPU |
| Python | 6,979 | 740 | 8.1× more CPU |
| Node.js | 5,378 | 910 | 10× more CPU |

**53% less CPU than Nginx with full memory safety between clients.**

## How It's So Fast

| Technique | What It Does |
|---|---|
| **AES-NI assembly** | Hardware AES encrypt/decrypt (1 instruction per round) |
| **SHA-NI assembly** | Hardware SHA-256 (2 rounds per instruction) |
| **64-bit MUL assembly** | Native carry-chain multiplication for RSA |
| **JIT'd syscalls** | Direct `syscall` instruction — bypasses libc entirely |
| **Response cache** | index.html pre-built in RAM (~3.4KB) — zero disk I/O |
| **fast_accept** | Direct accept syscall — no IP string formatting |
| **Precision wipe** | Only zeros bytes actually used (~9KB not 1.6MB) |
| **Pre-allocated buffers** | Zero malloc/free per request |

## Architecture

```
┌─────────────────────────────────────────────────┐
│  main.c — Server loop + response cache          │
├─────────────────────────────────────────────────┤
│  http.c — HTTP/1.1 parser & response builder    │
│  router.c — Static files + JS API routes        │
│  tcp.c — Raw TCP socket layer                   │
├─────────────────────────────────────────────────┤
│  tls/ — TLS 1.2 handshake + record layer        │
├─────────────────────────────────────────────────┤
│  crypto/ — SHA-256, HMAC, AES-128, RSA, BigNum  │
│  crypto/fast/ — AES-NI, SHA-NI, 64-bit MUL asm  │
├─────────────────────────────────────────────────┤
│  fast/ — Direct syscall I/O (bypass libc)       │
├─────────────────────────────────────────────────┤
│  jsengine/ — JS interpreter + JIT compiler      │
└─────────────────────────────────────────────────┘
```

## Request Flow (for `/`)

```
  accept (direct syscall)
    → recv (direct syscall)
      → parse HTTP (in-place, no copy)
        → path == "/" ? send cached response (3.4KB from RAM)
          → wipe only ~500 bytes used in recv buffer
            → close (direct syscall)

  Total: 3 syscalls, 1 strcmp, 1 memset. No disk. No malloc. No formatting.
```

## Security

- **Precision buffer wiping** — zeros exactly the bytes used between clients
- **No data leaks** — previous client data never visible to next client
- **Directory traversal blocked** — `..` paths rejected
- **Custom TLS** — no dependency on OpenSSL (500K LOC attack surface)

## Build & Run

```bash
make                      # Build
./server --http           # HTTP on port 8080
./server --https          # HTTPS on port 4443
./server                  # Both
make test                 # Run crypto test suite (19 tests)
```

## Zero Dependencies

No OpenSSL. No libuv. No libcurl. No npm. The only requirements are:
- GCC (C11)
- NASM (for x86_64 assembly)
- Linux (POSIX sockets)

## Project Structure

```
src/
├── main.c              # Server entry point + response cache
├── tcp.c/h             # Raw TCP sockets
├── http.c/h            # HTTP parser & response builder
├── router.c/h          # Static file server + API routing
├── crypto/
│   ├── aes.c/h         # AES-128 (ECB + CBC)
│   ├── sha256.c/h      # SHA-256
│   ├── hmac.c/h        # HMAC-SHA256
│   ├── bignum.c/h      # Arbitrary-precision arithmetic
│   ├── rsa.c/h         # RSA encrypt/decrypt
│   ├── pem.c/h         # PEM/DER key parser
│   └── fast/           # x86_64 ASM acceleration
│       ├── crypto_ops.asm  # AES-NI, SHA-NI, BigNum
│       ├── cpuid.asm       # CPU feature detection
│       └── fast_crypto.c/h # C dispatch layer
├── fast/
│   └── fast_io.asm     # Direct syscall wrappers + SSE2 memchr
└── tls/
    ├── handshake.c     # TLS 1.2 handshake
    ├── record.c        # TLS record layer
    ├── prf.c           # PRF (key derivation)
    └── tls_io.c        # TLS read/write

jsengine/               # Built-in JavaScript engine
├── jsengine.c/h        # Public API
└── src/
    ├── core/           # Lexer, parser, evaluator
    ├── jit/            # x86_64 JIT compiler
    └── fast/           # ASM math operations

www/                    # Web root (static files + JS API)
tests/                  # Crypto test suite
certs/                  # TLS certificates
```

## License

MIT
