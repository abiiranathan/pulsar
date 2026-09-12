# AGENTS.md

## Project intent

This repository is a high-performance, Linux-x86_64 focused C HTTP server library. The default design goal is maximum throughput and minimum per-request overhead. Do not make changes that add portability or abstraction layers unless the benefit is clearly worth the performance cost.

This project is optimized for Linux x86_64 and should preserve that assumption in code and benchmarks. Favor direct kernel interfaces, minimal allocations, and tight hot paths.

## Primary code locations

- Core public API: `include/pulsar.h` and `include/forms.h`
- Runtime structures and request/response state: `include/types.h`
- Routing and route metadata: `include/routing.h`
- Header handling: `include/headers.h`
- HTTP methods: `include/method.h`
- Event loop / epoll integration: `include/events.h`
- Direct syscall layer: `include/pulsar_syscall.h`
- Constants and tuning values: `include/constants.h`
- Implementation: `src/*.c`
- Benchmarks and profiling scripts: `scripts/*.sh`

### Important type definitions

- `PulsarConn` is the main per-connection runtime object and is defined in `include/types.h`.
- `request_t` and `response_t` are also defined there and carry the connection lifecycle data.
- `route_t` is defined in `include/routing.h`.
- `headers_t` is defined in `include/headers.h`.
- `HttpMethod` is defined in `include/method.h`.
- `event_queue_t` and `event_t` live in `include/events.h`.

## Performance requirements

Treat performance as a first-class correctness requirement.

### Must prioritize

- Low allocation count per request
- Fast path code inlined and branch-light
- Cache-friendly data layout
- O(1) routing / dispatch paths
- Avoiding heap churn in hot paths
- Minimal syscalls and minimal context switches
- Maintaining connection reuse and keep-alive efficiency

### Avoid unless clearly necessary

- Generic abstractions that hide cost
- Cross-platform fallback code in the hot path
- Per-request heap allocations
- Unbounded dynamic growth in request handling
- Extra copies when pointer slicing or direct buffer use is sufficient

## Linux x64 specific expectations

This codebase is not a portable generic server. It is intentionally aligned with Linux x86_64 behavior.

- Prefer Linux primitives such as `epoll`, `accept4`, direct `read` / `write`, and syscall wrappers.
- Favor kernel-native semantics over libc wrappers when the performance difference is meaningful.
- Keep code compatible with the project’s chosen Linux assumptions and x64 calling conventions.
- Do not add generic fallback logic in the hot path unless it is clearly gated and measured.

## Zero-copy and minimal-copy rules

Prefer zero-copy or near-zero-copy behavior wherever practical.

- Use pointer arithmetic and `StrSlice`-style views instead of duplicating strings when possible.
- Keep request buffers alive for the lifetime of the connection instead of re-materializing data unnecessarily.
- Avoid copying headers, bodies, or route segments unless required by the API contract.
- Preserve in-place parsing and slicing when possible.
- When a copy is required, make it a deliberate, well-justified design choice rather than a default pattern.

## Raw syscalls and direct kernel access

When practical, prefer direct syscall access over libc convenience wrappers in performance-critical code.

- Use the raw syscall layer in `include/pulsar_syscall.h` for Linux kernel interaction.
- Prefer direct, minimal wrappers for event handling, I/O, and other hot-path primitives.
- Keep syscall wrappers small, explicit, and easy to audit.
- Do not layer extra error handling or logging on the fast path unless it is required and measured.

## Benchmarking and perf workflow

Use the repo’s scripts for benchmarking and profiling, not ad hoc commands.

### Standard scripts

- `./scripts/bench.sh` — run `wrk` against the server
- `./scripts/record.sh` — capture perf data for the built binary
- `./scripts/report.sh` — generate a readable perf report from recorded data

### Typical workflow

```bash
# build the project
cmake --build build --parallel 4

# benchmark throughput/latency
./scripts/bench.sh

# record perf data
./scripts/record.sh ./build/bin/server

# inspect the profile
./scripts/report.sh ./perf-data/perf.data
```

If a change affects latency, throughput, syscall behavior, or parsing cost, validate it with the relevant script and compare before/after results.

## Editing principles

- Preserve the hot path and keep it readable.
- Prefer small, targeted changes over broad restructuring.
- Validate with the project’s build/tests when changing core behavior.
- If optimizing for speed, measure with the scripts before and after.
- Keep Linux x64 assumptions explicit in comments and design notes.

## Validation

Before claiming a performance or correctness fix, run the relevant validation:

```bash
cmake --build build --parallel 4
ctest --test-dir build --output-on-failure
```

For perf-sensitive changes, also run the relevant benchmark or perf script and capture the delta.
