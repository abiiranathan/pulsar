# tcp — high-performance Linux TCP primitives

`tcp` is a small, dependency-free (libc + pthreads only) C11 library for
building event-driven TCP clients and servers on Linux x86-64. It is the
transport layer extracted from [pulsar](../README.md): pulsar's HTTP engine
consumes exactly these primitives, and the same primitives can drive any other
protocol. It deliberately has **no** HTTP, TLS, or third-party dependencies.

The design priorities are the same as pulsar's: minimum syscalls, no
per-request heap traffic on the hot path, edge-triggered epoll, and direct
kernel interfaces over libc convenience wrappers.

## Highlights

- **Edge-triggered epoll loop** with O(1) intrusive connection lists and no
  per-event lookups.
- **Raw syscall layer** (`tcp_syscall.h`) that bypasses glibc pthread
  cancellation and TLS `errno` traffic on the hot path, with an automatic
  fallback under AddressSanitizer.
- **Zero-copy read path**: received bytes are handed to `on_data` as a view
  into a single reusable per-loop buffer; no allocation per read.
- **Buffered write path**: a write first tries a direct `write`/`writev`; only
  the unsent remainder is queued. A guarded, compacting growable buffer caps
  memory under backpressure.
- **Full-duplex**: reads stay armed while output is queued, so a slow peer
  cannot stall the inbound direction.
- **Async connect**, connect timeouts, cross-thread `stop`, and graceful
  half-close with pending-output flushing.

## Layout

```
tcp/
├── include/tcp/
│   ├── tcp.h            Umbrella header
│   ├── tcp_syscall.h    Raw Linux syscall wrappers
│   ├── tcp_events.h     Edge-triggered epoll queue
│   ├── tcp_socket.h     listen / accept / connect helpers
│   ├── tcp_buffer.h     Growable byte buffer
│   ├── tcp_connection.h Connection handle + callbacks + writes
│   └── tcp_client.h     Client event loop
├── src/                 Implementations
├── tests/               Unit + integration tests (ctest)
├── examples/            echo_client
└── CMakeLists.txt
```

## Building

### Standalone

```bash
cmake -S tcp -B tcp/build -DCMAKE_BUILD_TYPE=Release
cmake --build tcp/build --parallel
ctest --test-dir tcp/build --output-on-failure
```

This produces `libtcp.a` and `libtcp.so`, installs headers under `include/tcp`,
and exports the CMake package `Tcp` with the target `Tcp::tcp`. A pkg-config
file `tcp.pc` is installed as well.

### As part of pulsar

Pulsar adds this directory with `add_subdirectory(tcp)` and links `Tcp::tcp`;
no separate build step is required.

### With CMake `find_package`

```cmake
find_package(Tcp CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE Tcp::tcp)
```

## Quick start: a client

```c
#include <tcp/tcp.h>

static void on_data(tcp_conn_t* c, const void* data, size_t len) {
    /* data is only valid during this call: copy it if you keep it. */
    tcp_conn_write(c, data, len);   /* echo */
}

static void on_closed(tcp_conn_t* c, int err) {
    tcp_client_t* cli = tcp_conn_userdata(c);
    if (err) fprintf(stderr, "closed: %s\n", strerror(err));
    tcp_client_stop(cli);           /* end the loop */
}

int main(void) {
    static const tcp_conn_cbs_t cbs = {
        .on_data = on_data,
        .on_closed = on_closed,
    };

    tcp_client_t* cli = tcp_client_create(NULL);   /* default config */
    tcp_client_connect(cli, "127.0.0.1", 9000, cli, &cbs);
    tcp_client_run(cli);                            /* until idle/stopped */
    tcp_client_destroy(cli);
    return 0;
}
```

A complete example lives in [`examples/echo_client.c`](examples/echo_client.c).

## Quick start: a server

```c
#include <tcp/tcp.h>

tcp_listen_opts_t opts = tcp_listen_opts_default();
opts.reuse_port = 1;                 /* one listener per worker */
int lfd = tcp_listen("0.0.0.0", 9000, &opts);

for (;;) {
    int c = tcp_accept(lfd, NULL, 0);  /* non-blocking; EAGAIN when idle */
    if (c < 0) continue;               /* normally driven by an event loop */
    /* hand the fd to tcp_client_add() or read it directly */
}
```

`tcp_listen` returns a non-blocking, close-on-exec descriptor. `tcp_accept`
returns non-blocking, close-on-exec descriptors with `TCP_NODELAY` set.

## API summary

### `tcp_socket.h`

| Function | Purpose |
| --- | --- |
| `tcp_listen(host, port, opts)` | Create/bind/listen; returns fd or `-1`. |
| `tcp_accept(fd, peer, cap)` | Accept one connection (optional peer string). |
| `tcp_connect(host, port, opts)` | Blocking connect convenience. |
| `tcp_connect_start(host, port, opts)` | Begin non-blocking connect; returns fd. |
| `tcp_connect_check(fd)` | `0` connected, `1` in progress, `-1` failed. |
| `tcp_local_name` / `tcp_peer_name` / `tcp_local_port` | Address rendering. |
| `tcp_resolve`, `tcp_set_nonblock`, `tcp_set_cloexec` | Utilities. |

### `tcp_client.h` / `tcp_connection.h`

| Function | Purpose |
| --- | --- |
| `tcp_client_create(cfg)` | Create a loop (`NULL` = defaults). |
| `tcp_client_connect(cli, host, port, ud, cbs)` | Async connect. |
| `tcp_client_add(cli, fd, ud, cbs)` | Adopt a connected fd. |
| `tcp_client_run(cli)` | Run until stopped or idle. |
| `tcp_client_stop(cli)` | Thread-safe loop stop. |
| `tcp_conn_write` / `tcp_conn_writev` | Queue/attempt writes. |
| `tcp_conn_pending` | Bytes queued for send. |
| `tcp_conn_close` | Graceful half-close + teardown. |

## Semantics and invariants

### Callbacks

All callbacks run on the loop thread and must not block. Every callback is
optional.

- `on_connected` — the handshake completed (or an fd was adopted). Fires on the
  loop turn after `tcp_client_connect`/`tcp_client_add`.
- `on_data(c, data, len)` — a chunk of received bytes. `data` points into the
  loop's reusable read buffer and is valid **only** for the duration of the
  call.
- `on_writable` — a previously backpressured output queue fully drained.
- `on_closed(c, err)` — the connection ended; `err == 0` is an orderly peer
  close, otherwise a positive `errno` (e.g. `ECONNRESET`). The connection is
  freed immediately afterwards.

### Writing and backpressure

`tcp_conn_write` returns the number of bytes accepted (`len` on success) or
`-1`. When it returns `-1` with `errno == ENOBUFS`, the configured `write_max`
for that connection is full: stop producing and resume from `on_writable`.
A short direct write is handled internally — the remainder is queued and
flushed as the socket drains.

### Lifecycle

- A connection is owned by its loop and freed by it after `on_closed`. Do not
  `free()` it or use the pointer afterwards.
- `tcp_conn_close` is idempotent and safe from any callback. Queued output is
  flushed before the fd is closed.
- `tcp_client_destroy` tears down the loop and all connections without firing
  `on_closed`; do not call it from inside a callback of the same loop.

### Threading

The loop is single-threaded. `tcp_client_stop` is the only method safe to call
from another thread; it wakes the loop through an eventfd. Writes and all other
connection calls must happen on the loop thread.

### Errors

Functions returning an `int` fd return `-1` and set `errno` on failure.
`tcp_connect` never surfaces `EINPROGRESS`; `tcp_connect_start` may return a
socket whose connect is still in flight (resolve it with `tcp_connect_check` or
the client loop).

## Performance notes

- The read path performs one `read` into a pre-allocated per-loop buffer and
  reuses it across connections and iterations; no allocation, one syscall per
  arrival.
- The write fast path issues `write`/`writev` directly from the caller's
  buffer. Buffering only happens on a short write or `EAGAIN`.
- Event registration uses edge-triggered epoll, so idle connections cost
  nothing until state changes.
- `tcp_events.h`, `tcp_syscall.h` are header-only and fully inlinable, so the
  loop compiles the same whether it is used by a client or by pulsar.

## Testing

```bash
cmake -S tcp -B tcp/build -DCMAKE_BUILD_TYPE=Release
cmake --build tcp/build --parallel
ctest --test-dir tcp/build --output-on-failure
```

- `test_tcp_buffer` — growth, compaction, consume, `writev` append.
- `test_tcp_socket` — listen/accept/connect, async connect, peer rendering,
  refused connections.
- `test_tcp_client` — async connect, 64 KiB and 2 MiB echo round-trips,
  backpressure, adopted sockets, 8 concurrent connections, cross-thread stop.

## License

MIT, same as pulsar. See [`../LICENSE`](../LICENSE).
