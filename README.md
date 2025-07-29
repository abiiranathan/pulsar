
# Pulsar Web Server Library

[![Build Status](https://github.com/abiiranathan/pulsar/actions/workflows/ci.yml/badge.svg)](https://github.com/abiiranathan/pulsar/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Pulsar is a high-performance web server library written in C, designed for building scalable web applications and APIs.

## Features

- Lightweight and fast HTTP/1.1 with Keep-Alive support.
- Routing system with path parameters
- Form data parsing
- Linux/macOS support.
- Both static and shared library builds
- Profile-Guided Optimization (PGO) support
- Extremely low memory and CPU usage.
- High throughput (approx > 400K req/sec) on 8 threads
  and about 200K-300K when serving files.
- Intuitive API for request/response life-cycle.
- Customizable through the compiler build options.

## Benchmarks
For a simple Hello World response, 90% of requests return within 2ms and 99% within 10ms.

```txt
wrk -t8 -c100 -d5s --latency http://localhost:8080/
Running 5s test @ http://localhost:8080/
  8 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   657.96us    2.34ms  59.24ms   95.95%
    Req/Sec    54.56k    14.89k  105.38k    73.58%
  Latency Distribution
     50%  144.00us
     75%  398.00us
     90%    1.35ms
     99%    8.82ms
  2199214 requests in 5.10s, 406.88MB read
Requests/sec: 431261.64
Transfer/sec:     79.79MB
```

## Installation

### Prerequisites

- CMake 3.20 or higher
- C compiler (GCC, Clang, or Apple Clang)
- Git
- Optional: Ninja for faster builds

### Building with CMake

```bash
# Clone the repository
git clone https://github.com/abiiranathan/pulsar.git
cd pulsar

# Create build directory
mkdir build && cd build

# Configure with CMake (default options)
cmake ..

# Build the project
cmake --build .

# Install (may need sudo)
cmake --install .
```

### Build Options

Configure with custom options:

```bash
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DBUILD_TESTS=ON ..
```

Available options:
- `-DCMAKE_BUILD_TYPE`: Debug, Release, or Profile (default: Release)
- `-DBUILD_SHARED_LIBS`: Build shared library (ON/OFF, default: ON)
- `-DBUILD_STATIC_LIBS`: Build static library (ON/OFF, default: ON)
- `-DBUILD_TESTS`: Build tests (ON/OFF, default: ON)
- `-DENABLE_PGO`: Enable Profile-Guided Optimization (ON/OFF, default: OFF)
- `-DCMAKE_INSTALL_PREFIX`: Custom install path

### Profile-Guided Optimization (PGO)

To build with PGO:

```bash
# First build with profile generation
cmake -DCMAKE_BUILD_TYPE=Profile -DENABLE_PGO=ON ..
cmake --build .

# Run the server to generate profile data
./bin/server

# Rebuild with profile data
cmake -DCMAKE_BUILD_TYPE=Release -DENABLE_PGO=ON ..
cmake --build .
```

## Testing

Tests are built by default when `BUILD_TESTS=ON`. To run tests:

```bash
# Build and run tests with CMake
cd build
ctest --output-on-failure
```

## Usage

Example: [Hello World Server](example/server.c)

```c
#include <pulsar/pulsar.h>

bool hello_handler(connection_t* conn) {
    conn_set_status(conn, StatusOK);
    conn_set_content_type(conn, "text/plain");
    conn_write_string(conn, "Hello World!");
    return true;
}

bool auth_middleware(connection_t* conn) {
    const char* token = req_header_get(conn, "Authorization");
    if (!token) {
        conn_abort(conn);
        conn_set_status(conn, StatusUnauthorized);
        return false;
    }
    return true;
}

int main() {
    route_t* hello_route = route_register("/hello", HTTP_GET, hello_handler);
    use_route_middleware(hello_route, 1, auth_middleware);
    route_static("/static/", "./public");
    return pulsar_run(NULL, 8080);
}
```

### Linking with your project

See Example [example/CMakeLists.txt](example/CMakeLists.txt)

CMake:
```cmake
find_package(Pulsar REQUIRED)
target_link_libraries(your_target PRIVATE Pulsar::pulsar_shared)
```

pkg-config:
```bash
gcc your_program.c -o your_program $(pkg-config --cflags --libs pulsar)
```

## Documentation
For detailed API documentation, see the [API Reference](docs/API.md).

## License

Pulsar is licensed under the MIT License. See [LICENSE](LICENSE) for details.


