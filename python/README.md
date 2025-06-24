# Pulsar Python Bindings

## Overview
Python bindings for the Pulsar web server using ctypes, providing a high-performance HTTP server interface.

## Installation
```bash
pip install pulsar-python
```

## Quick Start
```python
from pulsar import Pulsar, HttpMethod, HttpStatus

def hello_handler(conn):
    Pulsar.set_status(conn, HttpStatus.OK)
    Pulsar.set_content_type(conn, "text/plain")
    Pulsar.write_string(conn, "Hello World!")
    return True

# Register route
Pulsar.route("/hello", HttpMethod.GET, hello_handler)

# Start server
Pulsar.run(8080)
```

## API Reference

### Core Functions
| Function                                                                     | Description                        |
| ---------------------------------------------------------------------------- | ---------------------------------- |
| `Pulsar.run(port: int) -> int`                                               | Start the server on specified port |
| `Pulsar.route(pattern: str, method: HttpMethod, handler: Callable) -> Route` | Register a new route               |
| `Pulsar.static_route(pattern: str, directory: str) -> Route`                 | Register static file route         |

### Request Handling
| Method                            | Description        |
| --------------------------------- | ------------------ |
| `get_method(conn) -> str`         | Get HTTP method    |
| `get_path(conn) -> str`           | Get request path   |
| `get_body(conn) -> bytes`         | Get request body   |
| `get_content_length(conn) -> int` | Get content length |

### Response Handling
| Method                                              | Description             |
| --------------------------------------------------- | ----------------------- |
| `set_status(conn, status: HttpStatus)`              | Set HTTP status code    |
| `set_content_type(conn, content_type: str) -> bool` | Set Content-Type header |
| `write(conn, data: bytes) -> int`                   | Write raw response      |
| `write_string(conn, text: str) -> int`              | Write text response     |
| `serve_file(conn, filename: str) -> bool`           | Serve file response     |

### Middleware
| Method                                     | Description                |
| ------------------------------------------ | -------------------------- |
| `use_global_middleware(*middleware)`       | Register global middleware |
| `use_route_middleware(route, *middleware)` | Register route middleware  |

### Enums
```python
class HttpMethod(IntEnum):
    GET = 1
    POST = 2
    PUT = 3
    # ... other methods ...

class HttpStatus(IntEnum):
    OK = 200
    NOT_FOUND = 404
    # ... all status codes ...
```

## Advanced Usage

### User Data
```python
def free_func(data):
    print(f"Cleaning up: {data}")

def handler(conn):
    data = {"key": "value"}
    Pulsar.set_user_data(conn, data, free_func)
    # ...
```

### Middleware Chain
```python
def auth_middleware(conn):
    if not Pulsar.get_req_header(conn, "Authorization"):
        Pulsar.set_status(conn, HttpStatus.UNAUTHORIZED)
        return False
    return True

Pulsar.use_global_middleware(auth_middleware)
```

## Platform Support
- Linux (`libpulsar.so`)
- macOS (`libpulsar.dylib`)

## Requirements
- Python 3.6+
- Pre-built Pulsar library in `pulsar/lib/`

## Error Handling
All functions raise Python exceptions for errors:
- `ValueError` for invalid arguments
- `RuntimeError` for server errors
- `OSError` for platform issues

## Performance Notes
- Uses native ctypes for minimal overhead
- Zero-copy file serving with `serve_file()`
- Memory-efficient request/response handling