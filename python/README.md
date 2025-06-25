
# Pulsar Python

[![PyPI version](https://img.shields.io/pypi/v/pulsar-python.svg)](https://pypi.org/project/pulsar-python/)
[![Python versions](https://img.shields.io/pypi/pyversions/pulsar-python.svg)](https://pypi.org/project/pulsar-python/)
[![License](https://img.shields.io/pypi/l/pulsar-python.svg)](https://opensource.org/licenses/MIT)

Python bindings for the Pulsar web server, providing a high-performance HTTP server interface with minimal overhead. It is currently linux only.

## Features

- High-performance HTTP server
- Simple and intuitive API
- Middleware support
- Route parameters
- Static file serving
- Built-in error handling
- Low-level access when needed

## Installation

```bash
pip install pulsar-python
```

## Quick Start

```python
from pulsar import Pulsar, HttpStatus, HttpMethod, Request, Response

app = Pulsar()

# Simple route
@app.GET("/")
def home(req: Request, res: Response):
    res.send("Hello, World!")

# Route with parameters
@app.GET("/greet/{name}")
def greet(req: Request, res: Response):
    name = req.get_path_param("name")
    res.send(f"Hello, {name}!")

# POST request handler
@app.POST("/echo")
def echo(req: Request, res: Response):
    res.send(req.body)

# Error handler
@app.errorhandler
def handle_errors(err: Exception, req: Request, res: Response):
    res.send(f"Error: {str(err)}", status=HttpStatus.INTERNAL_SERVER_ERROR)

# Serve static files
app.static("/static", "./public")

# Start server
app.run(port=8080)
```

## API Reference

### Pulsar Class

| Method                                       | Description                        |
| -------------------------------------------- | ---------------------------------- |
| `run(port: int = 8080)`                      | Start the server on specified port |
| `route(path: str, method: str, *middleware)` | Decorator to register routes       |
| `GET(path: str, *middleware)`                | Decorator for GET routes           |
| `POST(path: str, *middleware)`               | Decorator for POST routes          |
| `PUT(path: str, *middleware)`                | Decorator for PUT routes           |
| `DELETE(path: str, *middleware)`             | Decorator for DELETE routes        |
| `PATCH(path: str, *middleware)`              | Decorator for PATCH routes         |
| `OPTIONS(path: str, *middleware)`            | Decorator for OPTIONS routes       |
| `HEAD(path: str, *middleware)`               | Decorator for HEAD routes          |
| `static(url_prefix: str, directory: str)`    | Register static file route         |
| `use(*middleware)`                           | Register global middleware         |
| `errorhandler(func)`                         | Decorator for error handling       |

### Request Object

| Property/Method              | Description                    |
| ---------------------------- | ------------------------------ |
| `method`                     | HTTP method (GET, POST, etc.)  |
| `path`                       | Request path                   |
| `body`                       | Request body as bytes          |
| `content_length`             | Content length of request body |
| `get_query_param(name: str)` | Get query parameter by name    |
| `get_path_param(name: str)`  | Get path parameter by name     |
| `get_header(name: str)`      | Get request header by name     |
| `query_params`               | All query parameters (dict)    |
| `headers`                    | All request headers (dict)     |

### Response Object

| Method                                                 | Description               |
| ------------------------------------------------------ | ------------------------- |
| `set_status(status: HttpStatus)`                       | Set HTTP status code      |
| `set_content_type(content_type: str)`                  | Set Content-Type header   |
| `set_header(name: str, value: str)`                    | Set response header       |
| `write(data: Union[bytes, str])`                       | Write response data       |
| `send(content: Union[str, bytes], status: HttpStatus)` | Send response with status |
| `send_json(data: Any, status: HttpStatus)`             | Send JSON response        |
| `send_file(filename: str, content_type: str)`          | Serve file response       |
| `not_found()`                                          | Send 404 response         |
| `abort()`                                              | Abort the request         |

### Enums

```python
class HttpMethod(enum.IntEnum):
    GET = 0
    POST = 1
    PUT = 2
    PATCH = 3
    DELETE = 4
    HEAD = 5
    OPTIONS = 6

class HttpStatus(enum.IntEnum):
    # All standard HTTP status codes
    OK = 200
    CREATED = 201
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    NOT_FOUND = 404
    INTERNAL_SERVER_ERROR = 500
    # ... and many more
```

## Advanced Usage

### Middleware

```python
def logger(req: Request, res: Response):
    print(f"{req.method} {req.path}")

def auth_middleware(req: Request, res: Response):
    if not req.get_header("Authorization"):
        res.send("Unauthorized", status=HttpStatus.UNAUTHORIZED)
        res.abort()

# Global middleware
app.use(logger)

# Route-specific middleware
@app.GET("/protected", auth_middleware)
def protected_route(req: Request, res: Response):
    res.send("Secret content")
```

### Error Handling

```python
@app.errorhandler
def handle_errors(err: Exception, req: Request, res: Response):
    if isinstance(err, ValueError):
        res.send("Bad request", status=HttpStatus.BAD_REQUEST)
    else:
        res.send("Server error", status=HttpStatus.INTERNAL_SERVER_ERROR)
```

### JSON API

```python
@app.GET("/api/data")
def get_data(req: Request, res: Response):
    data = {"message": "Hello", "status": "success"}
    res.send_json(data)

@app.POST("/api/data")
def post_data(req: Request, res: Response):
    try:
        payload = json.loads(req.body.decode())
        # Process data...
        res.send_json({"status": "success"})
    except json.JSONDecodeError as e:
        res.send_json({"error": "Invalid JSON"}, status=HttpStatus.BAD_REQUEST)
```

## Platform Support

- [x] Linux (`libpulsar.so`)
- [] macOS (`libpulsar.dylib`)

## Requirements

- Python 3.8+
- Pre-built Pulsar library (included in package)

## Performance Tips

1. Use `send_file()` for static assets (uses zero-copy file serving)
2. Minimize middleware for critical paths
3. Use `bytes` instead of `str` for binary responses
4. Reuse objects where possible

## License

MIT License. See `LICENSE` file for 
