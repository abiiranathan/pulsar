"""
Pulsar Web Server.

This is a python wrapper around the C pulsar API.
"""
import sys
import ctypes
import enum
from typing import Any, Callable, Optional, TypeVar, Union, List, Dict
from pathlib import Path
from functools import wraps
import json

# Get package directory
PACKAGE_DIR = Path(__file__).parent.resolve()

def _load_library():
    lib_dir = Path(__file__).parent / "lib"
    
    # Platform-specific filenames
    libnames = {
        'linux': 'libpulsar.so',
        'darwin': 'libpulsar.dylib',
        'win32': 'pulsar.dll'
    }
    
    libname = libnames.get(sys.platform)
    if not libname:
        raise OSError(f"Unsupported platform: {sys.platform}")
    
    libpath = lib_dir / libname
    if not libpath.exists():
        raise FileNotFoundError(f"Library not found at {libpath}")
    
    return ctypes.CDLL(str(libpath))

lib = _load_library()

# Type definitions
class HttpMethod(enum.IntEnum):
    INVALID = -1
    GET = 0
    POST = 1
    PUT = 2
    PATCH = 3
    DELETE = 4
    HEAD = 5
    OPTIONS = 6

class HttpStatus(enum.IntEnum):
    # Informational
    CONTINUE = 100
    SWITCHING_PROTOCOLS = 101
    PROCESSING = 102
    EARLY_HINTS = 103

    # Success
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NON_AUTHORITATIVE_INFORMATION = 203
    NO_CONTENT = 204
    RESET_CONTENT = 205
    PARTIAL_CONTENT = 206
    MULTI_STATUS = 207
    ALREADY_REPORTED = 208
    IM_USED = 226

    # Redirection
    MULTIPLE_CHOICES = 300
    MOVED_PERMANENTLY = 301
    FOUND = 302
    SEE_OTHER = 303
    NOT_MODIFIED = 304
    USE_PROXY = 305
    TEMPORARY_REDIRECT = 307
    PERMANENT_REDIRECT = 308

    # Client Errors
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    PAYMENT_REQUIRED = 402
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    NOT_ACCEPTABLE = 406
    PROXY_AUTHENTICATION_REQUIRED = 407
    REQUEST_TIMEOUT = 408
    CONFLICT = 409
    GONE = 410
    LENGTH_REQUIRED = 411
    PRECONDITION_FAILED = 412
    PAYLOAD_TOO_LARGE = 413
    URI_TOO_LONG = 414
    UNSUPPORTED_MEDIA_TYPE = 415
    RANGE_NOT_SATISFIABLE = 416
    EXPECTATION_FAILED = 417
    IM_A_TEAPOT = 418
    MISDIRECTED_REQUEST = 421
    UNPROCESSABLE_ENTITY = 422
    LOCKED = 423
    FAILED_DEPENDENCY = 424
    TOO_EARLY = 425
    UPGRADE_REQUIRED = 426
    PRECONDITION_REQUIRED = 428
    TOO_MANY_REQUESTS = 429
    REQUEST_HEADER_FIELDS_TOO_LARGE = 431
    UNAVAILABLE_FOR_LEGAL_REASONS = 451

    # Server Errors
    INTERNAL_SERVER_ERROR = 500
    NOT_IMPLEMENTED = 501
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503
    GATEWAY_TIMEOUT = 504
    HTTP_VERSION_NOT_SUPPORTED = 505
    VARIANT_ALSO_NEGOTIATES = 506
    INSUFFICIENT_STORAGE = 507
    LOOP_DETECTED = 508
    NOT_EXTENDED = 510
    NETWORK_AUTHENTICATION_REQUIRED = 511


# ctypes setup
lib.pulsar_run.argtypes = [ctypes.c_int]
lib.pulsar_run.restype = ctypes.c_int

# Connection and request/response objects are opaque pointers
Connection = ctypes.c_void_p
Route = ctypes.c_void_p

# Handler type (returns None, takes Connection)
HandlerFunc = ctypes.CFUNCTYPE(None, Connection)

# Middleware type (same as handler)
MiddlewareFunc = ctypes.CFUNCTYPE(None, Connection)

def _setup_function(name: str, argtypes: List[Any], restype: Any) -> None: # type: ignore
    """Helper to setup ctypes function signatures"""
    func = getattr(lib, name)
    func.argtypes = argtypes
    func.restype = restype

# Setup all function signatures
_setup_function("route_register", 
    [ctypes.c_char_p, ctypes.c_int, HandlerFunc], Route)
_setup_function("register_static_route", 
    [ctypes.c_char_p, ctypes.c_char_p], Route)
_setup_function("use_global_middleware", 
    [ctypes.POINTER(MiddlewareFunc), ctypes.c_int, ], None)
_setup_function("use_route_middleware", 
    [Route, ctypes.POINTER(MiddlewareFunc), ctypes.c_int], None)

# Response functions
_setup_function("conn_servefile", [Connection, ctypes.c_char_p], ctypes.c_bool)
_setup_function("conn_write_string", [Connection, ctypes.c_char_p], ctypes.c_int)
_setup_function("conn_write", [Connection, ctypes.c_void_p, ctypes.c_size_t], ctypes.c_int)
_setup_function("conn_send", [Connection, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t], None)
_setup_function("conn_writef", [Connection, ctypes.c_char_p], ctypes.c_int)
_setup_function("conn_abort", [Connection], None)
_setup_function("conn_notfound", [Connection], ctypes.c_int)

# Request functions
_setup_function("req_method", [Connection], ctypes.c_char_p)
_setup_function("req_path", [Connection], ctypes.c_char_p)
_setup_function("req_body", [Connection], ctypes.c_char_p)
_setup_function("req_content_len", [Connection], ctypes.c_size_t)

# Parameter functions
_setup_function("query_get", [Connection, ctypes.c_char_p], ctypes.c_char_p)
_setup_function("get_path_param", [Connection, ctypes.c_char_p], ctypes.c_char_p)

# Header functions
_setup_function("req_header_get", [Connection, ctypes.c_char_p], ctypes.c_char_p)
_setup_function("res_header_get", [Connection, ctypes.c_char_p], ctypes.c_char_p)

# Status/header setters
_setup_function("conn_set_status", [Connection, ctypes.c_int], None)
_setup_function("conn_set_content_type", [Connection, ctypes.c_char_p], None)
_setup_function("conn_writeheader", [Connection, ctypes.c_char_p, ctypes.c_char_p], None)

# User data functions
_setup_function("set_userdata", 
    [Connection, ctypes.c_void_p, ctypes.CFUNCTYPE(None, ctypes.c_void_p)], None)
_setup_function("get_userdata", [Connection], ctypes.c_void_p)

# Method conversion
_setup_function("http_method_from_string", [ctypes.c_char_p], ctypes.c_int)
_setup_function("http_method_to_string", [ctypes.c_int], ctypes.c_char_p)
_setup_function("http_method_valid", [ctypes.c_int], ctypes.c_bool)
_setup_function("is_safe_method", [ctypes.c_int], ctypes.c_bool)

class Request:
    """Wrapper for request-related operations"""
    def __init__(self, conn: Connection):
        self._conn = conn
    
    @property
    def method(self) -> str:
        """Get request method"""
        return lib.req_method(self._conn).decode()
    
    @property
    def path(self) -> str:
        """Get request path"""
        return lib.req_path(self._conn).decode()
    
    @property
    def body(self) -> bytes:
        """Get request body"""
        body = lib.req_body(self._conn)
        return ctypes.string_at(body) if body else b''
    
    @property
    def content_length(self) -> int:
        """Get content length"""
        return lib.req_content_len(self._conn)
    
    def get_query_param(self, name: str) -> Optional[str]:
        """Get query parameter by name"""
        param = lib.query_get(self._conn, name.encode())
        return param.decode() if param else None
    
    def get_path_param(self, name: str) -> Optional[str]:
        """Get path parameter by name"""
        param = lib.get_path_param(self._conn, name.encode())
        return param.decode() if param else None
    
    def get_header(self, name: str) -> Optional[str]:
        """Get request header by name"""
        header = lib.req_header_get(self._conn, name.encode())
        return header.decode() if header else None
    
    @property
    def query_params(self) -> Dict[str, str]:
        """Get all query parameters as a dictionary"""
        # This would need to parse the query string
        # Implementation depends on how query params are stored in Pulsar
        return {}
    
    @property
    def headers(self) -> Dict[str, str]:
        """Get all headers as a dictionary"""
        # Implementation depends on how headers are stored in Pulsar
        return {}

class Response:
    """Wrapper for response-related operations"""
    def __init__(self, conn: Connection):
        self._conn = conn
    
    def set_status(self, status: HttpStatus) -> None:
        """Set response status code"""
        lib.conn_set_status(self._conn, status)

    def abort(self):
        lib.conn_abort(self._conn)
    
    def set_content_type(self, content_type: str) -> bool:
        """Set response content type"""
        return lib.conn_set_content_type(self._conn, content_type.encode())
    
    def set_header(self, name: str, value: str) -> bool:
        """Set response header"""
        return lib.conn_writeheader(self._conn, name.encode(), value.encode())
    
    def write(self, data: Union[bytes, str]) -> int:
        """Write response data"""
        if isinstance(data, str):
            return lib.conn_write_string(self._conn, data.encode())
        
        return lib.conn_write(self._conn, data, len(data))
    
    def send(self, content: Union[str, bytes],
             status: HttpStatus = HttpStatus.OK):
        """Write a response with status code and content-type"""
        if isinstance(content, str):
            lib.conn_send(self._conn, status, content.encode(), len(content))
        else:
            lib.conn_send(self._conn, status, content, len(content))
    
    def send_json(self, data: Any, status: HttpStatus = HttpStatus.OK) -> int:
        """Send JSON response"""
        self.set_status(status)
        self.set_content_type("application/json")
        return self.write(json.dumps(data))
    
    def send_file(self, filename: str, content_type: str | None = None) -> bool:
        """Serve a file"""
        if content_type:
            self.set_content_type(content_type)

        return lib.conn_servefile(self._conn, filename.encode())
    
    def not_found(self) -> int:
        """Serve 404 response"""
        return lib.conn_notfound(self._conn)
    

# Type variables for request/response
Req = TypeVar('Req', bound=Request)
Res = TypeVar('Res', bound=Response)
Conn = TypeVar('Conn', bound=ctypes.c_void_p)

# Middleware type: takes request and response, returns bool
Middleware = Callable[[Request, Response], None]

# Handler type: takes request and response, returns Union[str, bytes]
Handler = Callable[[Request, Response], None]

# Error handler type
ErrorHandler = Callable[[Exception, Request, Response], None]

# Global dictionary to maintain callback references
_CALLBACK_STORE : Dict[int, Union[Middleware, Handler]]= {}

def _create_handler_wrapper(c_handler: HandlerFunc):  # type: ignore
    """Wrapper that keeps Python handler alive and handles exceptions"""
    @HandlerFunc
    def wrapped_handler(conn: Connection):
        try:
            c_handler(conn) 
        except Exception as e:
            print(f"Handler error: {e} ", file=sys.stderr)
            return

    # Prevent GC
    _CALLBACK_STORE[id(c_handler)] = wrapped_handler # type: ignore
    return wrapped_handler

def _create_middleware_wrapper(py_middleware: Middleware):
    @MiddlewareFunc
    def wrapped_middleware(conn: Connection):
        req = Request(conn)
        res = Response(conn)
        py_middleware(req, res) 

    # Prevent GC
    _CALLBACK_STORE[id(py_middleware)] = wrapped_middleware
    return wrapped_middleware

class Pulsar:
    """Pulsar web server application class."""
    
    def __init__(self):
        self._error_handler: Optional[ErrorHandler] = None

    def run(self, port: int = 8080, host: str = "0.0.0.0") -> int:
        """Start the server on specified port"""
        return lib.pulsar_run(port)
    
    def route(self, path: str, method: str, *middleware: Middleware):
        """Decorator for registering routes"""
        def decorator(handler: Handler):
            @wraps(handler)
            def wrapped_handler(conn: ctypes.c_void_p):
                req = Request(conn)
                res = Response(conn)
                handler(req, res)
                
            # Register the route for method
            method_enum = lib.http_method_from_string(method.upper().encode())
            if method_enum == HttpMethod.INVALID:
                raise ValueError(f"Invalid HTTP method: {method}")
            
            route = lib.route_register(
                path.encode(),
                method_enum,
                _create_handler_wrapper(wrapped_handler)
            )
        
            if not route:
                raise RuntimeError(f"Failed to register route {method} {path}")
            
            # Register route-specific middleware if provided
            if middleware:
                # Create array of middleware function pointers
                mw_array = (MiddlewareFunc * len(middleware))()
                for i, mw in enumerate(middleware):
                    wrapped_mw = _create_middleware_wrapper(mw)
                    mw_array[i] = wrapped_mw
                
                # Pass the array and its length
                lib.use_route_middleware(
                    route,
                    mw_array,
                    len(middleware),
                )

            return wrapped_handler
        return decorator
    
    def use(self, *middleware: Middleware):
        if middleware:
            # Create array of middleware function pointers
            mw_array = (MiddlewareFunc * len(middleware))()
            for i, mw in enumerate(middleware):
                wrapped_mw = _create_middleware_wrapper(mw)
                mw_array[i] = wrapped_mw
            lib.use_global_middleware(mw_array, len(middleware))
       
    def GET(self, path: str, *middleware: Middleware):
        """Decorator for GET routes"""
        return self.route(path, "GET", *middleware)
    
    def POST(self, path: str, *middleware: Middleware):
        """Decorator for POST routes"""
        return self.route(path, "POST", *middleware)
    
    def PUT(self, path: str, *middleware: Middleware):
        """Decorator for PUT routes"""
        return self.route(path, "PUT", *middleware)
    
    def DELETE(self, path: str, *middleware: Middleware):
        """Decorator for DELETE routes"""
        return self.route(path, "DELETE", *middleware)
    
    def PATCH(self, path: str, *middleware: Middleware):
        """Decorator for PATCH routes"""
        return self.route(path, "PATCH", *middleware)
    
    def OPTIONS(self, path: str, *middleware: Middleware):
        """Decorator for OPTIONS routes"""
        return self.route(path, "OPTIONS", *middleware)
    
    def HEAD(self, path: str, *middleware: Middleware):
        """Decorator for HEAD routes"""
        return self.route(path, "HEAD", *middleware)
    

    def errorhandler(self, func: ErrorHandler):
        """Decorator for error handling"""
        self._error_handler = func
        return func
    
    def static(self, url_prefix: str, directory: str):
        """Register static file route. Files served efficiently with sendfile syscall."""
        route = lib.register_static_route(url_prefix.encode(),directory.encode())
        if not route:
            raise RuntimeError("Failed to register static route")
        return route

