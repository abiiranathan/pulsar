```c
int pulsar_run(const char *addr, int port);
```
Starts the server on the specified address (or IP address) and port. 
Runs until SIGINT/SIGTERM is received and then graceful shutdown is performed.

If *addr* is NULL, it will accept a connection on all available interfaces.
Equivalent to using 0.0.0.0.

### Routing

```c
route_t* route_register(const char* pattern, HttpMethod method, HttpHandler handler);
```
Registers a route with a URL pattern, HTTP method, and handler function.
Must return a valid route or panic if there is no memory for more routes.
You can modify [constans.h](../include/constants.h) and rebuild or pass compiler flags
to modify the number of routes through cmake.

## Static routes
Registers a static file serving route for a directory.
The directory must exist.
Traversal outside the server directory is not allowed.
```c
route_t* route_static(const char* pattern, const char* dir);
```

### Request Handling
Access request method, path, body and content length.

```c
const char* req_method(connection_t* conn);
const char* req_path(connection_t* conn); 
const char* req_body(connection_t* conn);
size_t req_content_len(connection_t* conn);
```

### Query Parameters
Access query parameters by name or get all parameters.

```c 
const char* query_get(connection_t* conn, const char* name);

headers_t* params= query_params(conn);
if (params) {
    // Check for query params.
    header_entry* entry = NULL;
    headers_foreach(params, entry) {
        printf("%s = %s\n", entry->name, entry->value);
    }
}
```

### Path Parameters
Get path parameter value by name (for routes like `/users/{id}`).
```c
const char* get_path_param(connection_t* conn, const char* name);
```

### Response Writing
Functions to set status code, headers, and write response data.

```c
void conn_set_status(connection_t* conn, http_status code);
bool conn_writeheader(connection_t* conn, const char* name, const char* value);
int conn_write(connection_t* conn, const void* data, size_t len);
int conn_write_string(connection_t* conn, const char* str);
int conn_writef(connection_t* conn, const char* fmt, ...);
bool conn_servefile(connection_t* conn, const char* filename);
```

### Middleware
Register global or route-specific middleware functions.

```c
void use_global_middleware(HttpHandler *middleware, size_t count);
void use_route_middleware(route_t* route, HttpHandler *middleware, size_t count);
```

## Post-request callback

```c
/** @brief Set a post_handler callback that is called after the handler runs
 * before writing data to the socket.
 */
void pulsar_set_callback(PulsarCallback cb);
```

## Set request context variables.
Store and retrieve per-request user data.

 - Set a user-owned value pointer to the context with a callback function to free the value. The function may be NULL if the value is not supposed to be freed.
Returns true on success.
```c
bool pulsar_set_context_value(connection_t* conn, const char* key, void* value, ValueFreeFunc free_func);
```

- Get a context value.
```c

void* pulsar_get_context_value(connection_t* conn, const char* key);
```

- Delete a context value.
```c
void pulsar_delete_context_value(connection_t* conn, const char* key);
```

## Example Usage

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
        conn_set_status(conn, StatusUnauthorized);
        return false;
    }
    return true;
}

int main() {
    // Register routes
    route_t* hello_route = route_register("/hello", HTTP_GET, hello_handler);
    use_route_middleware(hello_route, 1, auth_middleware);
    
    // Serve static files
    register_static_route("/static/", "./public");
    
    // Start server
    return pulsar_run(NULL, 8080);
}
```

## Working with forms
Pulsar server includes APIs for processing multipart/form-data.

Typical public API and usage:

```c
#include <pulsar/pulsar.h>
#include <pulsar/forms.h>

// Maximum memory to be allocated for form processing.
#define MEMORY 4096

void handle_post_form(connection_t *conn){
    // Initialize the form.
    char boundary[256];
    MultipartForm form={0};

    // You must allocate enough memory upfront, enough to process all the form
    // fields and files. (Memory does not include file contents)
    MultipartCode code = multipart_init(&form, MEMORY);

    // Handle error.
    if(code != MULTIPART_OK){
        conn_set_status(conn, StatusBadRequest);

        // Use multipart_error to extract error message from MultipartCode.
        conn_write_string(conn, multipart_error(code));
        multipart_cleanup(&form);
        return;
    }


    // Extract the form boundary from the request body.
    const char* content_type = req_header_get(conn, "Content-Type");
    bool parse_result = parse_boundary(content_type, boundary, sizeof(boundary));
    assert(parse_result && "Failed to parse form boundary from header");

    // Parse the form.
    const char* body      = req_body(conn);
    size_t content_length = req_content_len(conn);

    code = multipart_parse(body, content_length, boundary, &form);
    assert(code == MULTIPART_OK && "Form parsing failed");

    // Accessing form values.
    const char* username = multipart_field_value(&form, "username") ;

    // Access single file by field name.
    FileHeader* file = multipart_file(&form, "file");
    if (file) {
        if (multipart_save_file(file, body, "destination_path_here")) {
            conn_write_string(conn, "File uploaded successfully\n");
            multipart_cleanup(&form);
            return;
        }
    }else{
        // handle file not uploaded.
    }

    // Get multiple files sharing the same label (in multi-upload)
    size_t out_indices[4];
    size_t num_files;
    num_files = multipart_files(&form, "files[]", out_indices, 4);
    assert(num_files > 0);

    for (size_t i = 0; i < num_files; i++) {
        // Metadata about the file relative to the body(ie file size and offsets)
        FileHeader* file_header = form.files[i];

        // Efficient write using offsets in the req body to avoid duplicate allocation.
        if (!multipart_save_file(file_header, body, "destination_path")) {
            // handle error saving file.
        }
    }

    // Clean up the memory used by the form.
    multipart_cleanup(&form);
}

```
