#include "include/content_types.h"
#include "include/forms.h"
#include "include/pulsar.h"

#define SENDFILE 0

void hello_world_handler(connection_t* conn) {
    conn_set_status(conn, StatusOK);

    // Set-Cookie is a special header that can be set multiple times.
    conn_writeheader(conn, "Set-Cookie", "sessionId=12345; Path=/; HttpOnly");
    conn_writeheader(conn, "Set-Cookie", "theme=dark; Path=/; Secure");

#if SENDFILE
    conn_servefile(conn, __FILE__);
#else
    conn_set_content_type(conn, "text/plain");
    const char* response = "Hello, World! This is Pulsar HTTP server.\n";
    conn_write(conn, response, strlen(response));

    // // Write a value larger than STACK_BUFFER_SIZE to test migration to heap and reallocation
    // // Generate a large string to test heap migration
    // const size_t large_size = (STACK_BUFFER_SIZE * 4) + 1;  // Ensure it exceeds stack buffer
    // char* large_data        = malloc(large_size);
    // if (large_data) {
    //     // Fill with some test pattern
    //     memset(large_data, 'A', large_size - 1);
    //     large_data[large_size - 1] = '\0';

    //     conn_write(conn, "\n--- Large data test ---\n", 25);
    //     conn_write(conn, large_data, large_size - 1);  // Don't include null terminator
    //     conn_write(conn, large_data, large_size - 1);  // Don't include null terminator
    //     conn_write(conn, "\n--- End test ---\n", 18);

    //     free(large_data);
    // } else {
    //     const char* error_msg = "\nFailed to allocate test data\n";
    //     conn_write(conn, error_msg, strlen(error_msg));
    // }
#endif
}

void json_handler(connection_t* conn) {
    conn_set_status(conn, StatusOK);
    conn_set_content_type(conn, "application/json");

    const char* json = "{\"message\": \"Hello from JSON API\", \"status\": \"success\"}";
    conn_write(conn, json, strlen(json));
}

void echo_handler(connection_t* conn) {
    conn_set_status(conn, StatusOK);
    conn_set_content_type(conn, "text/plain");

    const char* method    = req_method(conn);
    const char* path      = req_path(conn);
    const char* body      = req_body(conn);
    size_t content_length = req_content_len(conn);

    // Echo request method and path
    conn_write(conn, "Method: ", 8);
    conn_write(conn, method, strlen(method));
    conn_write(conn, "\nPath: ", 7);
    conn_write(conn, path, strlen(path));

    // Echo body if present
    if (body && content_length > 0) {
        conn_write(conn, "\nBody: ", 7);
        conn_write(conn, body, content_length);
    }
}

void pathparams_query_params_handler(connection_t* conn) {
    const char* userId   = get_path_param(conn, "user_id");
    const char* username = get_path_param(conn, "username");
    ASSERT(userId && username);

    // Should exist, otherwise our router is broken
    printf("Path Params: \n");
    printf("User ID: %s and username: %s\n", userId, username);

    headers_t* params = query_params(conn);
    if (params) {
        // Check for query params.
        printf("Query Params: \n");
        header_entry* entry = NULL;
        headers_foreach(params, entry) {
            printf("%s = %s\n", entry->name, entry->value);
        }
    }
    conn_writef(conn, "Your user_id is %s and username %s\n", userId, username);
}

void handle_form(connection_t* conn) {
    MultipartForm form = {};
    char boundary[128];
    MpCode code;

    code = multipart_init(&form, 1 << 20);
    if (code != MP_OK) {
        conn_set_status(conn, StatusBadRequest);
        conn_write_string(conn, multipart_error(code));
        return;
    }

    const char* content_type = req_header_get(conn, "Content-Type");
    if (!content_type) {
        conn_set_status(conn, StatusBadRequest);
        conn_write_string(conn, "Invalid content type header");
        multipart_cleanup(&form);
        return;
    }

    if (!parse_boundary(content_type, boundary, sizeof(boundary))) {
        conn_set_status(conn, StatusBadRequest);
        conn_write_string(conn, "Invalid content type header");
        multipart_cleanup(&form);
        return;
    }

    const char* body      = req_body(conn);
    size_t content_length = req_content_len(conn);

    code = multipart_parse(body, content_length, boundary, &form);
    if (code != MP_OK) {
        conn_set_status(conn, StatusBadRequest);
        conn_write_string(conn, multipart_error(code));
        multipart_cleanup(&form);
        return;
    }

    FileHeader* file = multipart_file(&form, "file");
    if (file) {
        char dest[1024] = {0};
        strlcat(dest, "./test_output/", sizeof(dest));
        strlcat(dest, file->filename, sizeof(dest) - 15);  // ignore potential truncation
        if (multipart_save_file(file, body, dest)) {
            conn_write_string(conn, "File uploaded successfully\n");
        }
    }

    multipart_cleanup(&form);
}

void serve_movie(connection_t* conn) {
    const char* html =
        "<html><body style='max-width: 1000px; margin: 20px;'><video src='/static/FlightRisk.mp4' "
        "controls width='720' height='480'></video></body></html>";

    conn_set_status(conn, StatusOK);
    conn_set_content_type(conn, CONTENT_TYPE_HTML);
    conn_write_string(conn, html);
}

// Example syncronous logger.
// Note this is not ideal in production as it can seriously impair server performance.
#include <string.h>
#include <time.h>
#include <unistd.h>

// Thread-local buffer to avoid contention
#define LOG_BUFFER_SIZE 1024
#define LOGGING_ON      0

static __thread char log_buffer[LOG_BUFFER_SIZE];

void pulsar_callback(connection_t* conn, uint64_t total_ns) {
    if (!LOGGING_ON) {
        return;
    }

    const char* method = req_method(conn);
    const char* path   = req_path(conn);
    char* ua           = (char*)req_header_get(conn, "User-Agent");
    if (!ua) {
        ua = "-";
    }

    http_status status_code = res_get_status(conn);

    // Format latency with appropriate unit
    char latency_str[32];
    if (total_ns < 1000) {
        // nano seconds
        snprintf(latency_str, sizeof(latency_str), "%3luns", total_ns);
    } else if (total_ns < 1000000) {
        // Microseconds
        snprintf(latency_str, sizeof(latency_str), "%5luµs", total_ns / 1000);
    } else if (total_ns < 1000000000) {
        // Milliseconds
        snprintf(latency_str, sizeof(latency_str), "%5lums", total_ns / 1000000);
    } else if (total_ns < 60000000000) {
        // Seconds
        snprintf(latency_str, sizeof(latency_str), "%5lus", total_ns / 1000000000);
    } else {
        // Minutes
        snprintf(latency_str, sizeof(latency_str), "%5lum", total_ns / 60000000000);
    }

    // Build the log line in our buffer
    char* ptr       = log_buffer;
    const char* end = log_buffer + LOG_BUFFER_SIZE - 1;  // Leave room for null terminator

    // [Pulsar]
    ptr += snprintf(ptr, end - ptr, "[Pulsar] ");

    // Method (2 chars, left-aligned)
    ptr += snprintf(ptr, end - ptr, "%-2s ", method);

    // Path (3 chars, left-aligned)
    ptr += snprintf(ptr, end - ptr, "%-3s ", path);

    // Status code (3 digits)
    ptr += snprintf(ptr, end - ptr, "%3d ", status_code);

    // Latency (8 chars)
    ptr += snprintf(ptr, end - ptr, "%8s ", latency_str);

    // User-Agent
    ptr += snprintf(ptr, end - ptr, "%s\n", ua);

    // Single write to stdout
    write(STDOUT_FILENO, log_buffer, ptr - log_buffer);
}

// The callback function to free context values.
static void value_free_func(const char* key, void* value, void* user_data) {
    UNUSED(user_data);

    if (strcmp(key, "PULSAR") == 0) {
        free(value);
    }
}

// Setting request context.
// We create a Locals map creation factory function and set it.
Locals* locals_create_factory(void) {
    Locals* locals = LocalsNew(value_free_func, NULL);
    ASSERT(locals);
    return locals;
}

void mw1(connection_t* conn) {
    char* value = strdup("PULSAR");  // value dynamically allocated.
    if (value) {
        pulsar_set_context_value(conn, "name", value);
        // printf("Set value in context as: %s\n", value);
    }
}

void mw2(connection_t* conn) {
    // value retrieved from context.
    char* value = pulsar_get_context_value(conn, "name");
    assert(value);
    // printf("Hello: %s\n", value);
}

int main() {
    // set local context map creation callback.
    pulsar_set_locals_callback(locals_create_factory);

    // Set post-request callback handler.
    pulsar_set_callback(pulsar_callback);

    // Register routes using the new API
    route_register("/", HTTP_GET, hello_world_handler);

    route_t* hello   = route_register("/hello", HTTP_GET, hello_world_handler);
    Middleware mw[2] = {mw1, mw2};
    use_route_middleware(hello, mw, 2);

    route_register("/json", HTTP_GET, json_handler);
    route_register("/echo", HTTP_GET, echo_handler);
    route_register("/echo", HTTP_POST, echo_handler);
    route_register("/params/{user_id}/{username}", HTTP_GET, pathparams_query_params_handler);
    route_register("/form", HTTP_POST, handle_form);
    route_register("/movie", HTTP_GET, serve_movie);

    route_static("/static", "./");

    return pulsar_run("localhost", 8080);
}
