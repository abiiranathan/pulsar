#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "include/content_types.h"
#include "include/forms.h"
#include "include/headers.h"
#include "include/pulsar.h"
#include "include/routing.h"
#include "include/status_code.h"

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

void mw1(connection_t* conn) {
    // Pass context to mw2.
    char* value = strdup("PULSAR");
    if (value) {
        pulsar_set_context_value(conn, "name", value);
    }
}

void mw2(connection_t* conn) {
    char* value = NULL;
    pulsar_get_context_value(conn, "name", (void**)&value);

    assert(value);
    printf("Hello: %s\n", value);
    free(value);
}

int main() {
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
