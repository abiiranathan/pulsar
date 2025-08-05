#include "include/forms.h"
#include "include/pulsar.h"

void hello_world_handler(connection_t* conn) {
    static const char headers[] =
        "Set-Cookie: sessionId=12345; Path=/; HttpOnly\r\n"
        "Set-Cookie: theme=dark; Path=/; Secure\r\n"
        "Content-Type: text/plain\r\n";

    conn_set_status(conn, StatusOK);
    conn_writeheader_raw(conn, headers, sizeof(headers) - 1);  // -1 to exclude null terminator
    conn_write(conn, "Hello World", 11);
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

void sse_handler(connection_t* conn) {
    conn_start_sse(conn);
    size_t total = 10000;
    while (total > 0 && server_running) {
        char msg[64];
        char msg_id[24];

        snprintf(msg, sizeof(msg), "Message: %lu", total);
        snprintf(msg_id, sizeof(msg_id), "%lu", total);

        sse_event_t evt = SSE_EVENT_INIT(msg, "message", msg_id);
        conn_send_event(conn, &evt);
        total--;
        usleep(1000);
    }
    conn_end_sse(conn);
}

void chunked_handler(connection_t* conn) {
    conn_start_chunked_transfer(conn, 0);

    // Test case 1: Large single chunk (2KB)
    {
        char large_data[2048];
        memset(large_data, 'A', sizeof(large_data) - 1);
        large_data[sizeof(large_data) - 1] = '\0';

        conn_write_chunk(conn, large_data, strlen(large_data));
        usleep(100000);  // 100ms delay
    }

    // Test case 2: Multi-line text chunk (4KB)
    {
        char multi_line[4096];
        char* pos        = multi_line;
        size_t remaining = sizeof(multi_line) - 1;

        for (int i = 0; i < 20 && remaining > 100; i++) {
            int written =
                snprintf(pos, remaining,
                         "Line %d: This is a very long line of text that exceeds normal sizes. "
                         "It contains repeated information to make it longer and test large chunk handling. "
                         "Data data data data data data data data data data data data.\n",
                         i);
            if (written >= (int)remaining) break;
            pos += written;
            remaining -= written;
        }

        size_t data_len = pos - multi_line;
        conn_write_chunk(conn, multi_line, data_len);
        usleep(100000);
    }

    // Test case 3: JSON payload (3KB)
    {
        char json_data[3072];
        int len = snprintf(json_data, sizeof(json_data),
                           "{\n"
                           "  \"type\": \"large_response\",\n"
                           "  \"timestamp\": %ld,\n"
                           "  \"data\": {\n"
                           "    \"users\": [\n",
                           time(NULL));

        // Add many user objects
        for (int i = 0; i < 40 && len < (int)sizeof(json_data) - 200; i++) {
            len += snprintf(json_data + len, sizeof(json_data) - len,
                            "      {\"id\": %d, \"name\": \"User%d\", \"email\": \"user%d@example.com\", "
                            "\"active\": %s}%s\n",
                            i, i, i, (i % 2) ? "true" : "false", (i < 39) ? "," : "");
        }

        len +=
            snprintf(json_data + len, sizeof(json_data) - len,
                     "    ],\n"
                     "    \"metadata\": {\n"
                     "      \"count\": 40,\n"
                     "      \"generated_by\": \"chunked_handler\",\n"
                     "      \"description\": \"Large JSON payload for testing chunked transfer encoding\"\n"
                     "    }\n"
                     "  }\n"
                     "}");

        conn_write_chunk(conn, json_data, len);
        usleep(100000);
    }

    // Test case 4: Very large binary-safe data (8KB)
    {
        char huge_data[8192];

        // Fill with varied data including some null bytes to test binary safety
        for (size_t i = 0; i < sizeof(huge_data); i++) {
            huge_data[i] = (char)(i % 256);
        }

        conn_write_chunk(conn, huge_data, sizeof(huge_data));
        usleep(100000);
    }

    // Test case 5: Stream source file in large chunks
    {
        FILE* fp = fopen(__FILE__, "r");
        if (fp) {
            char file_chunk[4096];
            size_t bytes_read;

            while ((bytes_read = fread(file_chunk, 1, sizeof(file_chunk), fp)) > 0) {
                conn_write_chunk(conn, file_chunk, bytes_read);
                usleep(50000);  // 50ms between file chunks
            }

            fclose(fp);
        }
    }

    // Test case 6: Rapid succession of medium chunks (1.5KB each)
    for (int i = 0; i < 5; i++) {
        char medium_chunk[1536];

        int len = snprintf(medium_chunk, sizeof(medium_chunk), "CHUNK %d: ", i);

        // Fill rest with pattern
        for (int j = len; j < (int)sizeof(medium_chunk) - 1; j++) {
            medium_chunk[j] = 'A' + ((j - len) % 26);
        }
        medium_chunk[sizeof(medium_chunk) - 1] = '\0';

        conn_write_chunk(conn, medium_chunk, strlen(medium_chunk));
        usleep(25000);  // 25ms delay
    }

    // Test case 7: Single massive chunk (16KB)
    {
        static char massive_chunk[16384];

        char* pos        = massive_chunk;
        size_t remaining = sizeof(massive_chunk) - 1;

        // Create structured content
        int written = snprintf(pos, remaining, "=== MASSIVE CHUNK TEST ===\n");
        pos += written;
        remaining -= written;

        for (int i = 0; i < 200 && remaining > 80; i++) {
            written = snprintf(pos, remaining,
                               "Entry %03d: Long detailed entry with timestamp %ld and data payload.\n", i,
                               time(NULL) + i);
            if (written >= (int)remaining) break;
            pos += written;
            remaining -= written;
        }

        size_t total_len = pos - massive_chunk;
        conn_write_chunk(conn, massive_chunk, total_len);
        usleep(200000);  // 200ms
    }

    // Final small chunk to signal completion
    const char* completion = "\n=== LARGE CHUNK TESTING COMPLETED ===\n";
    conn_write_chunk(conn, completion, strlen(completion));
    conn_end_chunked_transfer(conn);
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
    MultipartForm form = {0};
    char boundary[128];
    MultipartCode code;

    code = multipart_init(&form, 1 << 20);
    if (code != MULTIPART_OK) {
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
    if (code != MULTIPART_OK) {
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
    conn_set_content_type(conn, HTML_TYPE);
    conn_write_string(conn, html);
}

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
    pulsar_set_context_value(conn, "name", "PULSAR", NULL);
}

void mw2(connection_t* conn) {
    // value retrieved from context.
    char* value = pulsar_get_context_value(conn, "name");
    printf("Context value: %s\n", value);
}

int main() {
    // Set post-request callback handler.
    pulsar_set_callback(pulsar_callback);

    // Register routes using the new API
    route_register("/", HTTP_GET, hello_world_handler);

    route_t* hello   = route_register("/hello", HTTP_GET, hello_world_handler);
    Middleware mw[2] = {mw1, mw2};
    use_route_middleware(hello, mw, 2);

    route_register("/json", HTTP_GET, json_handler);
    route_register("/sse", HTTP_GET, sse_handler);
    route_register("/chunked", HTTP_GET, chunked_handler);
    route_register("/echo", HTTP_GET, echo_handler);
    route_register("/echo", HTTP_POST, echo_handler);
    route_register("/params/{user_id}/{username}", HTTP_GET, pathparams_query_params_handler);
    route_register("/form", HTTP_POST, handle_form);
    route_register("/movie", HTTP_GET, serve_movie);

    route_static("/static/", "./");

    return pulsar_run("localhost", 8080);
}
