#include <fcntl.h>
#include <inttypes.h>
#include <solidc/defer.h>
#include "include/forms.h"
#include "include/plog.h"
#include "include/pulsar.h"

static bool print_header_callback(StrSlice name, StrSlice value, void* userdata) {
    (void)userdata;
    printf("%.*s = %.*s\n", (int)name.len, name.data, (int)value.len, value.data);
    return true;
}

void hello_world_handler(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;
    StrSlice headers = SS_LIT(
        "Set-Cookie: sessionId=12345; Path=/; HttpOnly\r\n"
        "Set-Cookie: theme=dark; Path=/; Secure\r\n"
        "Content-Type: text/html\r\n");

    conn_set_status(conn, StatusOK);
    conn_writeheader_raw(conn, headers.data, headers.len);
    conn_write(conn, "<h1>Hello World</h1>", 20);

    // // Log all headers
    // const headers_t* h = req_headers(conn);
    // // headers_foreach(h, print_header_callback, NULL);
    // for (size_t i = 0; i < h->count; ++i) {
    //     printf("%.*s: %.*s\n", (int)h->entries[i].name.len, h->entries[i].name.data,
    //            (int)h->entries[i].value.len, h->entries[i].value.data);
    // }
}

void json_handler(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;
    conn_set_status(conn, StatusOK);
    conn_set_content_type(conn, SS_LIT("application/json"));

    char json[] = "{\"message\": \"Hello from JSON API\", \"status\": \"success\"}";
    conn_write(conn, json, sizeof(json) - 1);
}

void echo_handler(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;
    conn_set_status(conn, StatusOK);
    conn_set_content_type(conn, SS_LIT("text/plain"));

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

void sse_handler(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;
    WITH_SSE_CONNECTION(conn, {
        size_t total = 1000;

        // This will block the whole worker thread :) Be ware!!
        while (total > 0 && server_running && conn_is_open(conn)) {
            char msg[64];
            char msg_id[24];

            snprintf(msg, sizeof(msg), "Message: %lu", total);
            snprintf(msg_id, sizeof(msg_id), "%lu", total);

            StrSlice data  = ss_from_cstr(msg);
            StrSlice event = SS_LIT("message");
            StrSlice id    = ss_from_cstr(msg_id);
            SSEvent evt    = SSE_EVENT_INIT(data, event, id);
            conn_send_event(conn, &evt);
            total--;
            usleep(1000);
        }
    });
}

void chunked_handler(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;
    WITH_CHUNKED_TRANSFER(conn, {
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
                             "Line %d: This is a very long line of text that exceeds normal "
                             "sizes. "
                             "It contains repeated information to make it longer and test large "
                             "chunk handling. "
                             "Data data data data data data data data data data data data.\n",
                             i);
                if (written >= (int)remaining) break;
                pos += written;
                remaining -= (size_t)written;
            }

            size_t data_len = (size_t)(pos - multi_line);
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
                len += snprintf(json_data + len, sizeof(json_data) - (size_t)len,
                                "      {\"id\": %d, \"name\": \"User%d\", \"email\": "
                                "\"user%d@example.com\", "
                                "\"active\": %s}%s\n",
                                i, i, i, (i % 2) ? "true" : "false", (i < 39) ? "," : "");
            }

            len += snprintf(json_data + len, sizeof(json_data) - (size_t)len,
                            "    ],\n"
                            "    \"metadata\": {\n"
                            "      \"count\": 40,\n"
                            "      \"generated_by\": \"chunked_handler\",\n"
                            "      \"description\": \"Large JSON payload for testing chunked "
                            "transfer encoding\"\n"
                            "    }\n"
                            "  }\n"
                            "}");

            conn_write_chunk(conn, json_data, (size_t)len);
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
            remaining -= (size_t)written;

            for (int i = 0; i < 200 && remaining > 80; i++) {
                written = snprintf(pos, remaining,
                                   "Entry %03d: Long detailed entry with timestamp %ld and data "
                                   "payload.\n",
                                   i, time(NULL) + i);
                if (written >= (int)remaining) break;
                pos += written;
                remaining -= (size_t)written;
            }

            size_t total_len = (size_t)(pos - massive_chunk);
            conn_write_chunk(conn, massive_chunk, total_len);
            usleep(200000);  // 200ms
        }

        // Final small chunk to signal completion
        const char* completion = "\n=== LARGE CHUNK TESTING COMPLETED ===\n";
        conn_write_chunk(conn, completion, strlen(completion));
    });
}

void pathparams_query_params_handler(PulsarCtx* ctx) {
    PulsarConn* conn     = ctx->conn;
    const char* userId   = get_path_param(conn, "user_id");
    const char* username = get_path_param(conn, "username");
    assert(userId && username);

    // Should exist, otherwise our router is broken
    printf("Path Params: \n");
    printf("User ID= %s and username= %s\n", userId, username);

    headers_t* params = query_params(conn);
    if (params) {
        // Check for query params.
        printf("Query Params: \n");
        headers_foreach(params, print_header_callback, NULL);
    }
    conn_writef(conn, "Your user_id is %s and username %s\n", userId, username);
}

void handle_form(PulsarCtx* ctx) {
    PulsarConn* conn   = ctx->conn;
    char boundary[128] = {0};
    MultipartCode code = {0};
    MultipartForm form = {0};

    code = multipart_init(&form);
    if (code != MULTIPART_OK) {
        conn_set_status(conn, StatusBadRequest);
        conn_write_string(conn, multipart_error(code));
        return;
    }

    defer {
        multipart_cleanup((MultipartForm*)&form);
    };

    StrSlice ctype = req_header_get(conn, "Content-Type");
    if (!ss_is_valid(ctype)) {
        conn_set_status(conn, StatusBadRequest);
        conn_write_string(conn, "Invalid content type header");
        return;
    }

    char* content_type = ss_to_owned_cstr(ctype);
    if (!content_type) {
        conn_set_status(conn, StatusInternalServerError);
        conn_write_string(conn, "Out of memory");
        return;
    }

    if (!parse_boundary(content_type, boundary, sizeof(boundary))) {
        conn_set_status(conn, StatusBadRequest);
        conn_write_string(conn, "Invalid content type header");
        return;
    }
    free(content_type);

    const char* body      = req_body(conn);
    size_t content_length = req_content_len(conn);

    code = multipart_parse(body, content_length, boundary, &form);
    if (code != MULTIPART_OK) {
        conn_set_status(conn, StatusBadRequest);
        conn_write_string(conn, multipart_error(code));
        return;
    }

    FileHeader* file = multipart_file(&form, "file");
    if (file) {
        char dest[1024] = {0};
        strlcat(dest, "./test_output/", sizeof(dest));
        strlcat(dest, file->filename, sizeof(dest) - 15);
        if (multipart_save_file(file, body, dest)) {
            conn_write_string(conn, "File uploaded successfully\n");
        }
    }
}

void serve_movie(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;
    const char* html =
        "<html><body style='max-width: 1000px; margin: 20px;'><video "
        "src='/static/FlightRisk.mp4' "
        "controls width='720' height='480'></video></body></html>";

    conn_set_status(conn, StatusOK);
    conn_set_content_type(conn, SS_LIT(HTML_TYPE));
    conn_write_string(conn, html);
}

/* -------------------------------------------------------------------------
 * Callback — hot path, no syscalls
 * ---------------------------------------------------------------------- */
static PlogState g_log;  // Lives for the duration of the process
static int enable_logging = 0;

void pulsar_callback(PulsarCtx* ctx, uint64_t total_ns) {
    if (!enable_logging) return;

    PulsarConn* conn        = ctx->conn;
    const char* method      = req_method(conn);
    const char* path        = req_path(conn);
    http_status status_code = res_get_status(conn);
    StrSlice user_agent     = req_header_get(conn, "User-Agent");
    if (!ss_is_valid(user_agent)) {
        user_agent = SS_LIT("-");
    }

    /* Format latency with the most readable unit. */
    char latency_str[24];
    if (total_ns < 1000) {
        snprintf(latency_str, sizeof(latency_str), "%3" PRIu64 "ns", total_ns);
    } else if (total_ns < 1000000) {
        snprintf(latency_str, sizeof(latency_str), "%5" PRIu64 "µs", total_ns / 1000);
    } else if (total_ns < 1000000000) {
        snprintf(latency_str, sizeof(latency_str), "%5" PRIu64 "ms", total_ns / 1000000);
    } else if (total_ns < UINT64_C(60000000000)) {
        snprintf(latency_str, sizeof(latency_str), "%5" PRIu64 "s", total_ns / 1000000000);
    } else {
        snprintf(latency_str, sizeof(latency_str), "%5" PRIu64 "m",
                 total_ns / UINT64_C(60000000000));
    }

    /*
     * Build the full log line on the stack.  snprintf + plog_submit is the
     * entire hot-path cost — no locks, no syscalls.
     */
    char line[PLOG_LINE_MAX];
    int n = snprintf(line, sizeof(line), "[Pulsar] %-7s %-5s %3d %8s %.*s\n", method, path,
                     (int)status_code, latency_str, (int)user_agent.len, user_agent.data);
    if (n > 0) {
        plog_submit(&g_log, line, (uint32_t)n);
    }
}

void mw1(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;
    char* name       = pulsar_strdup(conn, "PULSAR");
    pulsar_set(conn, "name", name, NULL);
}

void mw2(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;
    char* name       = pulsar_get(conn, "name");
    assert(name && "name is NULL");
    (void)name;
}

int main() {
    // int fd = open("pulsar.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    // Initialiaze logger bg thread
    if (!plog_init(&g_log, STDOUT_FILENO)) {
        return -1;
    }

    // Set post-request callback handler.
    // pulsar_set_callback(pulsar_callback);

    // Register routes using the new API
    route_register("/", HTTP_GET, hello_world_handler);

    route_t* hello   = route_get("/hello", hello_world_handler);
    Middleware mw[2] = {mw1, mw2};
    use_route_middleware(hello, mw, 2);

    route_get("/json", json_handler);
    route_get("/sse", sse_handler);
    route_get("/chunked", chunked_handler);
    route_get("/echo", echo_handler);
    route_get("/params/{user_id}/{username}", pathparams_query_params_handler);
    route_post("/echo", echo_handler);
    route_post("/form", handle_form);
    route_get("/movie", serve_movie);
    route_static("/static/", "./");

    int rc = pulsar_run("localhost", 8080);

    /* Flush and stop the drain thread before exit. */
    plog_destroy(&g_log);
    uint64_t drops = plog_drop_count(&g_log);
    if (drops > 0) {
        fprintf(stderr, "[plog] warning: %" PRIu64 " log entries dropped under load\n", drops);
    }
    return rc;
}
