#include <inttypes.h>        // for PRIu64
#include <solidc/filepath.h>
#include <string.h>          // for strlen, memset
#include <time.h>            // for time()
#include <unistd.h>          // for usleep

#include "include/error.h"   // abort_if*, require_path_param, defer_*, PARSE_MULTIPART_FORM
#include "include/forms.h"   // MultipartForm processing.
#include "include/pulsar.h"  // PulsarCtx, PulsarConn, route_*, pulsar_run, conn_*, req_*

/* =========================================================================
 * Hello World
 * Demonstrates raw header injection and a plain HTML response body.
 * ========================================================================= */
void hello_world_handler(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;

    // Inject multiple Set-Cookie headers directly into the response.
    // conn_writeheader_raw appends pre-formatted header lines verbatim.
    StrSlice headers = SS_LIT(
        "Set-Cookie: sessionId=12345; Path=/; HttpOnly\r\n"
        "Set-Cookie: theme=dark; Path=/; Secure\r\n"
        "Content-Type: text/html\r\n");

    conn_writeheader_raw(conn, headers.data, headers.len);
    conn_write(conn, "<h1>Hello World</h1>", 20);
}

/* =========================================================================
 * JSON response
 * Demonstrates conn_send_json: sets status, Content-Type, and body in one
 * call.
 * ========================================================================= */
void json_handler(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;
    char json[] = "{\"message\": \"Hello from JSON API\", \"status\": \"success\"}";
    conn_send_json(conn, StatusOK, json, sizeof(json) - 1);
}

/* =========================================================================
 * Echo
 * Reflects the request method, path, and body back to the client as plain
 * text.  Demonstrates multiple conn_write calls — the server buffers them
 * and flushes when the handler returns.
 * ========================================================================= */
void echo_handler(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;

    Request req = conn_get_request_metadata(conn);
    const char* method = req.method;
    const char* path = req.path;
    StrSlice body = req.body;

    conn_set_status(conn, StatusOK);
    conn_set_content_type(conn, SS_LIT("text/plain"));

    conn_write(conn, "Method: ", 8);
    conn_write(conn, method, strlen(method));
    conn_write(conn, "\nPath: ", 7);
    conn_write(conn, path, strlen(path));

    // Only echo the body when one was actually sent.
    if (body.data && body.len > 0) {
        conn_write(conn, "\nBody: ", 7);
        conn_write(conn, body.data, body.len);
    }
}

/* =========================================================================
 * Server-Sent Events (SSE)
 * Streams 1 000 numbered events to the client at 1 ms intervals.
 *
 * NOTE: WITH_SSE_CONNECTION holds the worker thread for the entire stream
 * duration.  This is intentional for the POC but limits concurrency — a
 * production implementation should use non-blocking I/O or a dedicated
 * thread pool for long-lived connections.
 * ========================================================================= */
void sse_handler(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;
    WITH_SSE_CONNECTION(conn, {
        size_t total = 1000;

        while (total > 0 && server_running && conn_is_open(conn)) {
            char msg[64];
            char msg_id[24];
            snprintf(msg, sizeof(msg), "Message: %zu", total);
            snprintf(msg_id, sizeof(msg_id), "%zu", total);

            SSEvent evt = SSE_EVENT_INIT(ss_from_cstr(msg), SS_LIT("message"), ss_from_cstr(msg_id));
            conn_send_event(conn, &evt);
            total--;
            usleep(1000);  // 1 ms between events
        }
    });
}

/* =========================================================================
 * Chunked transfer encoding
 * Exercises the chunked-transfer path with varied payload sizes and a live
 * file stream.  Each test case is self-contained in its own block scope.
 * ========================================================================= */
void chunked_handler(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;
    WITH_CHUNKED_TRANSFER(conn, {
        // ── Case 1: 2 KB of repeated 'A' characters ──────────────────────
        {
            char large_data[2048];
            memset(large_data, 'A', sizeof(large_data) - 1);
            large_data[sizeof(large_data) - 1] = '\0';
            conn_write_chunk(conn, large_data, sizeof(large_data) - 1);
            usleep(100000);  // 100 ms
        }

        // ── Case 2: 20 long lines of text (~4 KB) ────────────────────────
        {
            char multi_line[4096];
            char* pos = multi_line;
            size_t remaining = sizeof(multi_line) - 1;

            for (int i = 0; i < 20 && remaining > 100; i++) {
                int written = snprintf(pos, remaining,
                                       "Line %d: This is a very long line of text that exceeds normal sizes. "
                                       "It contains repeated information to make it longer and test large "
                                       "chunk handling. "
                                       "Data data data data data data data data data data data data.\n",
                                       i);
                if (written >= (int)remaining) break;
                pos += written;
                remaining -= (size_t)written;
            }

            conn_write_chunk(conn, multi_line, (size_t)(pos - multi_line));
            usleep(100000);
        }

        // ── Case 3: ~3 KB JSON array of 40 user objects ──────────────────
        {
            char json_data[3072];
            int len = snprintf(json_data, sizeof(json_data),
                               "{\n"
                               "  \"type\": \"large_response\",\n"
                               "  \"timestamp\": %ld,\n"
                               "  \"data\": {\n"
                               "    \"users\": [\n",
                               time(NULL));

            for (int i = 0; i < 40 && len < (int)sizeof(json_data) - 200; i++) {
                len += snprintf(json_data + len, sizeof(json_data) - (size_t)len,
                                "      {\"id\": %d, \"name\": \"User%d\", "
                                "\"email\": \"user%d@example.com\", "
                                "\"active\": %s}%s\n",
                                i, i, i, (i % 2) ? "true" : "false", (i < 39) ? "," : "");
            }

            len += snprintf(json_data + len, sizeof(json_data) - (size_t)len,
                            "    ],\n"
                            "    \"metadata\": {\n"
                            "      \"count\": 40,\n"
                            "      \"generated_by\": \"chunked_handler\",\n"
                            "      \"description\": \"Large JSON payload for testing "
                            "chunked transfer encoding\"\n"
                            "    }\n"
                            "  }\n"
                            "}");

            conn_write_chunk(conn, json_data, (size_t)len);
            usleep(100000);
        }

        // ── Case 4: Stream this source file back to the client ────────────
        // __FILE__ resolves to the current translation unit at compile time.
        {
            DEFER_VAR FILE* fp = fopen(__FILE__, "r");
            if (fp) {
                defer_fclose(fp);
                char file_chunk[4096];
                size_t bytes_read;
                while ((bytes_read = fread(file_chunk, 1, sizeof(file_chunk), fp)) > 0) {
                    conn_write_chunk(conn, file_chunk, bytes_read);
                    usleep(50000);  // 50 ms between file chunks
                }
            }
        }

        // ── Sentinel chunk ────────────────────────────────────────────────
        const char* done = "\n=== LARGE CHUNK TESTING COMPLETED ===\n";
        conn_write_chunk(conn, done, strlen(done));
    });
}

/* =========================================================================
 * Path and query parameters
 * Demonstrates require_path_param (aborts 500 on routing bug) and
 * query_params / DUMP_HEADERS for diagnostic output.
 * ========================================================================= */
void pathparams_query_params_handler(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;

    // require_path_param declares the variable and aborts 500 if the router
    // somehow failed to populate the segment — safer than assert().
    require_path_param(user_id, conn, "user_id");
    require_path_param(username, conn, "username");

    printf("Path params — user_id=%s  username=%s\n", user_id, username);

    headers_t* params = query_params(conn);
    DUMP_HEADERS(params);

    // // Required query parameter
    // require_query(query, conn, "q");         // Returns a slice (no alloc)
    // require_query_alloc(query2, conn, "q");  // allocates
    // printf("query: %s\n", query);
    // printf("query2: %s\n", query2);
    // free(query2);

    conn_writef(conn, "Your user_id is %s and username %s\n", user_id, username);
}

/* =========================================================================
 * Multipart form upload
 * PARSE_MULTIPART_FORM handles init, boundary extraction, body parsing,
 * and deferred cleanup in one macro call.  `body` holds the raw request
 * body needed by multipart_save_file.
 * ========================================================================= */
void handle_form(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;
    MultipartForm form = {0};

    PARSE_MULTIPART_FORM(conn, &form, content_type, body);

    FileHeader* file = multipart_file(&form, "file");
    if (file) {
        DEFER_VAR char* dst = filepath_join("test_output", file->filename);
        defer_free(dst);
        if (multipart_save_file(file, body.data, dst)) { conn_write_string(conn, "File uploaded successfully\n"); }
    }
}

/* =========================================================================
 * Movie player page
 * Serves a minimal HTML page that streams an MP4 via the /static/ route.
 * ========================================================================= */
void serve_movie(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;
    const char* html =
        "<html><body style='max-width:1000px;margin:20px'>"
        "<video src='/static/FlightRisk.mp4' controls width='720' height='480'>"
        "</video></body></html>";

    conn_set_status(conn, StatusOK);
    conn_set_content_type(conn, SS_LIT("text/html"));
    conn_write_string(conn, html);
}

/* =========================================================================
 * Middleware pair — context value passing
 * mw1 allocates a string in the connection arena and stores it under "name".
 * mw2 retrieves and validates it.  Together they demonstrate pulsar_set /
 * pulsar_get and the arena-backed pulsar_strdup pattern.
 * ========================================================================= */
void mw1(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;
    char* name = pulsar_strdup(conn, "PULSAR");
    pulsar_set(conn, "name", name, NULL);
}

void mw2(PulsarCtx* ctx) {
    PulsarConn* conn = ctx->conn;
    char* name = pulsar_get(conn, "name");

    // This assert is intentional: mw2 must never run without mw1 preceding
    // it in the middleware chain.  A routing misconfiguration is a programmer
    // error, not a recoverable runtime condition.
    assert(name && "mw2: 'name' key missing — ensure mw1 runs before mw2");
    (void)name;
}

/* =========================================================================
 * Entry point
 * ========================================================================= */
int main(void) {
    // Attach the built-in access logger; writes combined-log lines to stdout.
    pulsar_set_callback(pulsar_logger, STDOUT_FILENO);

    // ── Route table ───────────────────────────────────────────────────────
    route_register("/", HTTP_GET, hello_world_handler);

    // Attach middleware to /hello — mw1 must precede mw2.
    route_t* hello = route_get("/hello", hello_world_handler);
    Middleware mw[2] = {mw1, mw2};
    use_route_middleware(hello, mw, 2);

    route_get("/json", json_handler);
    route_get("/sse", sse_handler);
    route_get("/chunked", chunked_handler);
    route_get("/echo", echo_handler);
    route_post("/echo", echo_handler);
    route_get("/params/{user_id}/{username}", pathparams_query_params_handler);
    route_post("/form", handle_form);
    route_get("/movie", serve_movie);

    // Serve everything under ./ at the /static/ prefix.
    route_static("/static/", "./");

    return pulsar_run("localhost", 8080);
}