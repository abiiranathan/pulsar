#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "include/content_types.h"
#include "include/forms.h"
#include "include/headers.h"
#include "include/pulsar.h"
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
    conn_set_content_type(conn, CT_HTML);
    conn_write_string(conn, html);
}

int main() {
    // Register routes using the new API
    route_register("/", HTTP_GET, hello_world_handler);
    route_register("/hello", HTTP_GET, hello_world_handler);
    route_register("/json", HTTP_GET, json_handler);
    route_register("/echo", HTTP_GET, echo_handler);
    route_register("/echo", HTTP_POST, echo_handler);
    route_register("/params/{user_id}/{username}", HTTP_GET, pathparams_query_params_handler);
    route_register("/form", HTTP_POST, handle_form);
    route_register("/movie", HTTP_GET, serve_movie);

    register_static_route("/static", "./");

    return pulsar_run("localhost", 8080);
}
