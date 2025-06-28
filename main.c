#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "include/forms.h"
#include "include/headers.h"
#include "include/pulsar.h"

void hello_world_handler(connection_t* conn) {
    conn_set_status(conn, StatusOK);

    // Set-Cookie is a special header that can be set multiple times.
    conn_writeheader(conn, "Set-Cookie", "sessionId=12345; Path=/; HttpOnly");
    conn_writeheader(conn, "Set-Cookie", "theme=dark; Path=/; Secure");
    conn_set_content_type(conn, "text/plain");

    char buf[8192];
    FILE* fp = fopen(__FILE__, "r");
    int n    = fread(buf, 1, sizeof(buf), fp);
    if (n < 0) {
        perror("fread");
        fclose(fp);
        return;
    }
    fclose(fp);

    buf[n] = '\0';  // Null-terminate the buffer
    conn_write(conn, buf, n);
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

    // Should exist, otherwise our router is broken
    printf("Path Params: \n");
    printf("User ID: %s and username: %s\n", userId, username);

    assert(userId && username);

    // Check for query params.
    printf("Query Params: \n");
    header_entry* entry;
    headers_foreach(query_params(conn), entry) {
        printf("%s = %s\n", entry->name, entry->value);
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

void mw1(connection_t* conn) {
    // Pass a user-data ptr
    int* ptr = malloc(sizeof(int));
    if (ptr) {
        *ptr = 100;
        set_userdata(conn, ptr, free);
    }
}

void mw2(connection_t* conn) {
    // Print the user-data pointer
    int* userId = get_userdata(conn);
    UNUSED(userId);
}

int main() {
    HttpHandler mw[2] = {mw1, mw2};
    use_global_middleware(mw, 2);

    // Register routes using the new API
    route_register("/", HTTP_GET, hello_world_handler);
    route_register("/hello", HTTP_GET, hello_world_handler);
    route_register("/json", HTTP_GET, json_handler);
    route_register("/echo", HTTP_GET, echo_handler);
    route_register("/echo", HTTP_POST, echo_handler);
    route_register("/{user_id}/{username}", HTTP_GET, pathparams_query_params_handler);
    route_register("/form", HTTP_POST, handle_form);

    register_static_route("/static", "./");

    return pulsar_run(8080);
}
