#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <pulsar/forms.h>
#include <pulsar/pulsar.h>

bool hello_world_handler(connection_t* conn) {
    conn_set_status(conn, StatusOK);
    conn_set_content_type(conn, "text/plain");
    conn_write(conn, "Hello, World!", 13);
    return true;
}

bool json_handler(connection_t* conn) {
    conn_set_status(conn, StatusOK);
    conn_set_content_type(conn, "application/json");

    const char* json = "{\"message\": \"Hello from JSON API\", \"status\": \"success\"}";
    conn_write(conn, json, strlen(json));
    return true;
}

bool echo_handler(connection_t* conn) {
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

    return true;
}

bool pathparams_query_params_handler(connection_t* conn) {
    const char* userId   = get_path_param(conn, "user_id");
    const char* username = get_path_param(conn, "username");

    // Should exist, otherwise our router is broken
    assert(userId && username);

    printf("Path Params: \n");
    printf("User ID: %s and username: %s\n", userId, username);

    // Check for query params.
    printf("Query Params: \n");
    headers_foreach(query_params(conn), query) {
        printf("%s = %s\n", query->name, query->value);
    }

    conn_writef(conn, "Your user_id is %s and username %s\n", userId, username);
    return true;
}

bool handle_form(connection_t* conn) {
    MultipartForm form = {};
    char boundary[128];
    MpCode code;

    code = multipart_init(&form, 1 << 20);
    if (code != MP_OK) {
        conn_set_status(conn, StatusBadRequest);
        return conn_write_string(conn, multipart_error(code));
    }

    const char* content_type = req_header_get(conn, "Content-Type");
    if (!content_type) {
        conn_set_status(conn, StatusBadRequest);
        return conn_write_string(conn, "Invalid content type header");
    }

    if (!parse_boundary(content_type, boundary, sizeof(boundary))) {
        conn_set_status(conn, StatusBadRequest);
        return conn_write_string(conn, "Invalid content type header");
    }

    const char* body      = req_body(conn);
    size_t content_length = req_content_len(conn);

    code = multipart_parse(body, content_length, boundary, &form);
    if (code != MP_OK) {
        conn_set_status(conn, StatusBadRequest);
        return conn_write_string(conn, multipart_error(code));
    }

    FileHeader* file = multipart_file(&form, "file");
    if (!file)
        return false;

    char dest[1024] = {0};
    strlcat(dest, "./test_output/", sizeof(dest));
    strlcat(dest, file->filename, sizeof(dest) - 15);  // ignore potential truncation
    if (!multipart_save_file(file, body, dest)) {
        return false;
    }

    return conn_write_string(conn, "File uploaded successfully\n") > 0;
}

bool mw1(connection_t* conn) {
    UNUSED(conn);

    // Pass a user-data ptr
    int* ptr = malloc(sizeof(int));
    if (!ptr)
        return false;

    *ptr = 100;

    set_userdata(conn, ptr, free);
    return true;
}

bool mw2(connection_t* conn) {
    UNUSED(conn);

    // Print the user-data pointer
    int* userId = get_userdata(conn);
    UNUSED(userId);
    return 1;
}

int main() {
    use_global_middleware(2, mw1, mw2);

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
