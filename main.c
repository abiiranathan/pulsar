#include "pulsar.h"

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

    // Echo request method and path
    conn_write(conn, "Method: ", 8);
    conn_write(conn, conn->request->method, strlen(conn->request->method));
    conn_write(conn, "\nPath: ", 7);
    conn_write(conn, conn->request->path, strlen(conn->request->path));

    // Echo body if present
    if (conn->request->body && conn->request->body_received > 0) {
        conn_write(conn, "\nBody: ", 7);
        conn_write(conn, conn->request->body, conn->request->body_received);
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
    headers_foreach(conn->request->query_params, query) {
        printf("%s = %s\n", query->name, query->value);
    }

    conn_writef(conn, "Your user_id is %s and username %s\n", userId, username);
    return true;
}

int main() {
    // Register routes using the new API
    route_register("/", HTTP_GET, hello_world_handler);
    route_register("/hello", HTTP_GET, hello_world_handler);
    route_register("/json", HTTP_GET, json_handler);
    route_register("/echo", HTTP_GET, echo_handler);
    route_register("/echo", HTTP_POST, echo_handler);
    route_register("/{user_id}/{username}", HTTP_GET, pathparams_query_params_handler);

    register_static_route("/static", "./");

    return pulsar_run(8080);
}