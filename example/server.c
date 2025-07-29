#include <pulsar/pulsar.h>

void hello_handler(connection_t* conn) {
    conn_set_status(conn, StatusOK);
    conn_set_content_type(conn, "text/plain");
    conn_write_string(conn, "Hello World!");
}

int main() {
    route_register("/", HTTP_GET, hello_handler);
    return pulsar_run("localhost", 8080);
}
