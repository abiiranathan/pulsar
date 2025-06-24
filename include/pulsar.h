#ifndef PULSAR_H
#define PULSAR_H

#include "constants.h"
#include "content_types.h"
#include "routing.h"
#include "status_code.h"
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

// Response object structure.
typedef struct response_t response_t;

// Connection Object structure.
typedef struct connection_t connection_t;

// Request Object structure.
typedef struct request_t request_t;

// event loop.
int pulsar_run(int port);

void use_global_middleware(HttpHandler* middleware, size_t count);
void use_route_middleware(route_t* route, HttpHandler* middleware, size_t count);
bool conn_servefile(connection_t* conn, const char* filename);
int conn_write_string(connection_t* conn, const char* str);
int conn_notfound(connection_t* conn);
int conn_write(connection_t* conn, const void* data, size_t len);
int conn_writef(connection_t* conn, const char* fmt, ...) __attribute__((format(printf, 2, 3)));
void conn_abort(connection_t* conn);
void conn_send(connection_t* conn, http_status status, const void* data, size_t length);
bool conn_set_content_type(connection_t* conn, const char* content_type);
bool conn_writeheader(connection_t* conn, const char* name, const char* value);
void conn_set_status(connection_t* conn, http_status code);

const char* query_get(connection_t* conn, const char* name);
headers_t* query_params(connection_t* conn);
const char* req_header_get(connection_t* conn, const char* name);
const char* req_body(connection_t* conn);
const char* req_method(connection_t* conn);
const char* req_path(connection_t* conn);
size_t req_content_len(connection_t* conn);
const char* res_header_get(connection_t* conn, const char* name);

const char* get_path_param(connection_t* conn, const char* name);
HttpMethod http_method_from_string(const char* method);
const char* http_method_to_string(const HttpMethod method);

void set_userdata(connection_t* conn, void* ptr, void (*free_func)(void* ptr));
void* get_userdata(connection_t* conn);

#ifdef __cplusplus
}
#endif

#endif /* PULSAR_H */
