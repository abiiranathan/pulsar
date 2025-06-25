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

/**
 * @brief Response object structure
 *
 * Contains all data related to the HTTP response being constructed
 */
typedef struct response_t response_t;

/**
 * @brief Connection object structure
 *
 * Represents a client connection and maintains all connection state
 */
typedef struct connection_t connection_t;

/**
 * @brief Request object structure
 *
 * Contains all data related to the incoming HTTP request
 */
typedef struct request_t request_t;

/**
 * @brief Starts the Pulsar HTTP server event loop
 *
 * @param port The TCP port to listen on
 * @return int 0 on success, non-zero on error
 */
int pulsar_run(int port);

/**
 * @brief Registers global middleware functions
 *
 * @param middleware Array of middleware handler functions
 * @param count Number of middleware functions in array
 */
void use_global_middleware(HttpHandler* middleware, size_t count);

/**
 * @brief Registers route-specific middleware functions
 *
 * @param route The route to attach middleware to
 * @param middleware Array of middleware handler functions
 * @param count Number of middleware functions in array
 */
void use_route_middleware(route_t* route, HttpHandler* middleware, size_t count);

/**
 * @brief Serves a file as the response
 *
 * @param conn The connection object
 * @param filename Path to file to serve
 * @return true File was successfully opened
 * @return false File could not be opened
 */
bool conn_servefile(connection_t* conn, const char* filename);

/**
 * @brief Writes a string to the response body
 *
 * @param conn The connection object
 * @param str String to write (NULL-terminated)
 * @return int Number of bytes written, or -1 on error
 */
int conn_write_string(connection_t* conn, const char* str);

/**
 * @brief Sends a 404 Not Found response
 *
 * @param conn The connection object
 * @return int Number of bytes written
 */
int conn_notfound(connection_t* conn);

/**
 * @brief Writes binary data to the response body
 *
 * @param conn The connection object
 * @param data Pointer to data to write
 * @param len Length of data in bytes
 * @return int Number of bytes written, or -1 on error
 */
int conn_write(connection_t* conn, const void* data, size_t len);

/**
 * @brief Writes formatted string to response body
 *
 * @param conn The connection object
 * @param fmt printf-style format string
 * @param ... Format arguments
 * @return int Number of bytes written, or -1 on error
 */
int conn_writef(connection_t* conn, const char* fmt, ...) __attribute__((format(printf, 2, 3)));

/**
 * @brief Aborts request processing
 *
 * Stops middleware and handler execution immediately
 *
 * @param conn The connection object
 */
void conn_abort(connection_t* conn);

/**
 * @brief Sends a complete response
 *
 * @param conn The connection object
 * @param status HTTP status code
 * @param data Response body data
 * @param length Length of response body
 */
void conn_send(connection_t* conn, http_status status, const void* data, size_t length);

/**
 * @brief Sets the Content-Type header
 *
 * @param conn The connection object
 * @param content_type Content type string
 */
void conn_set_content_type(connection_t* conn, const char* content_type);

/**
 * @brief Adds a header to the response
 *
 * @param conn The connection object
 * @param name Header name
 * @param value Header value
 */
void conn_writeheader(connection_t* conn, const char* name, const char* value);

/**
 * @brief Sets the HTTP response status
 *
 * @param conn The connection object
 * @param code HTTP status code
 */
void conn_set_status(connection_t* conn, http_status code);

/**
 * @brief Gets a query parameter value
 *
 * @param conn The connection object
 * @param name Parameter name
 * @return const char* Parameter value or NULL if not found
 */
const char* query_get(connection_t* conn, const char* name);

/**
 * @brief Gets all query parameters
 *
 * @param conn The connection object
 * @return headers_t* Map of all query parameters
 */
headers_t* query_params(connection_t* conn);

/**
 * @brief Gets a request header value
 *
 * @param conn The connection object
 * @param name Header name
 * @return const char* Header value or NULL if not found
 */
const char* req_header_get(connection_t* conn, const char* name);

/**
 * @brief Gets the request body
 *
 * @param conn The connection object
 * @return const char* Request body or NULL if none
 */
const char* req_body(connection_t* conn);

/**
 * @brief Gets the request method
 *
 * @param conn The connection object
 * @return const char* HTTP method string
 */
const char* req_method(connection_t* conn);

/**
 * @brief Gets the request path
 *
 * @param conn The connection object
 * @return const char* Request path
 */
const char* req_path(connection_t* conn);

/**
 * @brief Gets the request content length
 *
 * @param conn The connection object
 * @return size_t Content-Length header value
 */
size_t req_content_len(connection_t* conn);

/**
 * @brief Gets a response header value
 *
 * @param conn The connection object
 * @param name Header name
 * @return const char* Header value or NULL if not found
 */
const char* res_header_get(connection_t* conn, const char* name);

/**
 * @brief Gets a path parameter value
 *
 * @param conn The connection object
 * @param name Parameter name
 * @return const char* Parameter value or NULL if not found
 */
const char* get_path_param(connection_t* conn, const char* name);

/**
 * @brief Converts HTTP method string to enum
 *
 * @param method HTTP method string
 * @return HttpMethod Method enum value
 */
HttpMethod http_method_from_string(const char* method);

/**
 * @brief Converts HTTP method enum to string
 *
 * @param method HTTP method enum
 * @return const char* Method string
 */
const char* http_method_to_string(const HttpMethod method);

/**
 * @brief Attaches user data to a connection
 *
 * @param conn The connection object
 * @param ptr User data pointer
 * @param free_func Optional cleanup function
 */
void set_userdata(connection_t* conn, void* ptr, void (*free_func)(void* ptr));

/**
 * @brief Gets user data from connection
 *
 * @param conn The connection object
 * @return void* User data pointer or NULL
 */
void* get_userdata(connection_t* conn);

#ifdef __cplusplus
}
#endif

#endif /* PULSAR_H */
