#ifndef METHOD_H
#define METHOD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>

typedef enum {
    HTTP_INVALID = -1,
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_PATCH,
    HTTP_DELETE,
    HTTP_HEAD,
    HTTP_OPTIONS,
} HttpMethod;

// If http method is safe. (GET / OPTIONS / HEAD)
bool is_safe_method(HttpMethod method);

// Returns true if the method is valid.
bool http_method_valid(HttpMethod method);

// Convert string method to method enum type.
// Returns HTTP_INVALID if method is not valid.
HttpMethod http_method_from_string(const char* method);

// Convert enum type to method string.
// Returns an empty string of method is not valid.
const char* http_method_to_string(const HttpMethod method);

#ifdef __cplusplus
}
#endif

#endif  // METHOD_H
