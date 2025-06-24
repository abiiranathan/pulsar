#ifndef METHOD_H
#define METHOD_H

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
static inline bool is_safe_method(HttpMethod method) {
    return method == HTTP_GET || method == HTTP_OPTIONS || method == HTTP_HEAD;
}

static inline bool http_method_valid(HttpMethod method) {
    return method > HTTP_INVALID && method <= HTTP_OPTIONS;
}

static inline const char* http_method_to_string(const HttpMethod method) {
    switch (method) {
        case HTTP_GET:
            return "GET";
        case HTTP_POST:
            return "POST";
        case HTTP_PUT:
            return "PUT";
        case HTTP_PATCH:
            return "PATCH";
        case HTTP_OPTIONS:
            return "OPTIONS";
        case HTTP_HEAD:
            return "HEAD";
        case HTTP_DELETE:
            return "DELETE";
        default:
            return "";
    }
}

static inline HttpMethod http_method_from_string(const char* method) {
    if (!method)
        return HTTP_INVALID;
    if (strcmp(method, "GET") == 0)
        return HTTP_GET;
    if (strcmp(method, "HEAD") == 0)
        return HTTP_HEAD;
    if (strcmp(method, "POST") == 0)
        return HTTP_POST;
    if (strcmp(method, "PUT") == 0)
        return HTTP_PUT;
    if (strcmp(method, "PATCH") == 0)
        return HTTP_PATCH;
    if (strcmp(method, "DELETE") == 0)
        return HTTP_DELETE;
    if (strcmp(method, "OPTIONS") == 0)
        return HTTP_OPTIONS;
    return HTTP_INVALID;
}

#endif /* METHOD_H */
