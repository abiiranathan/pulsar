#ifndef METHOD_H
#define METHOD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>

typedef enum : int8_t {
    HTTP_INVALID = -1,
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_PATCH,
    HTTP_DELETE,
    HTTP_HEAD,
    HTTP_OPTIONS,
} HttpMethod;

#define METHOD_VALID(method) ((method) > HTTP_INVALID && (method) <= HTTP_OPTIONS)
#define SAFE_METHOD(method)                                                                        \
    (((method) == HTTP_GET || (method) == HTTP_OPTIONS || (method) == HTTP_HEAD))

static char* methods[] = {
    [HTTP_GET] = "GET",         [HTTP_POST] = "POST",     [HTTP_PUT] = "PUT",
    [HTTP_PATCH] = "PATCH",     [HTTP_DELETE] = "DELETE", [HTTP_HEAD] = "HEAD",
    [HTTP_OPTIONS] = "OPTIONS",
};

static inline const char* http_method_to_string(const HttpMethod method) {
    if (!METHOD_VALID(method)) {
        return "";
    }
    return methods[method];
}

static inline HttpMethod http_method_from_string(const char* method) {
    if (method == NULL) return HTTP_INVALID;

    if (strcmp(method, "GET") == 0) return HTTP_GET;
    if (strcmp(method, "HEAD") == 0) return HTTP_HEAD;
    if (strcmp(method, "POST") == 0) return HTTP_POST;
    if (strcmp(method, "PUT") == 0) return HTTP_PUT;
    if (strcmp(method, "PATCH") == 0) return HTTP_PATCH;
    if (strcmp(method, "DELETE") == 0) return HTTP_DELETE;
    if (strcmp(method, "OPTIONS") == 0) return HTTP_OPTIONS;

    return HTTP_INVALID;
}

#ifdef __cplusplus
}
#endif

#endif  // METHOD_H
