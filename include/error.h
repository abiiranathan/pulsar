#pragma once
// error.h — Common error-handling, response, and resource-management macros for Pulsar.
//
// Design goals:
//   - Reduce boilerplate observed in handler code.
//   - Every "abort" macro performs a conn_send / conn_write and then returns from
//     the calling handler function.  They are intentionally statement-like and must
//     only appear inside void handler functions.
//   - "defer_*" macros register RAII cleanup via solidc's defer{} facility; they
//     must appear at the top of a block scope, before the resource is used.

#include <solidc/defer.h>
#include <stdio.h>  // for fprintf, stderr
#include "forms.h"
#include "pulsar.h"

/* =========================================================================
 * §1  Core conditional-abort primitive
 * =========================================================================
 *
 * abort_if(condition, conn, status_code, data, len)
 *
 *   Sends a response with the given status and body, then returns from the
 *   enclosing handler if `condition` is true.
 *
 *   Example:
 *     abort_if(ptr == NULL, conn, StatusBadRequest, "null pointer", 12);
 */
#define abort_if(condition, conn, status_code, data, len) \
    if ((condition)) {                                    \
        conn_send((conn), (status_code), (data), (len));  \
        return;                                           \
    }

/* abort_if_lit — variant that accepts a C string literal directly,
 * eliminating the need for an explicit SS_LIT() + length pair.
 *
 *   abort_if_lit(ptr == NULL, conn, StatusBadRequest, "null pointer");
 */
#define abort_if_lit(condition, conn, status_code, literal) \
    abort_if((condition), (conn), (status_code), (literal), (sizeof(literal) - 1))

#define abort_if_nullptr(ptr, conn, literal) \
    abort_if_lit(ptr == NULL, conn, StatusInternalServerError, literal)

/* =========================================================================
 * §2  Convenience abort macros for common HTTP status codes
 * =========================================================================
 *
 * Each macro sends the corresponding status code, writes `msg` (a C string
 * literal or char*) with `len` bytes, and returns from the handler.
 *
 * Low-ceremony variants that accept a literal.
 *
 *   abort_400_msg(conn, msg, len);
 *   abort_400(conn, "bad boundary");
 */

#define abort_400(conn, literal) abort_if_lit(true, (conn), StatusBadRequest, (literal))
#define abort_401(conn, literal) abort_if_lit(true, (conn), StatusUnauthorized, (literal))
#define abort_403(conn, literal) abort_if_lit(true, (conn), StatusForbidden, (literal))
#define abort_404(conn, literal) abort_if_lit(true, (conn), StatusNotFound, (literal))
#define abort_405(conn, literal) abort_if_lit(true, (conn), StatusMethodNotAllowed, (literal))
#define abort_409(conn, literal) abort_if_lit(true, (conn), StatusConflict, (literal))
#define abort_500(conn, literal) abort_if_lit(true, (conn), StatusInternalServerError, (literal))

#define abort_400_msg(conn, msg, len) abort_if(true, (conn), StatusBadRequest, (msg), (len))
#define abort_401_msg(conn, msg, len) abort_if(true, (conn), StatusUnauthorized, (msg), (len))
#define abort_403_msg(conn, msg, len) abort_if(true, (conn), StatusForbidden, (msg), (len))
#define abort_404_msg(conn, msg, len) abort_if(true, (conn), StatusNotFound, (msg), (len))
#define abort_405_msg(conn, msg, len) abort_if(true, (conn), StatusMethodNotAllowed, (msg), (len))
#define abort_409_msg(conn, msg, len) abort_if(true, (conn), StatusConflict, (msg), (len))
#define abort_413_msg(conn, msg, len) \
    abort_if(true, (conn), StatusRequestEntityTooLarge, (msg), (len))
#define abort_422_msg(conn, msg, len) \
    abort_if(true, (conn), StatusUnprocessableEntity, (msg), (len))
#define abort_500_msg(conn, msg, len) \
    abort_if(true, (conn), StatusInternalServerError, (msg), (len))

/* =========================================================================
 * §3  Path-parameter and query parameter extraction with built-in null guard
 * =========================================================================
 *
 * require_path_param(var, conn, key)
 *
 *   Declares `const char* var`, extracts the named path parameter, and
 *   responds 400 + returns if the parameter is absent.  A missing path param
 *   indicates a routing bug, but aborting gracefully is safer than asserting.
 *
 *   Example (replaces the assert pattern in pathparams_query_params_handler):
 *
 *     require_path_param(user_id,  conn, "user_id");
 *     require_path_param(username, conn, "username");
 */
#define require_path_param(var, conn, key)           \
    const char* var = get_path_param((conn), (key)); \
    abort_if_lit((var) == NULL, (conn), StatusBadRequest, "missing required path parameter: " key)

// Fetch a query string slice
#define require_query(var, conn, key)           \
    const char* var = query_get((conn), (key)); \
    abort_if_nullptr((var), (conn), StatusBadRequest, "missing required query parameter: " key)

#define defer_form_cleanup(form) \
    defer { multipart_cleanup((MultipartForm*)(form)); }

/*
 * parse_multipart_form(conn, form_ptr, boundary_buf, boundary_buf_size,
 *                      ct_var, body_var)
 *
 *   ct_var   — name for the char* Content-Type string (freed at scope exit).
 *   body_var — name for the StrSlice holding the raw request body.
 *
 *   Example:
 *     MultipartForm form = {0};
 *     parse_multipart_form(conn, &form, content_type, body);
 *
 *     // Both names are usable after the macro:
 *     printf("Content-Type: %s\n", content_type);
 *     printf("Body length:  %zu\n", body.len);
 */
#define parse_multipart_form(conn, form_ptr, content_type, body_var)                            \
    char boundary_buf[256] = {0};                                                               \
    MultipartCode mc = multipart_init((form_ptr));                                              \
    const char* me = multipart_error(mc);                                                       \
    abort_if(mc != MULTIPART_OK, (conn), StatusBadRequest, me, strlen(me));                     \
    defer_form_cleanup(form_ptr);                                                               \
    const char* content_type = req_header_get((conn), "Content-Type");                          \
    abort_if_lit(!parse_boundary(content_type, boundary_buf, sizeof(boundary_buf)), (conn),     \
                 StatusBadRequest, "invalid or missing multipart boundary");                    \
    StrSlice body_var = req_body_slice(conn);                                                   \
    MultipartCode mc2 = multipart_parse(body_var.data, body_var.len, boundary_buf, (form_ptr)); \
    const char* me2 = multipart_error(mc2);                                                     \
    abort_if(mc2 != MULTIPART_OK, (conn), StatusBadRequest, me2, strlen(me2))
