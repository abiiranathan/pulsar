#ifndef PULSAR_GO_BRIDGE_H
#define PULSAR_GO_BRIDGE_H

#include <stddef.h>
#include <stdint.h>
#include "../include/forms.h"
#include "../include/pulsar.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Exported Go dispatcher receiving only the route ID (O(1) index) */
extern void goPulsarDispatcher(PulsarConn* conn, int route_id);

/* C trampoline that delegates matched routes to Go (O(1), no lookup) */
void pulsar_c_trampoline(PulsarCtx* ctx);

/* Bridge registration functions */
int pulsar_bridge_add_route(int method, const char* pattern, int route_id);
int pulsar_bridge_add_static(const char* pattern, const char* dirname);

/* Returns non-zero if conn_abort() was called on this connection. */
int bridge_is_aborted(PulsarConn* conn);

/* Access logger: installs the builtin pulsar_logger */
int pulsar_bridge_set_logger(int fd);

/* Zero-allocation Path Parameter helpers */
int bridge_get_path_param(PulsarConn* conn, const char* name, size_t name_len,
                          const char** out_data, size_t* out_len);

size_t bridge_get_path_params_count(PulsarConn* conn);

void bridge_get_path_param_at(PulsarConn* conn, size_t idx, const char** name, size_t* name_len,
                              const char** val, size_t* val_len);

/* Zero-allocation Query & Header slice helpers */
int bridge_query_get(PulsarConn* conn, const char* name, size_t name_len, const char** out_data,
                     size_t* out_len);
int bridge_req_header_get(PulsarConn* conn, const char* name, size_t name_len,
                          const char** out_data, size_t* out_len);

/* Enumeration helpers for query params and request headers.
 * Each entry is returned as a (pointer, length) view into the connection's
 * request-scoped storage. Views are valid only for the current request. */
size_t bridge_query_count(PulsarConn* conn);
int bridge_query_at(PulsarConn* conn, size_t idx, const char** name, size_t* name_len,
                    const char** val, size_t* val_len);
size_t bridge_req_headers_count(PulsarConn* conn);
int bridge_req_header_at(PulsarConn* conn, size_t idx, const char** name, size_t* name_len,
                         const char** val, size_t* val_len);

/* Request metadata views. Returned pointers are request-scoped. */
int bridge_route_pattern(PulsarConn* conn, const char** out_data, size_t* out_len);
size_t bridge_content_length(PulsarConn* conn);

/* Multipart form support (see forms.h).
 *
 * bridge_parse_multipart() heap-allocates a MultipartForm, parses the
 * current request body into it, and returns it via out_form. The caller
 * owns the result and must release it with bridge_free_multipart().
 * File payloads are NOT copied: each FileHeader records an offset/size
 * window into the request body (see bridge_form_file_at()).
 *
 * Returns 0 on success. On failure returns -1 with out_code/out_msg
 * describing the MultipartCode failure (out_msg points at a static string).
 */
int bridge_parse_multipart(PulsarConn* conn, MultipartForm** out_form, int* out_code,
                           const char** out_msg);
size_t bridge_form_num_fields(MultipartForm* form);
size_t bridge_form_num_files(MultipartForm* form);
int bridge_form_field_at(MultipartForm* form, size_t idx, const char** name, size_t* name_len,
                         const char** val, size_t* val_len);
int bridge_form_file_at(MultipartForm* form, size_t idx, const char** field, size_t* field_len,
                        const char** filename, size_t* filename_len, const char** mimetype,
                        size_t* mimetype_len, size_t* offset, size_t* size);
void bridge_free_multipart(MultipartForm* form);
const char* bridge_multipart_error(int code);

#ifdef __cplusplus
}
#endif

#endif /* PULSAR_GO_BRIDGE_H */
