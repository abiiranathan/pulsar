#include "internal.h"

/* ================================================================
 * Request-Scoped Context & Arena API
 * ================================================================ */

Arena* pulsar_get_arena(PulsarConn* conn) { return conn->arena; }

void* pulsar_alloc(PulsarConn* conn, size_t sz) { return arena_alloc(conn->arena, sz); }

void* pulsar_get(PulsarConn* conn, const char* k) {
    // Return saved context value
    return locals_getvalue(&conn->locals, k);
}

bool pulsar_set(PulsarConn* conn, const char* key, void* value, ValueFreeFunc free_func) {
    // Store context value.
    return locals_setvalue(&conn->locals, key, value, free_func);
}

void pulsar_delete(PulsarConn* conn, const char* k) {
    // Delete context value
    locals_remove(&conn->locals, k);
}
