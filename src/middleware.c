#include "internal.h"

/* ================================================================
 * Middleware Registry
 *
 * Registration lives here; execution (execute_all_middleware) is INLINE in
 * the core request path and reads the exported registry below.
 * ================================================================ */

HttpHandler global_middleware[MAX_GLOBAL_MIDDLEWARE] = {0};
size_t global_mw_count = 0;
void* g_handler_userdata = NULL;

void use_global_middleware(HttpHandler* mw, size_t count) {
    ASSERT(count + global_mw_count <= MAX_GLOBAL_MIDDLEWARE);
    for (size_t i = 0; i < count; i++) {
        global_middleware[global_mw_count++] = mw[i];
    }
}

void use_route_middleware(route_t* route, HttpHandler* mw, size_t count) {
    ASSERT(route->mw_count + count <= MAX_ROUTE_MIDDLEWARE);
    for (size_t i = 0; i < count; i++) {
        route->middleware[route->mw_count++] = mw[i];
    }
}

void pulsar_set_handler_userdata(void* userdata) { g_handler_userdata = userdata; }
void* pulsar_get_handler_userdata(void) { return g_handler_userdata; }
