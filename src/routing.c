/**
 * High-performance, Thread-Safe Radix router with O(1) exact lookup.
 *
 * Thread Safety & Concurrency
 * ---------------------------
 * - All global routing structures are read-only post-startup.
 * - Per-method structures are 64-byte cacheline-aLIGN.
 * - Parameter matching allocates the returned route_t and PathParams
 *   strictly from the caller's per-request Arena. No shared memory is
 *   ever mutated during route_match().
 */

#include "../include/routing.h"

#include <solidc/arena.h>
#include <solidc/filepath.h>
#include <solidc/macros.h>  // for ASSERT

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <solidc/align.h>
#include "../include/method.h"

extern void static_file_handler(PulsarCtx* ctx);

#define CACHELINE_SIZE       64
#define MAX_PARAMS_PER_ROUTE 8

/*
 * ------------------------------------------------------------------------
 * Fast FNV-1a Hash
 * ------------------------------------------------------------------------
 */

#define FNV_OFFSET_BASIS_64 14695981039346656037ULL
#define FNV_PRIME_64        1099511628211ULL

INLINE uint64_t hash_path(const char* path, size_t len) {
    uint64_t hash = FNV_OFFSET_BASIS_64;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint64_t)(uint8_t)path[i];
        hash *= FNV_PRIME_64;
    }
    return hash;
}

/*
 * ------------------------------------------------------------------------
 * Exact Route Hash Table
 * ------------------------------------------------------------------------
 */

typedef struct ExactRouteEntry {
    uint64_t hash;
    const route_t* route;
} ExactRouteEntry;

typedef struct ExactRouteTable {
    ExactRouteEntry* entries;
    size_t capacity;
    size_t mask;
    size_t count;
} ExactRouteTable;

/*
 * ------------------------------------------------------------------------
 * Radix Tree Structures
 * ------------------------------------------------------------------------
 */

typedef enum NodeKind {
    NODE_LITERAL = 0,
    NODE_PARAM,
} NodeKind;

typedef struct RadixNode {
    NodeKind kind;
    char* edge;
    uint16_t edge_len;

    char* param_name;
    uint16_t param_name_len;

    const route_t* route;
    struct RadixNode* param_child;

    char* indices;
    struct RadixNode** children;
    uint16_t child_count;
    uint16_t child_capacity;
} RadixNode;

/*
 * ------------------------------------------------------------------------
 * Cache-ALIGN Per-Method Routing State
 * ------------------------------------------------------------------------
 * Grouping all lookup data for a method into a 64-byte aLIGN struct prevents
 * cacheline straddling and eliminates any possibility of false sharing.
 */

typedef struct ALIGN(CACHELINE_SIZE) MethodRouter {
    const route_t* fast_root;
    ExactRouteTable exact_table;
    RadixNode* radix_root;
    route_t** static_routes;
    size_t static_route_count;
} MethodRouter;

static MethodRouter method_routers[HTTP_METHOD_COUNT] ALIGN(CACHELINE_SIZE) = {0};

/** Master list of routes created at registration */
static route_t** global_routes = NULL;
static size_t global_route_capacity = 0;

// Total number of registered global routes.
// This MUST be exported for use by cgo.
size_t global_route_count = 0;
/*
 * ------------------------------------------------------------------------
 * Helpers & Tree Construction
 * ------------------------------------------------------------------------
 */

static size_t count_path_params(const char* pattern, bool* valid) {
    const char* p = pattern;
    size_t count = 0;
    *valid = true;

    while (*p) {
        if (*p == '{') {
            p++;
            while (*p && *p != '}') {
                if (*p == '{') {
                    *valid = false;
                    return 0;
                }
                p++;
            }
            if (*p != '}') {
                *valid = false;
                return 0;
            }
            count++;
            p++;
        } else if (*p == '}') {
            *valid = false;
            return 0;
        } else {
            p++;
        }
    }
    return count;
}

static RadixNode* radix_node_create(NodeKind kind) {
    RadixNode* node = (RadixNode*)calloc(1, sizeof(RadixNode));
    if (unlikely(node == NULL)) {
        ASSERT(node != NULL && "Failed to allocate RadixNode");
    }
    node->kind = kind;
    return node;
}

static size_t common_prefix_len(const char* a, const char* b, size_t max) {
    size_t i = 0;
    while (i < max && a[i] == b[i]) {
        i++;
    }
    return i;
}

static void radix_node_add_literal_child(RadixNode* parent, RadixNode* child) {
    ASSERT(child->edge_len > 0 && "Literal child must have non-empty edge");

    if (parent->child_count >= parent->child_capacity) {
        size_t new_cap = parent->child_capacity == 0 ? 4 : (size_t)parent->child_capacity * 2;
        char* new_indices = (char*)realloc(parent->indices, new_cap);
        ASSERT(new_indices != NULL && "Failed to grow node indices");

        RadixNode** new_children =
            (RadixNode**)realloc(parent->children, new_cap * sizeof(RadixNode*));
        ASSERT(new_children != NULL && "Failed to grow node children");

        parent->indices = new_indices;
        parent->children = new_children;
        parent->child_capacity = (uint16_t)new_cap;
    }

    parent->indices[parent->child_count] = child->edge[0];
    parent->children[parent->child_count] = child;
    parent->child_count++;
}

static RadixNode* radix_find_literal_child(const RadixNode* parent, char c, uint16_t* index_out) {
    for (uint16_t i = 0; i < parent->child_count; i++) {
        if (parent->indices[i] == c) {
            if (index_out) *index_out = i;
            return parent->children[i];
        }
    }
    return NULL;
}

static void radix_node_split(RadixNode* node, size_t at) {
    ASSERT(at > 0 && at < node->edge_len && "Invalid split point");

    RadixNode* tail = radix_node_create(NODE_LITERAL);
    tail->edge_len = (uint16_t)(node->edge_len - at);
    tail->edge = (char*)malloc(tail->edge_len + 1);
    ASSERT(tail->edge != NULL && "Edge allocation failed");
    memcpy(tail->edge, node->edge + at, tail->edge_len);
    tail->edge[tail->edge_len] = '\0';

    // Transfer state and child arrays to tail
    tail->route = node->route;
    tail->param_child = node->param_child;
    tail->child_count = node->child_count;
    tail->child_capacity = node->child_capacity;
    tail->children = node->children;
    tail->indices = node->indices;

    // Shrink edge in parent
    char* shrunk_edge = (char*)malloc(at + 1);
    ASSERT(shrunk_edge != NULL && "Edge allocation failed");
    memcpy(shrunk_edge, node->edge, at);
    shrunk_edge[at] = '\0';

    free(node->edge);
    node->edge = shrunk_edge;
    node->edge_len = (uint16_t)at;
    node->route = NULL;
    node->param_child = NULL;
    node->child_count = 0;
    node->child_capacity = 0;
    node->children = NULL;
    node->indices = NULL;

    radix_node_add_literal_child(node, tail);
}

static void radix_insert(RadixNode* root, const char* pattern, const route_t* r) {
    if (*pattern == '\0') {
        ASSERT(root->route == NULL && "Duplicate route registered");
        root->route = r;
        return;
    }

    if (*pattern == '{') {
        const char* name_start = pattern + 1;
        const char* end = strchr(name_start, '}');
        ASSERT(end != NULL && "Malformed parameter in pattern");
        size_t name_len = (size_t)(end - name_start);
        const char* rest = end + 1;

        if (root->param_child == NULL) {
            RadixNode* pnode = radix_node_create(NODE_PARAM);
            pnode->param_name = (char*)name_start;
            pnode->param_name_len = (uint16_t)name_len;
            root->param_child = pnode;
        }
        radix_insert(root->param_child, rest, r);
        return;
    }

    uint16_t child_idx = 0;
    RadixNode* child = radix_find_literal_child(root, pattern[0], &child_idx);
    if (child == NULL) {
        const char* stop = strchr(pattern, '{');
        size_t lit_len = stop ? (size_t)(stop - pattern) : strlen(pattern);

        RadixNode* node = radix_node_create(NODE_LITERAL);
        node->edge_len = (uint16_t)lit_len;
        node->edge = (char*)malloc(lit_len + 1);
        ASSERT(node->edge != NULL && "Edge allocation failed");
        memcpy(node->edge, pattern, lit_len);
        node->edge[lit_len] = '\0';

        radix_node_add_literal_child(root, node);
        radix_insert(node, pattern + lit_len, r);
        return;
    }

    size_t rem = strlen(pattern);
    size_t max_shared = rem < child->edge_len ? rem : child->edge_len;
    size_t shared = common_prefix_len(pattern, child->edge, max_shared);

    const char* brace = (const char*)memchr(pattern, '{', shared);
    if (brace) {
        shared = (size_t)(brace - pattern);
    }

    if (shared < child->edge_len) {
        radix_node_split(child, shared);
    }
    radix_insert(child, pattern + shared, r);
}

/*
 * ------------------------------------------------------------------------
 * Exact Route Table
 * ------------------------------------------------------------------------
 */

static void exact_table_init(ExactRouteTable* table, size_t min_capacity) {
    size_t cap = 16;
    while (cap < min_capacity * 2) {
        cap <<= 1;
    }
    table->capacity = cap;
    table->mask = cap - 1;
    table->entries = (ExactRouteEntry*)calloc(cap, sizeof(ExactRouteEntry));
    ASSERT(table->entries != NULL && "Exact route table allocation failed");
    table->count = 0;
}

static void exact_table_insert(ExactRouteTable* table, const route_t* r) {
    uint64_t hash = hash_path(r->pattern, r->pattern_len);
    size_t idx = (size_t)(hash & table->mask);

    while (table->entries[idx].route != NULL) {
        idx = (idx + 1) & table->mask;
    }

    table->entries[idx].hash = hash;
    table->entries[idx].route = r;
    table->count++;
}

INLINE const route_t* exact_table_lookup(const ExactRouteTable* table, const char* path,
                                         size_t len) {
    if (unlikely(table->entries == NULL)) return NULL;

    uint64_t hash = hash_path(path, len);
    size_t idx = (size_t)(hash & table->mask);

    while (table->entries[idx].route != NULL) {
        if (table->entries[idx].hash == hash) {
            const route_t* r = table->entries[idx].route;
            if (r->pattern_len == len && memcmp(r->pattern, path, len) == 0) {
                return r;
            }
        }
        idx = (idx + 1) & table->mask;
    }
    return NULL;
}

/*
 * ------------------------------------------------------------------------
 * Public API: Registration
 * ------------------------------------------------------------------------
 */

static route_t* route_register_helper(const char* pattern, HttpMethod method, HttpHandler handler,
                                      int is_static) {
    ASSERT(METHOD_VALID(method) && "Invalid HTTP method");
    ASSERT(pattern && handler && "pattern and handler must not be NULL");

    if (global_route_count >= global_route_capacity) {
        size_t new_cap = global_route_capacity == 0 ? 64 : global_route_capacity * 2;
        route_t** new_routes = (route_t**)realloc(global_routes, new_cap * sizeof(route_t*));
        ASSERT(new_routes != NULL && "Failed to grow global route list");
        global_routes = new_routes;
        global_route_capacity = new_cap;
    }

    route_t* r = (route_t*)calloc(1, sizeof(route_t));
    ASSERT(r != NULL && "Failed to allocate route_t");

    *r = (route_t){
        .pattern = pattern,
        .pattern_len = (uint16_t)strlen(pattern),
        .method = method,
        .handler = handler,
    };
    global_routes[global_route_count++] = r;

    if (is_static) {
        r->route_type = ROUTE_TYPE_STATIC;
        return r;
    }

    bool valid = true;
    size_t nparams = count_path_params(pattern, &valid);
    ASSERT(valid && "Invalid path parameters in pattern");
    ASSERT(nparams <= MAX_PARAMS_PER_ROUTE && "Too many {params} in pattern");
    r->route_type = (nparams > 0) ? ROUTE_TYPE_PARAM : ROUTE_TYPE_EXACT;

    if (r->route_type == ROUTE_TYPE_PARAM) {
        // Metadata template stored in the global route: contains param names only.
        // Dynamic values are written into per-request arena instances during match.
        r->state.path_params = (PathParams*)malloc(sizeof(PathParams));
        ASSERT(r->state.path_params && "Failed to allocate PathParams template");
        r->state.path_params->items = (PathParam*)calloc(nparams, sizeof(PathParam));
        ASSERT(r->state.path_params->items && "Failed to allocate PathParam items");
        r->state.path_params->total_params = (uint8_t)nparams;
        r->state.path_params->match_count = 0;

        const char* p = pattern;
        uint8_t idx = 0;
        while (*p && idx < nparams) {
            if (*p != '{') {
                p++;
                continue;
            }
            p++;
            const char* name_start = p;
            while (*p && *p != '}') p++;
            r->state.path_params->items[idx].name = (char*)name_start;
            r->state.path_params->items[idx].name_len = (size_t)(p - name_start);
            p++;
            idx++;
        }
    }

    return r;
}

route_t* route_register(const char* pattern, HttpMethod method, HttpHandler handler) {
    return route_register_helper(pattern, method, handler, 0);
}

route_t* route_static(const char* pattern, const char* dirname) {
    ASSERT(pattern && dirname && "pattern and dirname must be non-NULL");
    ASSERT(is_dir(dirname) && "dir must be an existing directory");

    route_t* r = route_register_helper(pattern, HTTP_GET, static_file_handler, 1);
    r->state.static_.dirname = dirname;
    r->state.static_.dirname_len = (uint8_t)strlen(dirname);
    return r;
}

/*
 * ------------------------------------------------------------------------
 * Public API: Build
 * ------------------------------------------------------------------------
 */

void sort_routes(void) {
    static int built = 0;
    if (built || global_route_count == 0) return;

    size_t exact_counts[HTTP_METHOD_COUNT] = {0};
    size_t static_counts[HTTP_METHOD_COUNT] = {0};

    for (size_t m = 0; m < HTTP_METHOD_COUNT; m++) {
        method_routers[m].radix_root = radix_node_create(NODE_LITERAL);
        method_routers[m].fast_root = NULL;
    }

    for (size_t i = 0; i < global_route_count; i++) {
        const route_t* r = global_routes[i];
        if (r->route_type == ROUTE_TYPE_EXACT) {
            exact_counts[r->method]++;
        } else if (r->route_type == ROUTE_TYPE_STATIC) {
            static_counts[r->method]++;
        }
    }

    for (size_t m = 0; m < HTTP_METHOD_COUNT; m++) {
        if (exact_counts[m] > 0) {
            exact_table_init(&method_routers[m].exact_table, exact_counts[m]);
        }
        if (static_counts[m] > 0) {
            method_routers[m].static_routes =
                (route_t**)malloc(static_counts[m] * sizeof(route_t*));
            ASSERT(method_routers[m].static_routes && "Failed to allocate static routes array");
        }
        method_routers[m].static_route_count = 0;
    }

    for (size_t i = 0; i < global_route_count; i++) {
        route_t* r = global_routes[i];

        if (r->pattern_len == 1 && r->pattern[0] == '/' && r->route_type == ROUTE_TYPE_EXACT) {
            method_routers[r->method].fast_root = r;
        }

        if (r->route_type == ROUTE_TYPE_STATIC) {
            size_t idx = method_routers[r->method].static_route_count++;
            method_routers[r->method].static_routes[idx] = r;
            continue;
        }

        if (r->route_type == ROUTE_TYPE_EXACT) {
            exact_table_insert(&method_routers[r->method].exact_table, r);
        }

        radix_insert(method_routers[r->method].radix_root, r->pattern, r);
    }

    // Sort static routes descending by length for longest-prefix match
    for (size_t m = 0; m < HTTP_METHOD_COUNT; m++) {
        MethodRouter* mr = &method_routers[m];
        for (size_t i = 1; i < mr->static_route_count; i++) {
            route_t* key = mr->static_routes[i];
            size_t j = i;
            while (j > 0 && mr->static_routes[j - 1]->pattern_len < key->pattern_len) {
                mr->static_routes[j] = mr->static_routes[j - 1];
                j--;
            }
            mr->static_routes[j] = key;
        }
    }

    if (method_routers[HTTP_HEAD].fast_root == NULL && method_routers[HTTP_GET].fast_root != NULL) {
        method_routers[HTTP_HEAD].fast_root = method_routers[HTTP_GET].fast_root;
    }

    built = 1;
}

/*
 * ------------------------------------------------------------------------
 * Public API: Matching
 * ------------------------------------------------------------------------
 */

static route_t* match_static(HttpMethod method, const char* path, size_t path_len) {
    const MethodRouter* mr = &method_routers[method];
    route_t** routes = mr->static_routes;
    const size_t count = mr->static_route_count;

    for (size_t i = 0; i < count; i++) {
        route_t* r = routes[i];
        if (r->pattern_len <= path_len && memcmp(r->pattern, path, r->pattern_len) == 0) {
            return r;
        }
    }
    return NULL;
}

typedef struct CapturedParam {
    const char* value;
    size_t value_len;
} CapturedParam;

static const route_t* radix_match_param(const RadixNode* root, const char* path, size_t path_len,
                                        CapturedParam* captured, uint8_t* depth) {
    if (path_len == 0) {
        return root->route;
    }

    char first = path[0];

    // Check literal child using cached indices
    if (root->child_count > 0) {
        const char* match = (const char*)memchr(root->indices, first, root->child_count);
        if (match != NULL) {
            size_t idx = (size_t)(match - root->indices);
            const RadixNode* child = root->children[idx];
            if (child->edge_len <= path_len && memcmp(child->edge, path, child->edge_len) == 0) {
                const route_t* found = radix_match_param(
                    child, path + child->edge_len, path_len - child->edge_len, captured, depth);
                if (found) return found;
            }
        }
    }

    // Try dedicated param child if literal branch missed or failed
    if (root->param_child != NULL) {
        const char* p = (const char*)memchr(path, '/', path_len);
        size_t seg_len = p ? (size_t)(p - path) : path_len;

        if (seg_len > 0) {
            ASSERT(*depth < MAX_PARAMS_PER_ROUTE && "Too many parameters in path");
            captured[*depth] = (CapturedParam){.value = path, .value_len = seg_len};
            (*depth)++;

            const route_t* found = radix_match_param(root->param_child, path + seg_len,
                                                     path_len - seg_len, captured, depth);
            if (found) return found;

            (*depth)--;
        }
    }

    return NULL;
}

/**
 * Thread-safe param tree match.
 *
 * Captures parameter values and instantiates a request-local route_t and
 * PathParams in the per-request Arena. The global route template is never modified.
 */
static route_t* match_method_tree(HttpMethod method, const char* path, size_t path_len,
                                  Arena* arena) {
    const RadixNode* root = method_routers[method].radix_root;
    if (root == NULL) return NULL;

    CapturedParam captured[MAX_PARAMS_PER_ROUTE];
    uint8_t depth = 0;
    const route_t* template = radix_match_param(root, path, path_len, captured, &depth);
    if (template == NULL) return NULL;

    if (template->route_type != ROUTE_TYPE_PARAM) {
        return (route_t*)template;
    }

    // Allocate request-local route_t copy in the Arena
    route_t* req_route = (route_t*)arena_alloc(arena, sizeof(route_t));
    if (unlikely(req_route == NULL)) return NULL;
    *req_route = *template;

    // Allocate request-local PathParams container
    PathParams* pp = (PathParams*)arena_alloc(arena, sizeof(PathParams));
    if (unlikely(pp == NULL)) return NULL;

    PathParam* items = (PathParam*)arena_alloc(arena, depth * sizeof(PathParam));
    if (unlikely(items == NULL)) return NULL;

    const PathParams* tmpl_pp = template->state.path_params;
    ASSERT(depth == tmpl_pp->total_params && "Parameter count mismatch");

    for (uint8_t i = 0; i < depth; i++) {
        char* value = arena_strdupn(arena, captured[i].value, captured[i].value_len);
        if (unlikely(value == NULL)) return NULL;

        items[i].name = tmpl_pp->items[i].name;
        items[i].name_len = tmpl_pp->items[i].name_len;
        items[i].value = value;
        items[i].value_len = captured[i].value_len;
    }

    pp->items = items;
    pp->total_params = depth;
    pp->match_count = depth;
    req_route->state.path_params = pp;

    return req_route;
}

route_t* route_match(const char* path, size_t url_length, HttpMethod method, Arena* arena) {
    // 1. Root "/" fast path
    if (likely(url_length == 1 && path[0] == '/')) {
        if (likely((unsigned)method < HTTP_METHOD_COUNT)) {
            const route_t* r = method_routers[method].fast_root;
            if (likely(r != NULL)) return (route_t*)r;
        }
    }

    if (unlikely((unsigned)method >= HTTP_METHOD_COUNT)) return NULL;

    // 2. Direct O(1) Exact Route Match
    const route_t* found =
        exact_table_lookup(&method_routers[method].exact_table, path, url_length);
    if (likely(found != NULL)) return (route_t*)found;

    // 3. Dynamic Parameter Match (allocates result into arena)
    route_t* dynamic_match = match_method_tree(method, path, url_length, arena);
    if (dynamic_match) return dynamic_match;

    // 4. Static Directory Match
    found = match_static(method, path, url_length);
    if (found) return (route_t*)found;

    // 5. Fallback for HEAD requests
    if (method == HTTP_HEAD) {
        found = exact_table_lookup(&method_routers[HTTP_GET].exact_table, path, url_length);
        if (found) return (route_t*)found;

        dynamic_match = match_method_tree(HTTP_GET, path, url_length, arena);
        if (dynamic_match) return dynamic_match;

        return match_static(HTTP_GET, path, url_length);
    }

    // 6. Fallback for OPTIONS requests
    if (method == HTTP_OPTIONS) {
        for (size_t m = 0; m < HTTP_METHOD_COUNT; m++) {
            found = exact_table_lookup(&method_routers[m].exact_table, path, url_length);
            if (found) return (route_t*)found;
        }
        for (size_t m = 0; m < HTTP_METHOD_COUNT; m++) {
            dynamic_match = match_method_tree((HttpMethod)m, path, url_length, arena);
            if (dynamic_match) return dynamic_match;
        }
        for (size_t m = 0; m < HTTP_METHOD_COUNT; m++) {
            found = match_static((HttpMethod)m, path, url_length);
            if (found) return (route_t*)found;
        }
    }

    return NULL;
}

/*
 * ------------------------------------------------------------------------
 * Cleanup
 * ------------------------------------------------------------------------
 */

static void radix_node_free(RadixNode* node) {
    if (node == NULL) return;
    for (uint16_t i = 0; i < node->child_count; i++) {
        radix_node_free(node->children[i]);
    }
    radix_node_free(node->param_child);
    free(node->children);
    free(node->indices);
    free(node->edge);
    free(node);
}

__attribute__((destructor)) void routing_radix_cleanup(void) {
    for (size_t m = 0; m < HTTP_METHOD_COUNT; m++) {
        radix_node_free(method_routers[m].radix_root);
        method_routers[m].radix_root = NULL;

        free(method_routers[m].exact_table.entries);
        method_routers[m].exact_table.entries = NULL;

        free(method_routers[m].static_routes);
        method_routers[m].static_routes = NULL;
        method_routers[m].static_route_count = 0;
    }
    for (size_t i = 0; i < global_route_count; i++) {
        route_t* r = global_routes[i];
        if (r->route_type == ROUTE_TYPE_PARAM && r->state.path_params) {
            free(r->state.path_params->items);
            free(r->state.path_params);
        }
        free(r);
    }
    free(global_routes);
    global_routes = NULL;
    global_route_count = 0;
    global_route_capacity = 0;
}
