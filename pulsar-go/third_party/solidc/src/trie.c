#include "../include/trie.h"

#include "../include/arena.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * Internal node definition
 * ========================================================================= */

/* Child-pointer offset inside a heap blob of capacity @p na. */
#define TRIE_CHILD_OFF(na) ((((size_t)(na)) + 7u) & ~(size_t)7u)

/*
 * Inline-first fan-out storage (SSO-style, Perf #13):
 *
 * Most trie nodes hold only a handful of children.  When capacity <=
 * TRIE_INLINE_CAP the sorted key bytes and child pointers live INSIDE the
 * node itself (ichars / ichild) — a whole trie hop then touches one cache
 * line and costs zero heap allocations.
 *
 * Beyond that capacity, storage moves to an arena-allocated blob laid out
 * as [ chars | pad to 8 | children* ].  The arena has no realloc: growth
 * allocates a fresh chunk and abandons the old one to be reclaimed at
 * trie_destroy().  Abandoned space forms a geometric series bounded by ~2x
 * the final size — exactly the trade-off arenas are designed for.
 */
#define TRIE_INLINE_CAP 4

typedef struct trie_node {
    uint16_t nchildren;
    uint8_t nalloc; /* TRIE_INLINE_CAP when inline; blob capacity otherwise */
    bool is_heap;   /* false: inline storage, true: arena blob              */
    bool is_end_of_word;
    uint32_t frequency;
    void* blob; /* heap/arena storage when is_heap                      */
    uint8_t ichars[TRIE_INLINE_CAP];
    struct trie_node* ichild[TRIE_INLINE_CAP];
} trie_node;

/** Const is dropped deliberately: search paths only read through these,
 * while insert paths need mutable access to the same storage. */
static inline uint8_t* node_chars(const trie_node* n) { return n->is_heap ? (uint8_t*)n->blob : (uint8_t*)n->ichars; }

static inline trie_node** node_children(const trie_node* n) {
    /* Heap blobs are laid out [chars | pad | children]: the pointer array
     * starts at the aligned offset, not at blob+0. */
    return n->is_heap ? (trie_node**)((char*)n->blob + TRIE_CHILD_OFF(n->nalloc)) : (trie_node**)n->ichild;
}

typedef struct _trie {
    trie_node* root;
    size_t word_count;
    Arena* arena; /* owns every node struct and overflow blob */
} trie_t;

/* =========================================================================
 * Node lifecycle
 * ========================================================================= */

/** Allocate a zeroed node from the trie's arena. */
static trie_node* node_alloc(trie_t* t) { return (trie_node*)arena_alloc_zero(t->arena, sizeof(trie_node)); }

/**
 * Grows the node's child storage to @p want slots.
 *
 * Storage ladder: inline (TRIE_INLINE_CAP) -> arena blob -> doubled arena
 * blobs.  The arena has no realloc, so each grow allocates a fresh chunk,
 * copies the live entries, and abandons the old storage until destroy.
 * Abandoned chunks form a geometric series bounded by ~2x final size.
 *
 * @p want must be greater than the current capacity; callers double.
 */
static bool node_reserve(trie_t* t, trie_node* n, uint8_t want) {
    void* nb = arena_alloc(t->arena, TRIE_CHILD_OFF(want) + (size_t)want * sizeof(trie_node*));
    if (!nb) {
        return false;
    }

    uint8_t* new_chars = (uint8_t*)nb;
    trie_node** new_children = (trie_node**)((char*)nb + TRIE_CHILD_OFF(want));

    if (n->is_heap) {
        memcpy(new_chars, n->blob, (size_t)n->nchildren);
        memcpy(new_children, (char*)n->blob + TRIE_CHILD_OFF(n->nalloc), (size_t)n->nchildren * sizeof(trie_node*));
    } else {
        memcpy(new_chars, n->ichars, (size_t)n->nchildren);
        memcpy(new_children, n->ichild, (size_t)n->nchildren * sizeof(trie_node*));
    }

    n->blob = nb;
    n->is_heap = true;
    n->nalloc = want;
    return true;
}

/* =========================================================================
 * Child lookup (hybrid linear/binary search on sorted chars[])
 * ========================================================================= */

/**
 * Returns the index of `c` in the node's sorted key bytes, or -1.
 * Linear scan for small fan-out (branch-predictable, no mid computation),
 * binary search once the child count makes it worthwhile.
 */
static inline int child_index(const trie_node* n, uint8_t c) {
    const uint8_t nc = n->nchildren;
    if (nc == 0) {
        return -1;
    }

    const uint8_t* ch = node_chars(n);
    if (nc <= 8) {
        for (uint8_t i = 0; i < nc; i++) {
            if (ch[i] == c) {
                return i;
            }
        }
        return -1;
    }

    int lo = 0, hi = (int)nc - 1;
    while (lo <= hi) {
        int mid = (lo + hi) >> 1;
        if (ch[mid] == c)
            return mid;
        else if (ch[mid] < c)
            lo = mid + 1;
        else
            hi = mid - 1;
    }
    return -1;
}

/**
 * Find or create a child for byte `c` under parent `n`.
 * On insert the packed blob grows by doubling (chars stay at offset 0;
 * the children pointer array is moved to its new aligned offset).
 *
 * Realloc safety: the blob is committed to the node immediately; a failed
 * grow simply leaves capacity larger than nalloc records — retried
 * cleanly by the next call.  (Previously a partial two-array realloc
 * failure freed the new chars buffer while the node still pointed at the
 * freed old one.)
 */
static trie_node* child_find_or_create(trie_t* t, trie_node* n, uint8_t c) {
    int idx = child_index(n, c);
    if (idx >= 0) return node_children(n)[idx];

    /* Need to insert a new child.  Grow storage when full:
     *   inline (4) -> arena blob (8) -> doubled blobs -> cap 255. */
    {
        uint8_t cur_cap = n->is_heap ? n->nalloc : TRIE_INLINE_CAP;
        if (n->nchildren == cur_cap) {
            uint32_t want = (uint32_t)cur_cap * 2;
            if (want > 255) want = 255;
            if ((uint8_t)want == cur_cap) {
                return NULL; /* hard cap */
            }
            if (!node_reserve(t, n, (uint8_t)want)) {
                return NULL;
            }
        }
    }

    /* Insertion sort: find where `c` belongs, shift right.
     * NOTE: plain int — an int8_t here overflowed for fan-outs > 127,
     * reachable with arbitrary byte keys (corruption bug). */
    int pos = (int)n->nchildren;
    uint8_t* ch = node_chars(n);
    trie_node** cp = node_children(n);
    while (pos > 0 && ch[pos - 1] > c) {
        ch[pos] = ch[pos - 1];
        cp[pos] = cp[pos - 1];
        pos--;
    }

    trie_node* child = node_alloc(t);
    if (!child) return NULL;

    ch[pos] = c;
    cp[pos] = child;
    n->nchildren++;
    return child;
}

/* =========================================================================
 * Public API
 * ========================================================================= */

trie_t* trie_create(void) {
    trie_t* t = (trie_t*)calloc(1, sizeof(trie_t));
    if (!t) return NULL;

    /*
     * All nodes and overflow blobs live in one arena.  Trie nodes are
     * never individually freed (trie_delete only unmarks words), so
     * teardown is a single arena_destroy() — no recursive subtree walk,
     * no per-node free, no stack-overflow risk on deep tries.
     */
    t->arena = arena_create(0);
    if (!t->arena) {
        free(t);
        return NULL;
    }

    t->root = node_alloc(t);
    if (!t->root) {
        arena_destroy(t->arena);
        free(t);
        return NULL;
    }
    return t;
}

void trie_destroy(trie_t* t) {
    if (!t) return;
    arena_destroy(t->arena);
    free(t);
}

bool trie_insert(trie_t* t, const char* word) {
    if (!t || !word || !*word) return false;

    trie_node* cur = t->root;
    for (const uint8_t* p = (const uint8_t*)word; *p; p++) {
        cur = child_find_or_create(t, cur, *p);
        if (!cur) return false;
    }

    if (!cur->is_end_of_word) {
        cur->is_end_of_word = true;
        t->word_count++;
    }
    cur->frequency++;
    return true;
}

bool trie_search(const trie_t* t, const char* word) {
    if (!t || !word || !*word) return false;

    const trie_node* cur = t->root;
    for (const uint8_t* p = (const uint8_t*)word; *p; p++) {
        int idx = child_index(cur, *p);
        if (idx < 0) return false;
        cur = node_children(cur)[idx];
    }
    return cur->is_end_of_word;
}

bool trie_starts_with(const trie_t* t, const char* prefix) {
    if (!t || !prefix || !*prefix) return false;

    const trie_node* cur = t->root;
    for (const uint8_t* p = (const uint8_t*)prefix; *p; p++) {
        int idx = child_index(cur, *p);
        if (idx < 0) return false;
        cur = node_children(cur)[idx];
    }
    return true;
}

bool trie_delete(trie_t* t, const char* word) {
    if (!t || !word || !*word) return false;

    const trie_node* cur = t->root;
    for (const uint8_t* p = (const uint8_t*)word; *p; p++) {
        int idx = child_index(cur, *p);
        if (idx < 0) return false;
        cur = node_children(cur)[idx];
    }

    if (!cur->is_end_of_word) return false;
    ((trie_node*)cur)->is_end_of_word = false;
    ((trie_node*)cur)->frequency = 0;
    t->word_count--;
    return true;
}

uint32_t trie_get_frequency(const trie_t* t, const char* word) {
    if (!t || !word || !*word) return 0;

    const trie_node* cur = t->root;
    for (const uint8_t* p = (const uint8_t*)word; *p; p++) {
        int idx = child_index(cur, *p);
        if (idx < 0) return 0;
        cur = node_children(cur)[idx];
    }
    return cur->is_end_of_word ? cur->frequency : 0;
}

size_t trie_get_word_count(const trie_t* t) { return t ? t->word_count : 0; }
bool trie_is_empty(const trie_t* t) { return !t || t->word_count == 0; }

/* =========================================================================
 * Autocomplete (DFS with arena allocation — same API as original)
 * ========================================================================= */

typedef struct {
    char** suggestions;
    size_t count;
    size_t capacity;
    size_t limit;
} _collector;

static void _collect(const trie_node* node, char* buf, size_t depth, size_t buf_max, _collector* c, Arena* arena) {
    if (!node || c->count >= c->limit) return;

    if (node->is_end_of_word) {
        buf[depth] = '\0';
        char* dup = arena_strdup(arena, buf);
        if (dup) c->suggestions[c->count++] = dup;
    }

    for (uint8_t i = 0; i < node->nchildren && c->count < c->limit; i++) {
        if (depth + 1 >= buf_max) return;
        buf[depth] = (char)node_chars(node)[i];
        _collect(node_children(node)[i], buf, depth + 1, buf_max, c, arena);
    }
}

const char** trie_autocomplete(const trie_t* t, const char* prefix, size_t max_suggestions, size_t* out_count,
                               Arena* arena) {
    if (out_count) *out_count = 0;
    if (!t || !prefix || !out_count || max_suggestions == 0 || !arena) return NULL;

    /* Navigate to the prefix node. */
    const trie_node* cur = t->root;
    for (const uint8_t* p = (const uint8_t*)prefix; *p; p++) {
        int idx = child_index(cur, *p);
        if (idx < 0) return NULL;
        cur = node_children(cur)[idx];
    }

    /* Allocate suggestion array and word buffer on the arena. */
    char** suggestions = arena_alloc(arena, sizeof(char*) * max_suggestions);
    if (!suggestions) return NULL;

    const size_t buf_max = 1024;
    char* buf = (char*)arena_alloc(arena, buf_max);
    if (!buf) return NULL;

    size_t prefix_len = strlen(prefix);
    if (prefix_len >= buf_max) return NULL;
    memcpy(buf, prefix, prefix_len);

    _collector c = {.suggestions = suggestions, .count = 0, .capacity = max_suggestions, .limit = max_suggestions};

    _collect(cur, buf, prefix_len, buf_max, &c, arena);

    if (c.count == 0) return NULL;

    *out_count = c.count;
    return (const char**)suggestions;
}
