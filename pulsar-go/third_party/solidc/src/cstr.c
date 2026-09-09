/**
 * @file cstr.c
 * @brief Implementation of high-performance C string with SSO.
 *
 * Optimisation notes:
 *
 *  SSO self-referential pointer
 *    On init/SSO-promote, `data` is set to `&s->buf[0]`.  Every read of
 *    string bytes goes through one unconditional pointer dereference — no
 *    ternary, no branch.  Only free/resize needs cstr_is_heap().
 *
 *  uint32_t fields
 *    Struct is 32 bytes on 64-bit.  length and capacity fit in L1 cache
 *    together with one hot 16-byte SSO string.
 *
 *  Search — cstr_search()
 *    Uses a SIMD-accelerated first-byte scan (`memchr`) combined with a
 *    guard-byte check on the last needle byte, and an unrolled scalar loop
 *    for short needles (<= 9 bytes).  Avoids glibc memmem's dynamic dispatch
 *    and internal strlen overhead while processing candidates at maximum
 *    cache bandwidth.
 *
 *  replace_all
 *    Single forward scan with a fixed-size stack-local offset table to avoid
 *    heap allocation for the common case (< 64 matches).
 *
 *  Growth policy
 *    Exact doubling from the next power-of-two above the request, ensuring
 *    amortised O(1) appends with no fractional-factor rounding surprises.
 */

#include "cstr.h"
#include "macros.h"
#include "simd.h"

#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Internal macros & helpers
 * ---------------------------------------------------------------------- */

#define CSTR_MAX_SIZE ((size_t)CSTR_MAX_LEN)

#define likely(x)   CSTR_LIKELY(x)
#define unlikely(x) CSTR_UNLIKELY(x)

/** Round x up to the next power-of-two >= x. Undefined for x == 0. */
static inline uint32_t next_pow2_u32(uint32_t x) {
    if (x <= 1) return 1;
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    return x + 1;
}

/** Minimum heap allocation that fits `need` bytes + NUL. */
static inline uint32_t cstr_grow_cap(uint32_t current, uint32_t need) {
    if (CSTR_UNLIKELY(need > CSTR_MAX_LEN)) return CSTR_MAX_LEN;

    uint32_t cap = current < CSTR_MIN_HEAP ? CSTR_MIN_HEAP : current;
    if (cap >= need) return cap;

#if defined(__GNUC__) || defined(__clang__)
    uint32_t clz = (uint32_t)__builtin_clz(need - 1);
    cap = 1u << (32u - clz);
#else
    cap = next_pow2_u32(need);
#endif

    if (cap < CSTR_MIN_HEAP) cap = CSTR_MIN_HEAP;
    if (cap > CSTR_MAX_LEN) cap = CSTR_MAX_LEN;
    return cap;
}

/** -------------------------------------------------------------------------
 * Internal: promote SSO -> heap, or grow existing heap.
 *
 * After a successful call, s->data points to heap memory of size cap,
 * s->capacity has the heap flag set, and existing content is preserved.
 * ---------------------------------------------------------------------- */
static bool cstr_ensure_cap(cstr* s, size_t need) {
    /* need is the total bytes required INCLUDING the NUL terminator. */
    if (CSTR_UNLIKELY(need > (size_t)CSTR_MAX_LEN)) return false;

    uint32_t need32 = (uint32_t)need;

    if (!cstr_is_heap(s)) {
        /* SSO path: need > CSTR_SSO_CAP triggers promotion */
        if (need32 <= CSTR_SSO_CAP) return true;

        uint32_t cap = cstr_grow_cap(CSTR_SSO_CAP, need32);
        char* mem = (char*)malloc(cap);
        if (CSTR_UNLIKELY(!mem)) return false;

        memcpy(mem, s->buf, s->length + 1);
        s->data = mem;
        s->capacity = CSTR_HEAP_FLAG | cap;
        return true;
    }

    /* Heap path */
    uint32_t cur_cap = cstr_heap_cap(s);
    if (need32 <= cur_cap) return true;

    uint32_t new_cap = cstr_grow_cap(cur_cap, need32);
    if (new_cap == 0) return false;

    char* mem = (char*)realloc(s->data, new_cap);
    if (CSTR_UNLIKELY(!mem)) return false;

    s->data = mem;
    s->capacity = CSTR_HEAP_FLAG | new_cap;
    return true;
}

/* -------------------------------------------------------------------------
 * Search — fast needle-in-haystack without memmem
 * ---------------------------------------------------------------------- */

static const char* cstr_search(const char* hs, size_t hlen, const char* nd, size_t nlen) {
    if (unlikely(nlen == 0)) return hs;
    if (unlikely(hlen < nlen)) return NULL;

    /* Single char: Delegate to SIMD memchr */
    if (nlen == 1) return (const char*)memchr(hs, (unsigned char)nd[0], hlen);

    const char* cur = hs;
    const char* end = hs + hlen - nlen;
    unsigned char n_first = (unsigned char)nd[0];
    unsigned char n_last = (unsigned char)nd[nlen - 1];

    while (cur <= end) {
        /* A. SIMD Scan for first character */
        cur = (const char*)memchr(cur, n_first, (size_t)(end - cur + 1));
        if (unlikely(!cur)) return NULL;

        /* B. Guard Byte Check (verify the last byte before full verification) */
        if ((unsigned char)cur[nlen - 1] == n_last) {
            /* C. Small String Optimization: unrolled loop for lengths 2-9 */
            if (nlen <= 9) {
                const char* p_hay = cur + 1;
                const char* p_nd = nd + 1;
                size_t k = nlen - 2;
                size_t i = 0;
                for (; i < k; i++) {
                    if (p_hay[i] != p_nd[i]) goto next_iter;
                }
                return cur; /* Match found */
            } else {
                /* D. Long String: Fallback to memcmp */
                if (memcmp(cur + 1, nd + 1, nlen - 2) == 0) return cur;
            }
        }

    next_iter:
        cur++;
    }

    return NULL;
}

/* -------------------------------------------------------------------------
 * Lifecycle
 * ---------------------------------------------------------------------- */

cstr* cstr_init(size_t initial_capacity) {
    if (initial_capacity >= CSTR_MAX_SIZE) {
        return NULL;
    }

    cstr* s = (cstr*)malloc(sizeof(cstr));
    if (CSTR_UNLIKELY(!s)) return NULL;

    cstr_init_inplace(s);

    if (initial_capacity >= CSTR_SSO_CAP) {
        if (CSTR_UNLIKELY(!cstr_ensure_cap(s, initial_capacity + 1))) {
            free(s);
            return NULL;
        }
    }
    return s;
}

cstr* cstr_new(const char* input) {
    if (CSTR_UNLIKELY(!input)) return NULL;
    return cstr_new_len(input, strlen(input));
}

cstr* cstr_new_len(const char* data, size_t length) {
    if (CSTR_UNLIKELY(!data && length > 0)) return NULL;

    cstr* s = (cstr*)malloc(sizeof(cstr));
    if (CSTR_UNLIKELY(!s)) return NULL;
    cstr_init_inplace(s);

    if (length > 0) {
        if (CSTR_UNLIKELY(!cstr_ensure_cap(s, length + 1))) {
            free(s);
            return NULL;
        }
        memcpy(s->data, data, length);
        s->data[length] = '\0';
        s->length = (uint32_t)length;
    }
    return s;
}

cstr* cstr_new_view(cstr_view v) { return cstr_new_len(v.data, v.length); }

void cstr_drop(cstr* s) {
    if (!s) return;
    if (cstr_is_heap(s)) {
        free(s->data);
        s->data = NULL;
        cstr_init_inplace(s); /* reset to safe SSO state */
    }
}

void cstr_free(cstr* s) {
    if (!s) return;
    if (cstr_is_heap(s)) {
        free(s->data);
        s->data = NULL;
    }
    free(s);
}

void cstr_debug(const cstr* s) {
    if (!s) {
        fprintf(stderr, "cstr: NULL\n");
        return;
    }

    fprintf(stderr,
            "cstr { data=%p, length=%u, capacity=%u, mode=%s }\n"
            "  content: \"%.*s\"\n",
            (const void*)s->data, s->length,
            (unsigned)(cstr_is_heap(s) ? cstr_heap_cap(s) : CSTR_SSO_CAP - 1u),
            cstr_is_heap(s) ? "heap" : "sso", (int)s->length, s->data);
}

bool cstr_reserve(cstr* s, size_t capacity) { return cstr_ensure_cap(s, capacity + 1); }

void cstr_shrink_to_fit(cstr* s) {
    if (!cstr_is_heap(s)) return;
    uint32_t needed = s->length + 1;
    if (cstr_heap_cap(s) == needed) return;

    char* mem = (char*)realloc(s->data, needed);
    if (mem) {
        s->data = mem;
        s->capacity = CSTR_HEAP_FLAG | needed;
    }
}

/* -------------------------------------------------------------------------
 * Append / prepend / insert with aliasing safety
 * ---------------------------------------------------------------------- */

bool cstr_append_len(cstr* s, const char* str, size_t len) {
    if (len == 0) return true;
    if (CSTR_UNLIKELY(!str)) return false;

    size_t new_len = (size_t)s->length + len;
    if (CSTR_UNLIKELY(new_len > CSTR_MAX_SIZE)) return false;

    /* Check for self-aliasing into s's existing buffer */
    bool is_aliased = (str >= s->data && str < s->data + s->length);
    size_t alias_offset = is_aliased ? (size_t)(str - s->data) : 0;

    if (CSTR_UNLIKELY(!cstr_ensure_cap(s, new_len + 1))) return false;

    const char* src = is_aliased ? (s->data + alias_offset) : str;
    memcpy(s->data + s->length, src, len);
    s->data[new_len] = '\0';
    s->length = (uint32_t)new_len;
    return true;
}

bool cstr_append(cstr* s, const char* CSTR_RESTRICT append_str) {
    if (CSTR_UNLIKELY(!append_str)) return false;
    return cstr_append_len(s, append_str, strlen(append_str));
}

bool cstr_append_cstr(cstr* s, const cstr* append) {
    if (CSTR_UNLIKELY(!append)) return false;
    return cstr_append_len(s, append->data, append->length);
}

bool cstr_append_view(cstr* s, cstr_view v) { return cstr_append_len(s, v.data, v.length); }

bool cstr_ncat(cstr* dest, const cstr* src, size_t n) {
    if (CSTR_UNLIKELY(!src)) return false;
    size_t copy_n = (n < (size_t)src->length) ? n : (size_t)src->length;
    return cstr_append_len(dest, src->data, copy_n);
}

bool cstr_append_char(cstr* s, char c) {
    uint32_t new_len = s->length + 1;
    if (CSTR_UNLIKELY(!cstr_ensure_cap(s, (size_t)new_len + 1))) return false;
    s->data[s->length] = c;
    s->data[new_len] = '\0';
    s->length = new_len;
    return true;
}

bool cstr_prepend_len(cstr* s, const char* str, size_t len) {
    if (len == 0) return true;
    if (CSTR_UNLIKELY(!str)) return false;

    size_t new_len = (size_t)s->length + len;
    if (CSTR_UNLIKELY(new_len > CSTR_MAX_SIZE)) return false;

    bool is_aliased = (str >= s->data && str < s->data + s->length);
    size_t alias_offset = is_aliased ? (size_t)(str - s->data) : 0;

    if (CSTR_UNLIKELY(!cstr_ensure_cap(s, new_len + 1))) return false;

    const char* src = is_aliased ? (s->data + alias_offset) : str;
    memmove(s->data + len, s->data, s->length + 1);
    memcpy(s->data, src, len);
    s->length = (uint32_t)new_len;
    return true;
}

bool cstr_prepend(cstr* s, const char* prepend_str) {
    if (CSTR_UNLIKELY(!prepend_str)) return false;
    return cstr_prepend_len(s, prepend_str, strlen(prepend_str));
}

bool cstr_prepend_cstr(cstr* s, const cstr* prepend) {
    if (CSTR_UNLIKELY(!prepend)) return false;
    return cstr_prepend_len(s, prepend->data, prepend->length);
}

bool cstr_prepend_view(cstr* s, cstr_view v) { return cstr_prepend_len(s, v.data, v.length); }

bool cstr_prepend_fast(cstr* s, const char* prepend_str) {
    size_t n = strlen(prepend_str);
    if (n == 0) return true;
    memmove(s->data + n, s->data, s->length + 1);
    memcpy(s->data, prepend_str, n);
    s->length += (uint32_t)n;
    return true;
}

bool cstr_insert_len(cstr* s, size_t index, const char* str, size_t len) {
    if (CSTR_UNLIKELY(index > (size_t)s->length)) return false;
    if (len == 0) return true;
    if (CSTR_UNLIKELY(!str)) return false;

    size_t new_len = (size_t)s->length + len;
    if (CSTR_UNLIKELY(new_len > CSTR_MAX_SIZE)) return false;

    bool is_aliased = (str >= s->data && str < s->data + s->length);
    size_t alias_offset = is_aliased ? (size_t)(str - s->data) : 0;

    if (CSTR_UNLIKELY(!cstr_ensure_cap(s, new_len + 1))) return false;

    const char* src = is_aliased ? (s->data + alias_offset) : str;
    char* pos = s->data + index;
    memmove(pos + len, pos, s->length - index + 1);
    memmove(pos, src, len);
    s->length = (uint32_t)new_len;
    return true;
}

bool cstr_insert(cstr* s, size_t index, const char* insert_str) {
    if (CSTR_UNLIKELY(!insert_str)) return false;
    return cstr_insert_len(s, index, insert_str, strlen(insert_str));
}

bool cstr_insert_cstr(cstr* s, size_t index, const cstr* insert) {
    if (CSTR_UNLIKELY(!insert)) return false;
    return cstr_insert_len(s, index, insert->data, insert->length);
}

bool cstr_insert_view(cstr* s, size_t index, cstr_view v) {
    return cstr_insert_len(s, index, v.data, v.length);
}

static inline void cstr_delete_range(cstr* s, uint32_t start, uint32_t del_len) {
    if (del_len == 0) return;

    uint32_t len = s->length;
    uint32_t tail = len - start - del_len;
    memmove(s->data + start, s->data + start + del_len, tail + 1);
    s->length = len - del_len;
}

bool cstr_remove(cstr* s, size_t index, size_t count) {
    uint32_t len = s->length;
    if (CSTR_UNLIKELY(index > len)) return false;

    uint32_t idx = (uint32_t)index;
    uint32_t cnt = (count > (size_t)(len - idx)) ? (len - idx) : (uint32_t)count;
    cstr_delete_range(s, idx, cnt);
    return true;
}

/* -------------------------------------------------------------------------
 * Printf-style helpers
 * ---------------------------------------------------------------------- */

cstr* cstr_format(const char* format, ...) {
    if (CSTR_UNLIKELY(!format)) return NULL;

    va_list a, a2;
    va_start(a, format);
    va_copy(a2, a);
    int need = vsnprintf(NULL, 0, format, a2);
    va_end(a2);

    if (CSTR_UNLIKELY(need < 0 || (size_t)need > CSTR_MAX_SIZE)) {
        va_end(a);
        return NULL;
    }

    cstr* s = cstr_init((size_t)need);
    if (CSTR_UNLIKELY(!s)) {
        va_end(a);
        return NULL;
    }

    vsnprintf(s->data, (size_t)need + 1, format, a);
    va_end(a);
    s->length = (uint32_t)need;
    return s;
}

bool cstr_append_fmt(cstr* s, const char* format, ...) {
    va_list a, a2;
    va_start(a, format);
    va_copy(a2, a);
    int n = vsnprintf(NULL, 0, format, a2);
    va_end(a2);

    if (CSTR_UNLIKELY(n < 0)) {
        va_end(a);
        return false;
    }

    uint32_t new_len = s->length + (uint32_t)n;
    if (CSTR_UNLIKELY(!cstr_ensure_cap(s, (size_t)new_len + 1))) {
        va_end(a);
        return false;
    }

    vsnprintf(s->data + s->length, (size_t)n + 1, format, a);
    va_end(a);
    s->length = new_len;
    return true;
}

/* -------------------------------------------------------------------------
 * Copy / assign
 * ---------------------------------------------------------------------- */

bool cstr_copy(cstr* dest, const cstr* src) {
    if (dest == src) return true;
    uint32_t src_len = src->length;
    if (CSTR_UNLIKELY(!cstr_ensure_cap(dest, (size_t)src_len + 1))) return false;
    memcpy(dest->data, src->data, (size_t)src_len + 1);
    dest->length = src_len;
    return true;
}

/* -------------------------------------------------------------------------
 * Remove helpers
 * ---------------------------------------------------------------------- */

size_t cstr_remove_all(cstr* s, const char* substr) {
    if (!substr || !*substr) return 0;
    cstr view = {
        .data = (char*)substr,
        .length = (uint32_t)strlen(substr),
        .capacity = 0,
    };
    return cstr_remove_all_cstr(s, &view);
}

size_t cstr_remove_all_cstr(cstr* s, const cstr* substr) {
    uint32_t sub_len = substr->length;
    if (sub_len == 0) return 0;
    const char* sub = substr->data;
    char* d = s->data;
    char *w = d, *r = d;
    const char* end = d + s->length;
    size_t count = 0;

    while (r < end) {
        size_t rem = (size_t)(end - r);
        if ((uint32_t)rem >= sub_len && memcmp(r, sub, sub_len) == 0) {
            r += sub_len;
            count++;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
    s->length = (uint32_t)(w - d);
    return count;
}

void cstr_remove_char(cstr* s, char c) {
    if (s->length == 0) return;

    char* read_ptr = s->data;
    char* write_ptr = s->data;
    size_t rem = s->length;

    while (rem > 0) {
        /* SIMD scan for the next occurrence of 'c' */
        char* match = (char*)memchr(read_ptr, (unsigned char)c, rem);
        if (!match) {
            /* No more occurrences: copy remaining tail */
            if (write_ptr != read_ptr) {
                memmove(write_ptr, read_ptr, rem);
            }
            write_ptr += rem;
            break;
        }

        /* Copy non-matching chunk preceding the match */
        size_t chunk_len = (size_t)(match - read_ptr);
        if (chunk_len > 0) {
            if (write_ptr != read_ptr) {
                memmove(write_ptr, read_ptr, chunk_len);
            }
            write_ptr += chunk_len;
        }

        /* Skip the matched character 'c' */
        read_ptr = match + 1;
        rem -= (chunk_len + 1);
    }

    *write_ptr = '\0';
    s->length = (uint32_t)(write_ptr - s->data);
}

void cstr_remove_substr(cstr* s, size_t start, size_t slen) {
    uint32_t len = s->length;
    if (CSTR_UNLIKELY(start >= len || slen == 0)) return;

    uint32_t st = (uint32_t)start;
    uint32_t cnt = (slen > (size_t)(len - st)) ? (len - st) : (uint32_t)slen;
    cstr_delete_range(s, st, cnt);
}

/* -------------------------------------------------------------------------
 * Public find / rfind
 * ---------------------------------------------------------------------- */

int cstr_find(const cstr* s, const char* substr) {
    size_t nlen = strlen(substr);
    const char* found = cstr_search(s->data, s->length, substr, nlen);
    return found ? (int)(found - s->data) : CSTR_NPOS;
}

int cstr_find_cstr(const cstr* s, const cstr* sub) {
    const char* found = cstr_search(s->data, s->length, sub->data, sub->length);
    return found ? (int)(found - s->data) : CSTR_NPOS;
}

int cstr_find_view(const cstr* s, cstr_view sub) {
    const char* found = cstr_search(s->data, s->length, sub.data, sub.length);
    return found ? (int)(found - s->data) : CSTR_NPOS;
}

int cstr_rfind(const cstr* s, const char* substr) {
    size_t nlen = strlen(substr);
    if (nlen == 0 || nlen > s->length) return CSTR_NPOS;

    const char* hs = s->data;
    size_t hlen = s->length;
    const char* last = NULL;
    const char* p = hs;

    /* Walk forward collecting last match — memchr makes each step fast. */
    while ((p = cstr_search(p, hlen - (size_t)(p - hs), substr, nlen)) != NULL) {
        last = p;
        p++;
        if ((size_t)(p - hs) + nlen > hlen) break;
    }
    return last ? (int)(last - hs) : CSTR_NPOS;
}

int cstr_rfind_cstr(const cstr* s, const cstr* sub) {
    if (sub->length == 0) return (int)s->length;
    if (sub->length > s->length) return CSTR_NPOS;
    return cstr_rfind_view(s, (cstr_view){sub->data, sub->length});
}

int cstr_rfind_view(const cstr* s, cstr_view sub) {
    if (sub.length == 0) return (int)s->length;
    if (sub.length > s->length) return CSTR_NPOS;

    const char* hs = s->data;
    size_t hlen = s->length;
    const char* last = NULL;
    const char* p = hs;

    while ((p = cstr_search(p, hlen - (size_t)(p - hs), sub.data, sub.length)) != NULL) {
        last = p;
        p++;
        if ((size_t)(p - hs) + sub.length > hlen) break;
    }
    return last ? (int)(last - hs) : CSTR_NPOS;
}

/* -------------------------------------------------------------------------
 * Comparison
 * ---------------------------------------------------------------------- */

int cstr_cmp(const cstr* s1, const cstr* s2) {
    if (!s1 && !s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;
    return strcmp(s1->data, s2->data);
}

int cstr_ncmp(const cstr* s1, const cstr* s2, size_t n) {
    if (!s1 && !s2) return 0;
    if (!s1) return -1;
    if (!s2) return 1;
    return strncmp(s1->data, s2->data, n);
}

/* -------------------------------------------------------------------------
 * starts_with / ends_with
 * ---------------------------------------------------------------------- */

bool cstr_starts_with(const cstr* s, const char* prefix) {
    size_t plen = strlen(prefix);
    if (plen == 0) return true;
    if (plen > (size_t)s->length) return false;
    return memcmp(s->data, prefix, plen) == 0;
}

bool cstr_starts_with_cstr(const cstr* s, const cstr* prefix) {
    return cstr_starts_with_view(s, (cstr_view){prefix->data, prefix->length});
}

bool cstr_starts_with_view(const cstr* s, cstr_view prefix) {
    uint32_t plen = prefix.length;
    if (plen == 0) return true;
    if (plen > s->length) return false;
    return memcmp(s->data, prefix.data, plen) == 0;
}

bool cstr_ends_with(const cstr* s, const char* suffix) {
    size_t slen = strlen(suffix);
    if (slen == 0) return true;
    if (slen > (size_t)s->length) return false;
    return memcmp(s->data + s->length - slen, suffix, slen) == 0;
}

bool cstr_ends_with_cstr(const cstr* s, const cstr* suffix) {
    return cstr_ends_with_view(s, (cstr_view){suffix->data, suffix->length});
}

bool cstr_ends_with_view(const cstr* s, cstr_view suffix) {
    uint32_t slen = suffix.length;
    if (slen == 0) return true;
    if (slen > s->length) return false;
    return memcmp(s->data + s->length - slen, suffix.data, slen) == 0;
}

/* -------------------------------------------------------------------------
 * Count occurrences
 * ---------------------------------------------------------------------- */

size_t cstr_count_substr_len(const cstr* s, const char* substr, size_t nlen) {
    if (nlen == 0 || nlen > s->length) return 0;

    const char* p = s->data;
    size_t rem = s->length;
    size_t count = 0;

    /* Fast path: single-character needle using SIMD memchr */
    if (nlen == 1) {
        unsigned char target = (unsigned char)substr[0];
        while ((p = (const char*)memchr(p, target, rem)) != NULL) {
            count++;
            p++;
            rem = s->length - (size_t)(p - s->data);
        }
        return count;
    }

    /* Multi-character search path */
    while ((p = cstr_search(p, rem, substr, nlen)) != NULL) {
        count++;
        p += nlen;
        rem = s->length - (size_t)(p - s->data);
        if (rem < nlen) break;
    }
    return count;
}

size_t cstr_count_substr(const cstr* s, const char* substr) {
    return cstr_count_substr_len(s, substr, strlen(substr));
}

size_t cstr_count_substr_cstr(const cstr* s, const cstr* sub) {
    return cstr_count_substr_len(s, sub->data, sub->length);
}

size_t cstr_count_substr_view(const cstr* s, cstr_view sub) {
    return cstr_count_substr_len(s, sub.data, sub.length);
}

/* -------------------------------------------------------------------------
 * Case conversion & memory hygiene
 * ---------------------------------------------------------------------- */

void cstr_lower(cstr* s) { simd_ascii_lower(s->data, s->length); }

void cstr_upper(cstr* s) { simd_ascii_upper(s->data, s->length); }

void cstr_wipe(cstr* s) {
    if (!s || !s->data) return;
    size_t cap = cstr_capacity(s);
    SOLIDC_SECURE_ZERO(s->data, cap);
    s->length = 0;
}

static inline bool cstr_snake_should_underscore(const char* d, uint32_t i, uint32_t len) {
    (void)len;
    if (i == 0) return false;

    unsigned char c = (unsigned char)d[i];
    unsigned char prev = (unsigned char)d[i - 1];
    unsigned char next = (i + 1 < len) ? (unsigned char)d[i + 1] : (unsigned char)'x';

    bool curr_upper = (unsigned)(c - 'A') <= 25u;
    bool prev_lower = (unsigned)(prev - 'a') <= 25u || (unsigned)(prev - '0') <= 9u;
    bool prev_upper = (unsigned)(prev - 'A') <= 25u;

    if (!curr_upper) return false;
    if (prev_lower) return true; /* lower -> UPPER: myVar -> my_var */
    /* Acronym end: UPPER -> UPPER -> lower: XMLParser -> xml_parser */
    return prev_upper && (unsigned)(next - 'a') <= 25u;
}

bool cstr_snakecase(cstr* s) {
    uint32_t orig = s->length;
    if (orig == 0) return true;

    /*
     * FIX (corruption): the previous implementation converted in place with
     * two forward cursors.  Once an inserted '_' pushed the write cursor
     * past the read cursor, the loop re-read its own output ("HelloWorld"
     * became "hello_wwwwww...").  Build the result in a scratch buffer
     * first; worst case doubles every byte ('_' before each char).
     */
    size_t max_out = (size_t)orig * 2;
    char stack_tmp[512];
    char* tmp = stack_tmp;
    bool heap_tmp = max_out + 1 > sizeof(stack_tmp);
    if (heap_tmp) {
        tmp = (char*)malloc(max_out + 1);
        if (!tmp) return false;
    }

    const char* d = s->data;
    size_t w = 0;
    bool last_was_underscore = false;

    for (uint32_t i = 0; i < orig; i++) {
        unsigned char c = (unsigned char)d[i];

        /* Collapse spaces/hyphens/underscores into one '_' */
        if (c == ' ' || c == '-' || c == '_') {
            if (!last_was_underscore && w > 0) {
                tmp[w++] = '_';
                last_was_underscore = true;
            }
            continue;
        }

        bool curr_upper = (unsigned)(c - 'A') <= 25u;
        if (curr_upper && cstr_snake_should_underscore(d, i, orig) && !last_was_underscore &&
            w > 0) {
            tmp[w++] = '_';
        }

        tmp[w++] = (char)(curr_upper ? (c | 0x20u) : c);
        last_was_underscore = false;
    }

    memcpy(s->data, tmp, w);
    s->data[w] = '\0';
    s->length = (uint32_t)w;

    if (heap_tmp) free(tmp);
    return true;
}

static inline bool cstr_is_sep(unsigned char c) { return c == '_' || c == '-' || isspace(c); }

void cstr_camelcase(cstr* s) {
    uint32_t len = s->length;
    if (len == 0) return;
    char* d = s->data;
    uint32_t r = 0, w = 0;

    /* Skip leading separators */
    while (r < len && cstr_is_sep((unsigned char)d[r])) r++;

    if (r < len) {
        unsigned char c = (unsigned char)d[r++];
        d[w++] = (char)((unsigned)(c - 'A') <= 25u ? (c | 0x20u) : c);
    }

    bool cap = false;
    while (r < len) {
        unsigned char c = (unsigned char)d[r++];
        if (cstr_is_sep(c)) {
            cap = true;
            continue;
        }
        if (cap) {
            d[w++] = (char)((unsigned)(c - 'a') <= 25u ? (c & ~0x20u) : c);
            cap = false;
        } else {
            /* FIX: interior characters keep their original case.  The old
             * code lowercased everything not preceded by a separator,
             * destroying camel-case capitals ("HelloWorld" -> "helloworld"). */
            d[w++] = (char)c;
        }
    }
    d[w] = '\0';
    s->length = w;
}

void cstr_pascalcase(cstr* s) {
    uint32_t len = s->length;
    if (len == 0) return;
    char* d = s->data;
    uint32_t r = 0, w = 0;

    while (r < len && cstr_is_sep((unsigned char)d[r])) r++;

    bool new_word = true;
    while (r < len) {
        unsigned char c = (unsigned char)d[r++];
        if (cstr_is_sep(c)) {
            new_word = true;
            continue;
        }
        if (new_word) {
            d[w++] = (char)((unsigned)(c - 'a') <= 25u ? (c & ~0x20u) : c);
            new_word = false;
        } else {
            /* FIX: interior characters keep their original case (same bug
             * class as cstr_camelcase: "helloWorld" -> "Helloworld"). */
            d[w++] = (char)c;
        }
    }
    d[w] = '\0';
    s->length = w;
}

void cstr_titlecase(cstr* s) {
    uint32_t len = s->length;
    char* d = s->data;
    /*
     * FIX: a letter is capitalized when the previous character was NOT a
     * letter (word boundary), not just after whitespace.  The old code
     * only reset its flag on isspace(), so "foo-bar_baz" kept "bar"/"baz"
     * lowercase; the documented contract (and tests) require
     * "Foo-Bar_Baz".
     */
    bool cap = true;
    for (uint32_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)d[i];
        if (!isalpha(c)) {
            cap = true;
            continue; /* punctuation/digits/space pass through unchanged */
        }
        if (cap) {
            d[i] = (char)toupper(c);
            cap = false;
        } else {
            d[i] = (char)tolower(c); /* normalize interior capitals */
        }
    }
}

/* -------------------------------------------------------------------------
 * Trim
 * ---------------------------------------------------------------------- */

void cstr_trim(cstr* s) {
    uint32_t len = s->length;
    if (len == 0) return;
    char* d = s->data;

    uint32_t start = 0, end = len - 1;
    while (start < len && isspace((unsigned char)d[start])) start++;
    while (end > start && isspace((unsigned char)d[end])) end--;

    uint32_t new_len = (start > end) ? 0 : (end - start + 1);
    if (new_len && start) memmove(d, d + start, new_len);
    d[new_len] = '\0';
    s->length = new_len;
}

void cstr_rtrim(cstr* s) {
    uint32_t len = s->length;
    if (len == 0) return;
    char* d = s->data;
    uint32_t e = len;
    while (e > 0 && isspace((unsigned char)d[e - 1])) e--;
    d[e] = '\0';
    s->length = e;
}

void cstr_ltrim(cstr* s) {
    uint32_t len = s->length;
    if (len == 0) return;
    char* d = s->data;
    uint32_t start = 0;
    while (start < len && isspace((unsigned char)d[start])) start++;
    if (start == 0) return;
    uint32_t new_len = len - start;
    memmove(d, d + start, new_len + 1);
    s->length = new_len;
}

void cstr_trim_chars(cstr* s, const char* chars) {
    uint32_t len = s->length;
    if (len == 0 || *chars == '\0') return;
    char* d = s->data;

    uint32_t start = 0;
    while (start < len && d[start] != '\0' && strchr(chars, d[start])) start++;
    if (start == len) {
        s->length = 0;
        d[0] = '\0';
        return;
    }

    uint32_t end = len - 1;
    while (end > start && d[end] != '\0' && strchr(chars, d[end])) end--;

    uint32_t new_len = end - start + 1;
    if (start) memmove(d, d + start, new_len);
    d[new_len] = '\0';
    s->length = new_len;
}

/* -------------------------------------------------------------------------
 * Substrings & Replacement
 * ---------------------------------------------------------------------- */

cstr* cstr_substr(const cstr* s, size_t start, size_t length) {
    uint32_t slen = s->length;
    if (CSTR_UNLIKELY(start > slen)) return NULL;
    uint32_t avail = slen - (uint32_t)start;
    uint32_t copy = (length > avail) ? avail : (uint32_t)length;
    return cstr_new_len(s->data + start, copy);
}

cstr* cstr_replace(const cstr* s, const char* old_str, const char* new_str) {
    size_t old_len = strlen(old_str);
    if (old_len == 0) return cstr_new_len(s->data, s->length);

    const char* found = cstr_search(s->data, s->length, old_str, old_len);
    if (!found) return cstr_new_len(s->data, s->length);

    size_t new_len = strlen(new_str);
    size_t prefix_len = (size_t)(found - s->data);
    size_t suffix_len = s->length - prefix_len - old_len;
    size_t result_len = prefix_len + new_len + suffix_len;

    cstr* r = cstr_init(result_len);
    if (CSTR_UNLIKELY(!r)) return NULL;

    char* d = r->data;
    memcpy(d, s->data, prefix_len);
    memcpy(d + prefix_len, new_str, new_len);
    memcpy(d + prefix_len + new_len, found + old_len, suffix_len);
    d[result_len] = '\0';
    r->length = (uint32_t)result_len;
    return r;
}

#define RA_STACK_CAP 64

cstr* cstr_replace_all(const cstr* s, const char* old_sub, const char* new_sub) {
    size_t old_len = strlen(old_sub);
    if (old_len == 0) return cstr_new_len(s->data, s->length);

    size_t new_len = strlen(new_sub);
    const char* hs = s->data;
    size_t hlen = s->length;

    /* Collect match offsets. */
    size_t stack_offs[RA_STACK_CAP];
    size_t* offs = stack_offs;
    size_t offs_cap = RA_STACK_CAP;
    size_t count = 0;

    const char* p = hs;
    size_t rem = hlen;

    while ((p = cstr_search(p, rem, old_sub, old_len)) != NULL) {
        if (CSTR_UNLIKELY(count >= offs_cap)) {
            /* Guard against integer overflow before multiplying. */
            if (CSTR_UNLIKELY(offs_cap > SIZE_MAX / 2 / sizeof(size_t))) goto oom;

            size_t new_cap = offs_cap * 2;
            size_t* no;
            if (offs == stack_offs) {
                no = (size_t*)malloc(new_cap * sizeof(size_t));
                if (CSTR_UNLIKELY(!no)) goto oom;
                memcpy(no, stack_offs, count * sizeof(size_t));
            } else {
                no = (size_t*)realloc(offs, new_cap * sizeof(size_t));
                if (CSTR_UNLIKELY(!no)) goto oom;
            }
            offs = no;
            offs_cap = new_cap;
        }
        offs[count++] = (size_t)(p - hs);
        p += old_len;
        rem = hlen - (size_t)(p - hs);
    }

    if (count == 0) {
        if (offs != stack_offs) free(offs);
        return cstr_new_len(hs, hlen);
    }

    /* Compute exact output length with overflow protection */
    size_t result_len;
    if (new_len >= old_len) {
        size_t diff = new_len - old_len;
        if (diff > 0 && count > (CSTR_MAX_SIZE - hlen) / diff) {
            goto oom; /* Integer overflow */
        }
        result_len = hlen + count * diff;
    } else {
        result_len = hlen - count * (old_len - new_len);
    }

    {
        cstr* r = cstr_init(result_len);
        if (CSTR_UNLIKELY(!r)) goto oom;

        char* dst = r->data;
        size_t write_pos = 0;
        size_t src_pos = 0;

        for (size_t i = 0; i < count; i++) {
            size_t gap = offs[i] - src_pos;
            if (gap) {
                memcpy(dst + write_pos, hs + src_pos, gap);
                write_pos += gap;
            }
            if (new_len) {
                memcpy(dst + write_pos, new_sub, new_len);
                write_pos += new_len;
            }
            src_pos = offs[i] + old_len;
        }
        size_t tail = hlen - src_pos;
        if (tail) {
            memcpy(dst + write_pos, hs + src_pos, tail);
            write_pos += tail;
        }

        dst[write_pos] = '\0';
        r->length = (uint32_t)write_pos;

        if (offs != stack_offs) free(offs);
        return r;
    }

oom:
    if (offs != stack_offs) free(offs);
    return NULL;
}

#undef RA_STACK_CAP

/* -------------------------------------------------------------------------
 * Split & join
 * ---------------------------------------------------------------------- */

cstr** cstr_split(const cstr* s, const char* delim, size_t* count_out) {
    *count_out = 0;

    if (!delim || !*delim) {
        cstr** r = (cstr**)malloc(sizeof(cstr*));
        if (CSTR_UNLIKELY(!r)) return NULL;
        r[0] = cstr_new_len(s->data, s->length);
        if (CSTR_UNLIKELY(!r[0])) {
            free(r);
            return NULL;
        }
        *count_out = 1;
        return r;
    }

    size_t dlen = strlen(delim);
    size_t cap = 8;
    cstr** result = (cstr**)malloc(cap * sizeof(cstr*));
    if (CSTR_UNLIKELY(!result)) return NULL;

    const char* start = s->data;
    size_t rem = s->length;
    size_t count = 0;

    if (dlen == 1) {
        /* Fast path: single-character delimiter using SIMD memchr */
        unsigned char target = (unsigned char)delim[0];
        while (1) {
            const char* match = (const char*)memchr(start, target, rem);
            size_t tok_len = match ? (size_t)(match - start) : rem;

            if (CSTR_UNLIKELY(count >= cap)) {
                if (CSTR_UNLIKELY(cap > SIZE_MAX / 2 / sizeof(cstr*))) goto split_err;
                size_t new_cap = cap * 2;
                cstr** tmp = (cstr**)realloc(result, new_cap * sizeof(cstr*));
                if (CSTR_UNLIKELY(!tmp)) goto split_err;
                result = tmp;
                cap = new_cap;
            }

            result[count] = cstr_new_len(start, tok_len);
            if (CSTR_UNLIKELY(!result[count])) goto split_err;
            count++;

            if (!match) break;
            start = match + 1;
            rem -= (tok_len + 1);
        }
    } else {
        /* Multi-character delimiter path using cstr_search */
        const char* end = s->data + s->length;
        while (1) {
            const char* found = cstr_search(start, (size_t)(end - start), delim, dlen);
            const char* tok_end = found ? found : end;

            if (CSTR_UNLIKELY(count >= cap)) {
                if (CSTR_UNLIKELY(cap > SIZE_MAX / 2 / sizeof(cstr*))) goto split_err;
                size_t new_cap = cap * 2;
                cstr** tmp = (cstr**)realloc(result, new_cap * sizeof(cstr*));
                if (CSTR_UNLIKELY(!tmp)) goto split_err;
                result = tmp;
                cap = new_cap;
            }

            result[count] = cstr_new_len(start, (size_t)(tok_end - start));
            if (CSTR_UNLIKELY(!result[count])) goto split_err;
            count++;

            if (!found) break;
            start = found + dlen;
        }
    }

    *count_out = count;
    return result;

split_err:
    for (size_t i = 0; i < count; i++) {
        cstr_free(result[i]);
    }
    free(result);
    return NULL;
}

cstr* cstr_join(const cstr** strings, size_t count, const char* delim) {
    if (CSTR_UNLIKELY(!strings || count == 0)) return cstr_new_len("", 0);

    if (count == 1) {
        if (CSTR_UNLIKELY(!strings[0])) return NULL;
        return cstr_new_len(strings[0]->data, strings[0]->length);
    }

    size_t dlen = delim ? strlen(delim) : 0;
    size_t total = 0;

    /* Pass 1: Compute exact size with overflow validation */
    for (size_t i = 0; i < count; i++) {
        if (CSTR_UNLIKELY(!strings[i])) return NULL;

        size_t slen = strings[i]->length;
        if (CSTR_UNLIKELY(slen > CSTR_MAX_SIZE - total)) return NULL;
        total += slen;

        if (i + 1 < count && dlen) {
            if (CSTR_UNLIKELY(dlen > CSTR_MAX_SIZE - total)) return NULL;
            total += dlen;
        }
    }

    cstr* r = cstr_init(total);
    if (CSTR_UNLIKELY(!r)) return NULL;

    char* w = r->data;

    uint32_t first_len = strings[0]->length;
    if (first_len) {
        memcpy(w, strings[0]->data, first_len);
        w += first_len;
    }

    /* Pass 2: Copy remaining strings */
    if (dlen == 1) {
        char d_char = delim[0];
        for (size_t i = 1; i < count; i++) {
            *w++ = d_char;
            uint32_t slen = strings[i]->length;
            if (slen) {
                memcpy(w, strings[i]->data, slen);
                w += slen;
            }
        }
    } else if (dlen > 1) {
        for (size_t i = 1; i < count; i++) {
            memcpy(w, delim, dlen);
            w += dlen;
            uint32_t slen = strings[i]->length;
            if (slen) {
                memcpy(w, strings[i]->data, slen);
                w += slen;
            }
        }
    } else {
        for (size_t i = 1; i < count; i++) {
            uint32_t slen = strings[i]->length;
            if (slen) {
                memcpy(w, strings[i]->data, slen);
                w += slen;
            }
        }
    }

    *w = '\0';
    r->length = (uint32_t)(w - r->data);
    return r;
}

/* -------------------------------------------------------------------------
 * Reverse
 * ---------------------------------------------------------------------- */

cstr* cstr_reverse(const cstr* s) {
    uint32_t len = s->length;
    cstr* r = cstr_init(len);
    if (!r) return NULL;
    char* dst = r->data;
    const char* src = s->data;
    for (uint32_t i = 0; i < len; i++) dst[i] = src[len - 1 - i];
    dst[len] = '\0';
    r->length = len;
    return r;
}

void cstr_reverse_inplace(cstr* s) {
    uint32_t len = s->length;
    if (len < 2) return;
    char* d = s->data;
    for (uint32_t i = 0, j = len - 1; i < j; i++, j--) {
        char t = d[i];
        d[i] = d[j];
        d[j] = t;
    }
}
