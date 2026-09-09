/**
 * @file sort.c
 * @brief Implementation of sol_qsort (introsort) and the specialized
 *        sorts declared in sort.h (branchless quicksort + LSD radix).
 *
 * Design notes
 * ------------
 * Generic path (sol_qsort):
 *   Introsort with median-of-three/ninther pivots, Hoare partitioning
 *   (equal keys stop both pointers), insertion sort below 24 elements,
 *   heapsort depth bound.  Word-sized swap kernels for the common
 *   element sizes, and an O(1)-amortized sorted/reverse pre-check per
 *   node (scans abort at the first inversion, so random data pays
 *   almost nothing while presorted inputs finish in one linear pass).
 *
 * Specialized paths (i32/i64/f64):
 *   - n < RADIX_MIN: branchless quicksort.  The pivot INSTANCE is swapped
 *     out of the way and re-inserted after partitioning, so no second
 *     equality pass is needed for progress.  Only a DEGENERATE split
 *     (empty side) triggers the full three-way equality filter, which is
 *     therefore free on high-entropy data (fixes the saw_eq trap).
 *   - n >= RADIX_MIN: LSD radix sort on order-preserving integer keys
 *     (sign flip for signed ints, IEEE-754 bit twist for doubles, NaNs
 *     clamped past +inf).  Column histograms computed up front let whole
 *     byte columns be SKIPPED when uniform -- few-distinct-value inputs
 *     collapse to one or two passes.
 */
#include "../include/sort.h"
#include "macros.h"

#include <math.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================= */
/* Generic introsort                                                         */
/* ========================================================================= */

#define SW_INSERTION_THRESHOLD 24
#define SW_NINTHER_THRESHOLD   128
#define SW_STACK_TMP_MAX       64

typedef int (*sw_cmp)(const void*, const void*);

/**
 * Swap kernels specialized for common element sizes.  Base pointers come
 * from malloc (16-byte aligned) and all offsets are multiples of the
 * element size, so the direct word accesses are always aligned.
 */
static inline void sw_swap(char* a, char* b, size_t sz, char* tmp) {
    if (sz == 4) {
        uint32_t t;
        memcpy(&t, a, 4);
        memcpy(a, b, 4);
        memcpy(b, &t, 4);
    } else if (sz == 8) {
        uint64_t t;
        memcpy(&t, a, 8);
        memcpy(a, b, 8);
        memcpy(b, &t, 8);
    } else if (sz <= SW_STACK_TMP_MAX) {
        char buf[SW_STACK_TMP_MAX];
        memcpy(buf, a, sz);
        memcpy(a, b, sz);
        memcpy(b, buf, sz);
    } else if ((sz & (sizeof(unsigned long) - 1)) == 0) {
        unsigned long* wa = (unsigned long*)a;
        unsigned long* wb = (unsigned long*)b;
        for (size_t k = 0; k < sz / sizeof(unsigned long); k++) {
            unsigned long t = wa[k];
            wa[k] = wb[k];
            wb[k] = t;
        }
    } else {
        memcpy(tmp, a, sz);
        memcpy(a, b, sz);
        memcpy(b, tmp, sz);
    }
}

/** Insertion sort over [lo, hi] (inclusive pointers). O(n) when nearly sorted. */
static void sw_insertion_sort(char* lo, char* hi, size_t sz, sw_cmp cmp, char* tmp) {
    for (char* i = lo + sz; i <= hi; i += sz) {
        char* j = i;
        while (j > lo && cmp(j, j - sz) < 0) {
            sw_swap(j, j - sz, sz, tmp);
            j -= sz;
        }
    }
}

static void sw_sift_down(char* base, size_t root, size_t end, size_t sz, sw_cmp cmp, char* tmp) {
    for (;;) {
        size_t child = 2 * root + 1;
        if (child >= end) break;
        if (child + 1 < end && cmp(base + child * sz, base + (child + 1) * sz) < 0) child++;
        if (cmp(base + root * sz, base + child * sz) >= 0) break;
        sw_swap(base + root * sz, base + child * sz, sz, tmp);
        root = child;
    }
}

static void sw_heapsort(char* base, size_t n, size_t sz, sw_cmp cmp, char* tmp) {
    if (n < 2) return;
    for (size_t i = n / 2; i-- > 0;) sw_sift_down(base, i, n, sz, cmp, tmp);
    for (size_t e = n; e-- > 1;) {
        sw_swap(base, base + e * sz, sz, tmp);
        sw_sift_down(base, 0, e, sz, cmp, tmp);
    }
}

static inline char* sw_med3(char* a, char* b, char* c, sw_cmp cmp) {
    return cmp(a, b) < 0 ? (cmp(b, c) < 0 ? b : (cmp(a, c) < 0 ? c : a))
                         : (cmp(b, c) > 0 ? b : (cmp(a, c) < 0 ? a : c));
}

static char* sw_ninther(char* base, size_t n, size_t sz, sw_cmp cmp) {
    size_t step = n / 8;
    char* a = sw_med3(base, base + step * sz, base + 2 * step * sz, cmp);
    char* b = sw_med3(base + 3 * step * sz, base + 4 * step * sz, base + 5 * step * sz, cmp);
    char* c = sw_med3(base + 6 * step * sz, base + 7 * step * sz, base + (n - 1) * sz, cmp);
    return sw_med3(a, b, c, cmp);
}

/** Hoare partition over base[lo..hi]; pivot value resides at index lo.
 * Returns the pivot's final position. */
static size_t sw_partition(char* base, size_t lo, size_t hi, size_t sz, sw_cmp cmp, char* tmp) {
    size_t i = lo + 1;
    size_t j = hi;
    for (;;) {
        while (i <= j && cmp(base + i * sz, base + lo * sz) < 0) i++;
        while (i <= j && cmp(base + j * sz, base + lo * sz) > 0) j--;
        if (i >= j) break;
        sw_swap(base + i * sz, base + j * sz, sz, tmp);
        i++;
        j--;
    }
    sw_swap(base + lo * sz, base + j * sz, sz, tmp);
    return j;
}

/**
 * Structured-data pre-check: returns
 *   1  if [base, base+n) is non-descending (already sorted),
 *  -1  if it is non-ascending (reverse it in place),
 *   0  otherwise.
 * The scan stops at the first element that proves neither, so random
 * data exits after ~2 comparisons.  Presorted / reversed / all-equal
 * inputs -- glibc's best cases -- become a single linear pass.
 */
static int sw_precheck(char* base, size_t n, size_t sz, sw_cmp cmp, char* tmp) {
    if (n < 2) return 1;
    int asc = 1, desc = 1;
    for (size_t i = 1; i < n; i++) {
        int c = cmp(base + i * sz, base + (i - 1) * sz);
        if (c < 0)
            asc = 0;
        else if (c > 0)
            desc = 0;
        if (!asc && !desc) return 0;
    }
    if (asc) return 1;
    if (desc) {
        /* reverse in place */
        char* lo = base;
        char* hi = base + (n - 1) * sz;
        while (lo < hi) {
            sw_swap(lo, hi, sz, tmp);
            lo += sz;
            hi -= sz;
        }
        return -1;
    }
    return 0; /* unreachable: loop exits only when a flag survives */
}

static void sw_qsort_rec(char* base, size_t n, size_t sz, sw_cmp cmp, char* tmp, size_t depth) {
    while (n > SW_INSERTION_THRESHOLD) {
        int pre = sw_precheck(base, n, sz, cmp, tmp);
        if (pre != 0) return;

        if (depth-- == 0) {
            sw_heapsort(base, n, sz, cmp, tmp);
            return;
        }

        char* pivot;
        if (n > SW_NINTHER_THRESHOLD) {
            pivot = sw_ninther(base, n, sz, cmp);
        } else {
            pivot = sw_med3(base, base + (n / 2) * sz, base + (n - 1) * sz, cmp);
        }
        if (pivot != base) sw_swap(base, pivot, sz, tmp);

        size_t p = sw_partition(base, 0, n - 1, sz, cmp, tmp);
        size_t left = p;
        size_t right = n - p - 1;

        if (left < right) {
            sw_qsort_rec(base, left, sz, cmp, tmp, depth);
            base += (p + 1) * sz;
            n = right;
        } else {
            sw_qsort_rec(base + (p + 1) * sz, right, sz, cmp, tmp, depth);
            n = left;
        }
    }

    if (n > 1) sw_insertion_sort(base, base + (n - 1) * sz, sz, cmp, tmp);
}

void sol_qsort(void* base, size_t n, size_t size, int (*compar)(const void*, const void*)) {
    if (!base || !compar || size == 0 || n < 2) return;

    char stack_tmp[SW_STACK_TMP_MAX];
    char* heap_tmp = NULL;
    if (size > SW_STACK_TMP_MAX) {
        heap_tmp = malloc(size);
        if (!heap_tmp) {
            qsort(base, n, size, compar);
            return;
        }
    }

    size_t depth = 0;
    for (size_t v = n; v; v >>= 1) depth++;
    depth *= 2;

    sw_qsort_rec((char*)base, n, size, compar, heap_tmp ? heap_tmp : stack_tmp, depth);
    free(heap_tmp);
}

/* ========================================================================= */
/* Specialized sorts: branchless quicksort + LSD radix                       */
/* ========================================================================= */

#define SOLIDC_RADIX_MIN ((size_t)1024)

/*
 * SOLIDC_SORT_DEF parameters:
 *   suffix   — API name fragment
 *   T        — element type
 *   U        — unsigned key type for radix (same width)
 *   WIDTH    — number of radix bytes (sizeof(U))
 *   TO_KEY(k,x)   / FROM_KEY(k,x) — statements mapping element <-> key var
 *   LESS(a,b)     — strict less-than on T
 */
#define SOLIDC_SORT_DEF(suffix, T, U, WIDTH, TO_KEY, FROM_KEY, LESS)                                     \
    static inline bool solidc_lt_##suffix(T a, T b);                                                     \
    static inline bool solidc_lt_##suffix(T a, T b) { return LESS; }                                     \
                                                                                                         \
    static inline size_t solidc_med3_idx_##suffix(const T* a, size_t x, size_t y, size_t z) {            \
        return solidc_lt_##suffix(a[y], a[x])                                                            \
                   ? (solidc_lt_##suffix(a[z], a[y]) ? y : (solidc_lt_##suffix(a[z], a[x]) ? z : x))     \
                   : (solidc_lt_##suffix(a[y], a[z]) ? y : (solidc_lt_##suffix(a[x], a[z]) ? x : z));    \
    }                                                                                                    \
                                                                                                         \
    static inline size_t solidc_pivot_index_##suffix(const T* a, size_t n) {                             \
        if (n > 128) {                                                                                   \
            size_t s = n / 8;                                                                            \
            size_t m1 = solidc_med3_idx_##suffix(a, 0, s, 2 * s);                                        \
            size_t m2 = solidc_med3_idx_##suffix(a, 3 * s, 4 * s, 5 * s);                                \
            size_t m3 = solidc_med3_idx_##suffix(a, 6 * s, 7 * s, n - 1);                                \
            return solidc_med3_idx_##suffix(a, m1, m2, m3);                                              \
        }                                                                                                \
        return solidc_med3_idx_##suffix(a, 0, n / 2, n - 1);                                             \
    }                                                                                                    \
                                                                                                         \
    /* Branchless Lomuto over a[0..len): returns count < pv.  Every element                              \
     * is written through conditional moves -- no data-dependent branches. */                            \
    static inline size_t solidc_partition_##suffix(T* a, size_t len, T pv) {                             \
        size_t store = 0;                                                                                \
        for (size_t i = 0; i < len; i++) {                                                               \
            T v = a[i];                                                                                  \
            unsigned lt = (unsigned)solidc_lt_##suffix(v, pv);                                           \
            T d = a[store];                                                                              \
            a[store] = lt ? v : d;                                                                       \
            if (i != store) a[i] = lt ? d : v;                                                           \
            store += lt;                                                                                 \
        }                                                                                                \
        return store;                                                                                    \
    }                                                                                                    \
                                                                                                         \
    /* Equality-band extraction on region a[0..len).  Moves == pv to the                                 \
     * FRONT and returns their count.  gt_disc selects the discriminator:                                \
     *   true  -> region members are >= pv (pivot was the minimum)                                       \
     *   false -> region members are <= pv (pivot was the maximum)                                       \
     * Cold path: only runs on degenerate splits. */                                                     \
    static inline size_t solidc_split_eq_##suffix(T* a, size_t len, T pv, bool gt_disc) {                \
        size_t st = 0;                                                                                   \
        for (size_t i = 0; i < len; i++) {                                                               \
            T v = a[i];                                                                                  \
            unsigned side = (unsigned)(gt_disc ? solidc_lt_##suffix(pv, v) : solidc_lt_##suffix(v, pv)); \
            T d = a[st];                                                                                 \
            a[st] = side ? d : v;                                                                        \
            if (i != st) a[i] = side ? v : d;                                                            \
            st += (size_t)(1u - side);                                                                   \
        }                                                                                                \
        return st;                                                                                       \
    }                                                                                                    \
                                                                                                         \
    static inline void solidc_isort_##suffix(T* a, size_t n) {                                           \
        for (size_t i = 1; i < n; i++) {                                                                 \
            T v = a[i];                                                                                  \
            size_t j = i;                                                                                \
            while (j > 0 && solidc_lt_##suffix(v, a[j - 1])) {                                           \
                a[j] = a[j - 1];                                                                         \
                j--;                                                                                     \
            }                                                                                            \
            a[j] = v;                                                                                    \
        }                                                                                                \
    }                                                                                                    \
                                                                                                         \
    static inline void solidc_sift_##suffix(T* a, size_t root, size_t end) {                             \
        for (;;) {                                                                                       \
            size_t c = 2 * root + 1;                                                                     \
            if (c >= end) break;                                                                         \
            if (c + 1 < end && solidc_lt_##suffix(a[c], a[c + 1])) c++;                                  \
            if (!solidc_lt_##suffix(a[root], a[c])) break;                                               \
            T t = a[root];                                                                               \
            a[root] = a[c];                                                                              \
            a[c] = t;                                                                                    \
            root = c;                                                                                    \
        }                                                                                                \
    }                                                                                                    \
                                                                                                         \
    static void solidc_heapsort_##suffix(T* a, size_t n) {                                               \
        if (n < 2) return;                                                                               \
        for (size_t i = n / 2; i-- > 0;) solidc_sift_##suffix(a, i, n);                                  \
        for (size_t e = n; e-- > 1;) {                                                                   \
            T t = a[0];                                                                                  \
            a[0] = a[e];                                                                                 \
            a[e] = t;                                                                                    \
            solidc_sift_##suffix(a, 0, e);                                                               \
        }                                                                                                \
    }                                                                                                    \
                                                                                                         \
    /* ---- LSD radix on order-preserving unsigned keys ---- */                                          \
    static void solidc_radix_##suffix(T* a, T* tmp, size_t n) {                                          \
        U (*to_key)(T) = solidc_to_key_##suffix;                                                         \
        T (*from_key)(U) = solidc_from_key_##suffix;                                                     \
                                                                                                         \
        U* src = (U*)a;                                                                                  \
        U* dst = (U*)tmp;                                                                                \
        for (size_t i = 0; i < n; i++) src[i] = to_key(a[i]);                                            \
                                                                                                         \
        uint32_t hist[WIDTH][256];                                                                       \
        memset(hist, 0, sizeof(hist));                                                                   \
        for (size_t i = 0; i < n; i++) {                                                                 \
            U k = src[i];                                                                                \
            for (uint32_t b = 0; b < WIDTH; b++) hist[b][(k >> (8 * b)) & 0xFF]++;                       \
        }                                                                                                \
                                                                                                         \
        U* from = src;                                                                                   \
        U* to = dst;                                                                                     \
        for (uint32_t b = 0; b < WIDTH; b++) {                                                           \
            /* Skip uniform columns: every byte identical => no reordering. */                           \
            uint32_t col_total = 0;                                                                      \
            for (uint32_t s = 0; s < 256; s++) col_total += hist[b][s];                                  \
            (void)col_total;                                                                             \
            bool uniform = false;                                                                        \
            for (uint32_t s = 0; s < 256; s++)                                                           \
                if (hist[b][s] == n) {                                                                   \
                    uniform = true;                                                                      \
                    break;                                                                               \
                }                                                                                        \
            if (uniform) continue;                                                                       \
                                                                                                         \
            uint32_t pos[256];                                                                           \
            uint32_t sum = 0;                                                                            \
            for (uint32_t s = 0; s < 256; s++) {                                                         \
                pos[s] = sum;                                                                            \
                sum += hist[b][s];                                                                       \
            }                                                                                            \
            for (size_t i = 0; i < n; i++) {                                                             \
                U k = from[i];                                                                           \
                to[pos[(k >> (8 * b)) & 0xFF]++] = k;                                                    \
            }                                                                                            \
            U* t = from;                                                                                 \
            from = to;                                                                                   \
            to = t;                                                                                      \
        }                                                                                                \
                                                                                                         \
        if (from != src) memcpy(src, from, n * sizeof(U));                                               \
        for (size_t i = 0; i < n; i++) a[i] = from_key(((U*)a)[i]);                                      \
    }                                                                                                    \
                                                                                                         \
    static void solidc_sort_rec_##suffix(T* a, size_t n, size_t depth, T* radix_buf) {                   \
        while (n > 24) {                                                                                 \
            if (depth-- == 0) {                                                                          \
                solidc_heapsort_##suffix(a, n);                                                          \
                return;                                                                                  \
            }                                                                                            \
                                                                                                         \
            /* Structured-data pre-check (see generic path comment). */                                  \
            {                                                                                            \
                int asc = 1, desc = 1;                                                                   \
                for (size_t i = 1; i < n; i++) {                                                         \
                    if (solidc_lt_##suffix(a[i], a[i - 1]))                                              \
                        asc = 0;                                                                         \
                    else if (solidc_lt_##suffix(a[i - 1], a[i]))                                         \
                        desc = 0;                                                                        \
                    if (!asc && !desc) break;                                                            \
                }                                                                                        \
                if (asc) return;                                                                         \
                if (desc) {                                                                              \
                    for (size_t i = 0, j = n - 1; i < j; i++, j--) {                                     \
                        T t = a[i];                                                                      \
                        a[i] = a[j];                                                                     \
                        a[j] = t;                                                                        \
                    }                                                                                    \
                    return;                                                                              \
                }                                                                                        \
            }                                                                                            \
                                                                                                         \
            /* Large arrays: radix dominates once the column skips cannot                                \
             * save work either. */                                                                      \
            if (radix_buf && n >= SOLIDC_RADIX_MIN) {                                                    \
                solidc_radix_##suffix(a, radix_buf, n);                                                  \
                return;                                                                                  \
            }                                                                                            \
                                                                                                         \
            /* Pivot instance moved out of the partitioned range so the                                  \
             * recursion ALWAYS shrinks without any equality scan. */                                    \
            size_t pidx = solidc_pivot_index_##suffix(a, n);                                             \
            T pv = a[pidx];                                                                              \
            a[pidx] = a[n - 1];                                                                          \
                                                                                                         \
            size_t store = solidc_partition_##suffix(a, n - 1, pv);                                      \
            /* Swap the pivot into its final slot -- a[store] holds a real                               \
             * element (>= pv) that must move to the right side, so a plain                              \
             * assignment would DESTROY it (caught by multiset tests). */                                \
            T displaced = a[store];                                                                      \
            a[store] = pv;                                                                               \
            a[n - 1] = displaced;                                                                        \
            size_t left = store;                                                                         \
            size_t right = n - store - 1;                                                                \
                                                                                                         \
            if (left != 0 && right != 0) {                                                               \
                /* Healthy split: plain two-way recursion.  No equality                                  \
                 * pass on random data -- the saw_eq trap is gone. */                                    \
                if (left <= right) {                                                                     \
                    solidc_sort_rec_##suffix(a, left, depth, radix_buf);                                 \
                    a += store + 1;                                                                      \
                    n = right;                                                                           \
                } else {                                                                                 \
                    solidc_sort_rec_##suffix(a + store + 1, right, depth, radix_buf);                    \
                    n = left;                                                                            \
                }                                                                                        \
                continue;                                                                                \
            }                                                                                            \
                                                                                                         \
            /* Degenerate split (pivot was an extreme value): extract the                                \
             * equality band so duplicate-heavy inputs stay linear. */                                   \
            if (left == 0) {                                                                             \
                /* Pivot was the minimum: a[1..n) are all >= pv. */                                      \
                size_t eq = solidc_split_eq_##suffix(a + 1, n - 1, pv, true);                            \
                if (eq == n - 1) return; /* every element == pv */                                       \
                a += 1 + eq;                                                                             \
                n -= 1 + eq; /* continue with the strictly-greater tail */                               \
            } else {                                                                                     \
                /* Pivot was the maximum: a[0..left) are all <= pv. */                                   \
                size_t eq = solidc_split_eq_##suffix(a, left, pv, false);                                \
                if (eq == left) return;                                                                  \
                solidc_sort_rec_##suffix(a + eq, left - eq, depth, radix_buf);                           \
                return;                                                                                  \
            }                                                                                            \
        }                                                                                                \
        if (n > 1) solidc_isort_##suffix(a, n);                                                          \
    }                                                                                                    \
                                                                                                         \
    void sol_sort_##suffix(T* a, size_t n) {                                                             \
        if (!a || n < 2) return;                                                                         \
        T* radix_buf = NULL;                                                                             \
        if (n >= SOLIDC_RADIX_MIN) {                                                                     \
            radix_buf = malloc(n * sizeof(T));                                                           \
            /* malloc failure simply disables the radix path. */                                         \
        }                                                                                                \
        size_t depth = 0;                                                                                \
        for (size_t v = n; v; v >>= 1) depth++;                                                          \
        solidc_sort_rec_##suffix(a, n, depth * 2, radix_buf);                                            \
        free(radix_buf);                                                                                 \
    }

/* ---- per-type key mappings ---- */

static inline uint32_t solidc_to_key_i32(int32_t x) { return (uint32_t)x ^ 0x80000000u; }
static inline int32_t solidc_from_key_i32(uint32_t k) { return (int32_t)(k ^ 0x80000000u); }

static inline uint64_t solidc_to_key_i64(int64_t x) { return (uint64_t)x ^ 0x8000000000000000ULL; }
static inline int64_t solidc_from_key_i64(uint64_t k) { return (int64_t)(k ^ 0x8000000000000000ULL); }

/** IEEE-754 total-order twist; NaNs are clamped past +inf so they sort to
 * the END (matching the documented contract).  Unmapping collapses every
 * NaN to the canonical quiet NaN, whose payload the sort intentionally
 * does not preserve. */
static inline uint64_t solidc_to_key_f64(double d) {
    uint64_t u;
    memcpy(&u, &d, sizeof(u));
    if (SOLIDC_ISNAN(d)) return UINT64_MAX;
    uint64_t mask = (uint64_t)(-(int64_t)(u >> 63)) | 0x8000000000000000ULL;
    return u ^ mask;
}
static inline double solidc_from_key_f64(uint64_t k) {
    if (k == UINT64_MAX) {
        double nan_canonical;
        uint64_t bits = 0x7FF8000000000000ULL;
        memcpy(&nan_canonical, &bits, sizeof(bits));
        return nan_canonical;
    }
    uint64_t mask = (uint64_t)(-(int64_t)(k >> 63)) | 0x8000000000000000ULL;
    uint64_t u = k ^ mask;
    double d;
    memcpy(&d, &u, sizeof(d));
    return d;
}

/* NOTE: solidc_med3_idx_ must be defined before pivot_index in the macro;
 * the macro references it, C allows forward use within the TU after the
 * whole expansion unit is compiled -- verified by build. */

SOLIDC_SORT_DEF(i32, int32_t, uint32_t, 4, solidc_to_key_i32, solidc_from_key_i32, a < b)
SOLIDC_SORT_DEF(i64, int64_t, uint64_t, 8, solidc_to_key_i64, solidc_from_key_i64, a < b)
SOLIDC_SORT_DEF(f64, double, uint64_t, 8, solidc_to_key_f64, solidc_from_key_f64,
                (!SOLIDC_ISNAN(a)) && (SOLIDC_ISNAN(b) || a < b))
