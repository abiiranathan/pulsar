/**
 * @file map_swiss.c
 * @brief High-performance Swiss table implementation of the swiss_map.h API.
 */
#include "../include/swiss_map.h"

#if defined(__SSE2__)
    #include <emmintrin.h>
#elif defined(__ARM_NEON) || defined(__ARM_NEON__)
    #include <arm_neon.h>
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "macros.h"

#ifdef _MSC_VER
    #include <BaseTsd.h>
    #ifndef ssize_t
typedef SSIZE_T ssize_t;
    #endif
#endif

#define XXH_INLINE_ALL
#include <xxhash.h>

#include "../include/lock.h"

/* ------------------------------------------------------------------ */
/* Constants & Layout Definitions                                      */
/* ------------------------------------------------------------------ */

#define SW_GROUP   16   /* SIMD group width                     */
#define SW_EMPTY   0x80 /* ctrl byte: empty slot                */
#define SW_DELETED 0xFE /* ctrl byte: tombstone                 */
#define SW_MASK_H2 0x7F /* H2 = hash & 0x7F stored in ctrl      */

#define SW_MAX_LOAD_NUM 7
#define SW_MAX_LOAD_DEN 8

typedef struct {
    void* key;
    void* value;
    size_t len;
} SwissSlot;

struct swiss_map {
    unsigned char* ctrl; /* Base of single-allocation block (ctrl metadata) */
    SwissSlot* slots;    /* Aligned pointer to slots array inside block     */
    size_t size;         /* Live entries                                    */
    size_t tombs;        /* Tombstones                                      */
    size_t capacity;     /* Power of 2 (>= 16)                              */
    size_t growth_left;  /* Remaining growth budget                         */
    float max_load_factor;
    HashFunction hash;
    KeyCmpFunction key_compare;
    KeyFreeFunction key_free;
    ValueFreeFunction value_free;
    Lock lock;
};

/* ------------------------------------------------------------------ */
/* SIMD Group Scanning Abstraction                                     */
/* ------------------------------------------------------------------ */

#if defined(__SSE2__)
    #define SW_HAVE_SSE2 1
typedef __m128i sw_group_t;

static inline sw_group_t sw_group_load(const unsigned char* p) { return _mm_loadu_si128((const __m128i*)p); }
static inline uint32_t sw_group_match(sw_group_t g, unsigned char needle) {
    return (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(g, _mm_set1_epi8((char)needle)));
}
static inline uint32_t sw_group_match_empty(sw_group_t g) {
    return (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(g, _mm_set1_epi8((char)SW_EMPTY)));
}
static inline uint32_t sw_group_match_deleted(sw_group_t g) {
    return (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(g, _mm_set1_epi8((char)SW_DELETED)));
}

#elif defined(__ARM_NEON) || defined(__ARM_NEON__)
    #define SW_HAVE_NEON 1
typedef uint8x16_t sw_group_t;

static inline sw_group_t sw_group_load(const unsigned char* p) { return vld1q_u8(p); }

static inline uint32_t sw_neon_movemask(uint8x16_t eq) {
    static const uint8_t mask_bits[16]
        __attribute__((aligned(16))) = {1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128};
    uint8x16_t masked = vandq_u8(eq, vld1q_u8(mask_bits));
    #if defined(__aarch64__) || defined(_M_ARM64)
    uint8_t low_sum = vaddv_u8(vget_low_u8(masked));
    uint8_t high_sum = vaddv_u8(vget_high_u8(masked));
    return (uint32_t)low_sum | ((uint32_t)high_sum << 8);
    #else
    uint8x8_t p1 = vpadd_u8(vget_low_u8(masked), vget_high_u8(masked));
    uint8x8_t p2 = vpadd_u8(p1, p1);
    uint8x8_t p3 = vpadd_u8(p2, p2);
    return (uint32_t)vget_lane_u8(p3, 0) | ((uint32_t)vget_lane_u8(p3, 1) << 8);
    #endif
}

static inline uint32_t sw_group_match(sw_group_t g, unsigned char needle) {
    return sw_neon_movemask(vceqq_u8(g, vdupq_n_u8(needle)));
}
static inline uint32_t sw_group_match_empty(sw_group_t g) {
    return sw_neon_movemask(vceqq_u8(g, vdupq_n_u8(SW_EMPTY)));
}
static inline uint32_t sw_group_match_deleted(sw_group_t g) {
    return sw_neon_movemask(vceqq_u8(g, vdupq_n_u8(SW_DELETED)));
}

#else
typedef struct {
    unsigned char b[SW_GROUP];
} sw_group_t;

static inline sw_group_t sw_group_load(const unsigned char* p) {
    sw_group_t g;
    memcpy(g.b, p, SW_GROUP);
    return g;
}
static inline uint32_t sw_group_match(sw_group_t g, unsigned char needle) {
    uint32_t m = 0;
    for (int i = 0; i < SW_GROUP; i++) {
        if (g.b[i] == needle) m |= (1u << i);
    }
    return m;
}
static inline uint32_t sw_group_match_empty(sw_group_t g) { return sw_group_match(g, SW_EMPTY); }
static inline uint32_t sw_group_match_deleted(sw_group_t g) { return sw_group_match(g, SW_DELETED); }
#endif

/* ------------------------------------------------------------------ */
/* Bit & Hash Helpers                                                 */
/* ------------------------------------------------------------------ */

static inline size_t sw_h1(size_t hash, size_t mask) { return (hash >> 7) & mask; }
static inline unsigned char sw_h2(size_t hash) { return (unsigned char)(hash & SW_MASK_H2); }
static inline bool sw_is_full(unsigned char c) { return (c & 0x80) == 0; }

static inline size_t sw_cap_round(size_t n) {
    size_t c = 16;
    while (c < n) c <<= 1;
    return c;
}

static inline bool sw_key_eq(KeyCmpFunction cmp, const void* k1, const void* k2) {
    return (k1 == k2) || cmp((void*)k1, (void*)k2);
}

static inline size_t swiss_default_hash(const void* key, size_t len) {
    if (len <= 8) {
        uint64_t v = 0;
        if (len > 0) memcpy(&v, key, len);
        return (size_t)v;
    }
    return (size_t)XXH3_64bits(key, len);
}

/** David Stafford Mix13 finalizer: full avalanche with low latency (2 muls, 3 shifts). */
static inline size_t swiss_finalize(size_t h) {
    uint64_t x = (uint64_t)h;
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return (size_t)x;
}

static inline size_t swiss_hash_of(SwissMap* m, const void* key, size_t key_len) {
    if (m->hash) return swiss_finalize(m->hash(key, key_len));
    return swiss_finalize(swiss_default_hash(key, key_len));
}

static inline void swiss_ctrl_init(SwissMap* m) { memset(m->ctrl, SW_EMPTY, m->capacity + SW_GROUP); }

static inline void swiss_set_ctrl(SwissMap* m, size_t i, unsigned char h2) {
    m->ctrl[i] = h2;
    if (i < SW_GROUP) m->ctrl[m->capacity + i] = h2; /* Mirrored tail group */
}

/* ------------------------------------------------------------------ */
/* Memory Allocation (Contiguous Single-Block)                        */
/* ------------------------------------------------------------------ */

static bool swiss_alloc_table(size_t cap, unsigned char** ctrl_out, SwissSlot** slots_out) {
    size_t ctrl_bytes = cap + SW_GROUP + SW_GROUP;
    size_t slots_offset = (ctrl_bytes + 15) & ~15U; /* 16-byte align slots */
    size_t total_alloc = slots_offset + cap * sizeof(SwissSlot);

    unsigned char* block = (unsigned char*)calloc(1, total_alloc);
    if (!block) return false;

    *ctrl_out = block;
    *slots_out = (SwissSlot*)(block + slots_offset);
    return true;
}

SwissMap* swiss_create(const SwissConfig* config) {
    if (!config || !config->key_compare) return NULL;

    SwissMap* m = (SwissMap*)calloc(1, sizeof(SwissMap));
    if (!m) return NULL;

    size_t cap = config->initial_capacity > 0 ? sw_cap_round(config->initial_capacity) : 16;
    if (cap < 16) cap = 16;
    if (cap > SIZE_MAX / (sizeof(SwissSlot) * 2)) {
        free(m);
        return NULL;
    }

    if (!swiss_alloc_table(cap, &m->ctrl, &m->slots)) {
        free(m);
        return NULL;
    }

    m->capacity = cap;
    swiss_ctrl_init(m);
    /* Default 7/8 matches the abseil sweet spot; an explicit lower
     * max_load_factor is honored.  (Defaulting to 0.75 made every table
     * one power-of-two larger than necessary -- measured 2x slowdown on
     * insert-heavy workloads from the extra resize + footprint.) */
    m->max_load_factor =
        (config->max_load_factor > 0.1f && config->max_load_factor <= 0.875f) ? config->max_load_factor : 0.875f;
    m->key_compare = config->key_compare;
    m->key_free = config->key_free;
    m->value_free = config->value_free;
    m->hash = config->hash_func;
    m->growth_left = (size_t)((float)cap * m->max_load_factor);
    lock_init(&m->lock);
    return m;
}

void swiss_destroy(SwissMap* m) {
    if (!m) return;

    if (m->key_free || m->value_free) {
        for (size_t i = 0; i < m->capacity; i++) {
            if (sw_is_full(m->ctrl[i])) {
                SwissSlot* s = &m->slots[i];
                if (m->key_free) m->key_free(s->key);
                if (m->value_free) m->value_free(s->value);
            }
        }
    }

    free(m->ctrl); /* Frees both ctrl and slots single-block */
    lock_free(&m->lock);
    free(m);
}

size_t swiss_length(SwissMap* m) { return m ? m->size : 0; }
size_t swiss_capacity(SwissMap* m) { return m ? m->capacity : 0; }

/* ------------------------------------------------------------------ */
/* Resize & Rehash                                                    */
/* ------------------------------------------------------------------ */

static bool swiss_resize(SwissMap* m, size_t new_cap) {
    unsigned char* old_block = m->ctrl;
    SwissSlot* old_slots = m->slots;
    size_t old_cap = m->capacity;

    unsigned char* new_ctrl;
    SwissSlot* new_slots;
    if (!swiss_alloc_table(new_cap, &new_ctrl, &new_slots)) {
        return false;
    }

    m->ctrl = new_ctrl;
    m->slots = new_slots;
    m->capacity = new_cap;
    swiss_ctrl_init(m);
    m->size = 0;
    m->tombs = 0;

    const size_t mask = new_cap - 1;

#if defined(SW_HAVE_SSE2)
    __m128i empty_vec = _mm_set1_epi8((char)SW_EMPTY);
#endif

    for (size_t i = 0; i < old_cap; i++) {
        if (!sw_is_full(old_block[i])) continue;

        SwissSlot* old_s = &old_slots[i];
        size_t h = swiss_hash_of(m, old_s->key, old_s->len);
        size_t pos = sw_h1(h, mask);
        unsigned char h2 = sw_h2(h);
        size_t stride = 0;

        for (;;) {
            sw_group_t g = sw_group_load(m->ctrl + pos);
#if defined(SW_HAVE_SSE2)
            uint32_t emp = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(g, empty_vec));
#else
            uint32_t emp = sw_group_match_empty(g);
#endif
            if (emp) {
                int j = SOLIDC_CTZ(emp);
                size_t slot = (pos + (size_t)j) & mask;
                swiss_set_ctrl(m, slot, h2);
                m->slots[slot] = *old_s;
                m->size++;
                break;
            }
            stride += SW_GROUP;
            pos = (pos + stride) & mask;
        }
    }

    free(old_block);

    size_t max_allowed = (size_t)((float)new_cap * m->max_load_factor);
    m->growth_left = (max_allowed > m->size) ? (max_allowed - m->size) : 0;
    return true;
}

static inline bool swiss_maybe_grow(SwissMap* m) {
    if (SOLIDC_EXPECT(m->growth_left > 0, 1)) return true;

    if (m->tombs > (m->capacity >> 5) + (m->size >> 5)) {
        return swiss_resize(m, m->capacity);
    }
    return swiss_resize(m, m->capacity * 2);
}

/* ------------------------------------------------------------------ */
/* Map Operations                                                     */
/* ------------------------------------------------------------------ */

bool swiss_set(SwissMap* m, void* key, size_t key_len, void* value) {
    if (SOLIDC_EXPECT(!m || !key, 0)) return false;

    if (SOLIDC_EXPECT(m->growth_left == 0, 0)) {
        if (!swiss_maybe_grow(m)) return false;
    }

    size_t h = swiss_hash_of(m, key, key_len);
    size_t mask = m->capacity - 1;
    size_t pos = sw_h1(h, mask);
    unsigned char h2 = sw_h2(h);

    ssize_t target_slot = -1;
    bool target_is_tomb = false;
    size_t stride = 0;

#if defined(SW_HAVE_SSE2)
    __m128i match_vec = _mm_set1_epi8((char)h2);
    __m128i empty_vec = _mm_set1_epi8((char)SW_EMPTY);
    __m128i del_vec = _mm_set1_epi8((char)SW_DELETED);
#endif

    for (;;) {
        sw_group_t g = sw_group_load(m->ctrl + pos);

#if defined(SW_HAVE_SSE2)
        uint32_t matches = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(g, match_vec));
#else
        uint32_t matches = sw_group_match(g, h2);
#endif
        while (matches) {
            int j = SOLIDC_CTZ(matches);
            matches &= matches - 1;
            size_t slot = (pos + (size_t)j) & mask;
            SwissSlot* s = &m->slots[slot];
            if (sw_key_eq(m->key_compare, s->key, key)) {
                if (m->value_free) m->value_free(s->value);
                s->value = value;
                return true;
            }
        }

#if defined(SW_HAVE_SSE2)
        uint32_t empties = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(g, empty_vec));
#else
        uint32_t empties = sw_group_match_empty(g);
#endif
        if (empties) {
            if (target_slot < 0) {
                target_slot = (ssize_t)((pos + (size_t)SOLIDC_CTZ(empties)) & mask);
                target_is_tomb = false;
            }
            break; /* Key cannot exist past first empty slot */
        }

        if (target_slot < 0) {
#if defined(SW_HAVE_SSE2)
            uint32_t dels = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(g, del_vec));
#else
            uint32_t dels = sw_group_match_deleted(g);
#endif
            if (dels) {
                target_slot = (ssize_t)((pos + (size_t)SOLIDC_CTZ(dels)) & mask);
                target_is_tomb = true;
            }
        }

        stride += SW_GROUP;
        pos = (pos + stride) & mask;
    }

    /* Single-pass insertion */
    size_t slot = (size_t)target_slot;
    if (target_is_tomb) {
        m->tombs--;
    } else {
        m->growth_left--;
    }

    swiss_set_ctrl(m, slot, h2);
    SwissSlot* s = &m->slots[slot];
    s->key = key;
    s->value = value;
    s->len = key_len;
    m->size++;
    return true;
}

void* swiss_get(SwissMap* m, void* key, size_t key_len) {
    if (SOLIDC_EXPECT(!m || !key, 0)) return NULL;

    size_t h = swiss_hash_of(m, key, key_len);
    size_t mask = m->capacity - 1;
    size_t pos = sw_h1(h, mask);
    unsigned char h2 = sw_h2(h);
    size_t stride = 0;

#if defined(SW_HAVE_SSE2)
    __m128i match_vec = _mm_set1_epi8((char)h2);
    __m128i empty_vec = _mm_set1_epi8((char)SW_EMPTY);
#endif

    for (;;) {
        sw_group_t g = sw_group_load(m->ctrl + pos);

#if defined(SW_HAVE_SSE2)
        uint32_t matches = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(g, match_vec));
#else
        uint32_t matches = sw_group_match(g, h2);
#endif
        while (matches) {
            int j = SOLIDC_CTZ(matches);
            matches &= matches - 1;
            size_t slot = (pos + (size_t)j) & mask;
            SwissSlot* s = &m->slots[slot];
            if (sw_key_eq(m->key_compare, s->key, key)) {
                return s->value;
            }
        }

#if defined(SW_HAVE_SSE2)
        uint32_t empties = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(g, empty_vec));
#else
        uint32_t empties = sw_group_match_empty(g);
#endif
        if (empties) return NULL;

        stride += SW_GROUP;
        pos = (pos + stride) & mask;
    }
}

bool swiss_remove(SwissMap* m, void* key, size_t key_len) {
    if (SOLIDC_EXPECT(!m || !key, 0)) return false;

    size_t h = swiss_hash_of(m, key, key_len);
    size_t mask = m->capacity - 1;
    size_t pos = sw_h1(h, mask);
    unsigned char h2 = sw_h2(h);
    size_t stride = 0;

#if defined(SW_HAVE_SSE2)
    __m128i match_vec = _mm_set1_epi8((char)h2);
    __m128i empty_vec = _mm_set1_epi8((char)SW_EMPTY);
#endif

    for (;;) {
        sw_group_t g = sw_group_load(m->ctrl + pos);

#if defined(SW_HAVE_SSE2)
        uint32_t matches = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(g, match_vec));
#else
        uint32_t matches = sw_group_match(g, h2);
#endif
        while (matches) {
            int j = SOLIDC_CTZ(matches);
            matches &= matches - 1;
            size_t slot = (pos + (size_t)j) & mask;
            SwissSlot* s = &m->slots[slot];
            if (sw_key_eq(m->key_compare, s->key, key)) {
                if (m->key_free) m->key_free(s->key);
                if (m->value_free) m->value_free(s->value);
                s->key = NULL;
                s->value = NULL;
                s->len = 0;
                swiss_set_ctrl(m, slot, SW_DELETED);
                m->size--;
                m->tombs++;
                return true;
            }
        }

#if defined(SW_HAVE_SSE2)
        uint32_t empties = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(g, empty_vec));
#else
        uint32_t empties = sw_group_match_empty(g);
#endif
        if (empties) return false;

        stride += SW_GROUP;
        pos = (pos + stride) & mask;
    }
}

/* ------------------------------------------------------------------ */
/* Iterator                                                           */
/* ------------------------------------------------------------------ */

swiss_iterator swiss_iter(SwissMap* m) {
    swiss_iterator it = {.map = m, .index = 0};
    return it;
}

bool swiss_next(swiss_iterator* it, void** key, void** value) {
    SwissMap* m = it->map;
    if (!m) return false;
    size_t cap = m->capacity;
    size_t i = it->index;

    while (i < cap) {
        /* Vectorized skipping of empty/tombstone 16-slot groups */
        if ((i & 15) == 0 && i + SW_GROUP <= cap) {
#if defined(SW_HAVE_SSE2)
            sw_group_t g = sw_group_load(m->ctrl + i);
            uint32_t non_full = (uint32_t)_mm_movemask_epi8(g); /* MSB set = empty/tomb */
            uint32_t full_mask = (~non_full) & 0xFFFF;
#else
            uint32_t full_mask = 0;
            for (int k = 0; k < SW_GROUP; k++) {
                if (sw_is_full(m->ctrl[i + k])) full_mask |= (1u << k);
            }
#endif
            if (full_mask == 0) {
                i += SW_GROUP;
                continue;
            }
            int j = SOLIDC_CTZ(full_mask);
            i += (size_t)j;
            it->index = i + 1;
            SwissSlot* s = &m->slots[i];
            if (key) *key = s->key;
            if (value) *value = s->value;
            return true;
        }

        if (sw_is_full(m->ctrl[i])) {
            it->index = i + 1;
            SwissSlot* s = &m->slots[i];
            if (key) *key = s->key;
            if (value) *value = s->value;
            return true;
        }
        i++;
    }

    it->index = cap;
    return false;
}

/* ------------------------------------------------------------------ */
/* Thread-Safe Wrappers                                               */
/* ------------------------------------------------------------------ */

bool swiss_set_safe(SwissMap* m, void* key, size_t key_len, void* value) {
    if (!m) return false;
    lock_acquire(&m->lock);
    bool r = swiss_set(m, key, key_len, value);
    lock_release(&m->lock);
    return r;
}

void* swiss_get_safe(SwissMap* m, void* key, size_t key_len) {
    if (!m) return NULL;
    lock_acquire(&m->lock);
    void* r = swiss_get(m, key, key_len);
    lock_release(&m->lock);
    return r;
}

bool swiss_remove_safe(SwissMap* m, void* key, size_t key_len) {
    if (!m) return false;
    lock_acquire(&m->lock);
    bool r = swiss_remove(m, key, key_len);
    lock_release(&m->lock);
    return r;
}
