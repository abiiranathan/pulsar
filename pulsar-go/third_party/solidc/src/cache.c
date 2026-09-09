#include "cache.h"
#include "macros.h"

#include <stdatomic.h>  // for atomic_uint_fast32_t, memory_order_*
#include <stdbool.h>    // for bool, true, false
#include <stddef.h>     // for size_t, NULL
#include <stdint.h>     // for uint16_t, uint32_t, uint64_t, uint8_t
#include <stdlib.h>     // for malloc, free, calloc
#include <string.h>     // for memcpy, memcmp
#include <time.h>       // for time, time_t
#include "../include/align.h"

#define XXH_INLINE_ALL
#include <xxhash.h>

#ifdef _MSC_VER
    #ifndef __builtin_prefetch
        #define __builtin_prefetch(x, ...) ((void)0)
    #endif
#endif

/** Maximum linear probe sequence length during open addressing collisions. */
#define CACHE_PROBE_MAX 16

/** Reserved tag indicating an unallocated or empty slot. */
#define TAG_EMPTY 0x0000

/** Sentinel index representing NULL/End-of-Stack in slab allocator. */
#define SLAB_NULL_INDEX 0xFFFFFFFFU

/** Maximum optimistic read retries on seqlock contention. */
#define MAX_READ_RETRIES 100

/** Pause hint while spinning on a seqlock writer (PAUSE/YIELD/nop). */
#if defined(_MSC_VER)
    #include <intrin.h>
    #define CACHE_PAUSE() _mm_pause()
#elif defined(__x86_64__) || defined(__i386__)
    #define CACHE_PAUSE() __builtin_ia32_pause()
#elif defined(__aarch64__) || defined(__arm__)
    #define CACHE_PAUSE() __asm__ __volatile__("yield" ::: "memory")
#else
    #define CACHE_PAUSE() ((void)0)
#endif

/** Block unit stored in ABA-safe lock-free slab allocator pool. */
typedef struct {
    uint32_t next_idx;                 /** Index of next free block in pool stack. */
    uint8_t data[CACHE_MAX_VALUE_LEN]; /** Dynamic payload storage block. */
} slab_block_t;

/** ABA-safe lock-free stack allocator using a 64-bit packed head counter. */
typedef struct {
    slab_block_t* blocks;  /** Contiguous backing array of slab blocks. */
    _Atomic uint64_t head; /** High 32 bits: ABA generation; Low 32 bits: Block index. */
    size_t total_blocks;   /** Total block capacity in shard slab pool. */
} slab_allocator_t;

/**
 * Cache slot structure aligned to 256 bytes (4 x 64-byte L1 CPU cache lines).
 * Hot metadata is tightly packed in the first 16 bytes to maximize L1 cache hit rate.
 */
typedef struct {
    /* --- CACHE LINE 0: HOT METADATA (16 bytes active + 16 bytes pad) --- */
    _Atomic uint32_t sequence; /**< Seqlock sequence: Even = idle, Odd = write in progress. */
    uint16_t tag;              /**< 16-bit hash pre-filter tag (0 = empty). */
    uint16_t key_len;          /**< Length of key stored in slot. */
    uint32_t val_len;          /**< Length of payload value stored in slot. */
    uint32_t slab_idx;         /**< Index in slab allocator if payload exceeds inline limit. */
    uint64_t expire_at_sec;    /**< Unix timestamp (seconds) when slot expires. */
    uint8_t _pad[8];           /**< Explicit padding rounding header to 32 bytes. */

    /* --- CACHE LINE 1: INLINE KEY (64 bytes) --- */
    uint8_t key[CACHE_MAX_KEY_LEN]; /**< Inline key buffer. */

    /* --- CACHE LINE 2 & 3: INLINE VALUE (160 bytes) --- */
    uint8_t val_inline[CACHE_INLINE_VAL_LEN]; /**< Inline value buffer (Total size = 32 + 64 + 160 = 256B). */
} ALIGN(256) cache_slot_t;

/** Cache shard containing a power-of-2 open-addressing slot table and dynamic slab pool. */
typedef struct {
    cache_slot_t* slots;   /** Array of 256-byte cache-aligned hash slots. */
    size_t slot_capacity;  /** Power-of-2 slot capacity within this shard. */
    size_t slot_mask;      /** Bitwise mask (capacity - 1) replacing integer division. */
    slab_allocator_t slab; /** Dedicated slab pool for large allocations in shard. */
} cache_shard_t;

/** Concrete cache implementation structure. */
struct cache_s {
    cache_shard_t shards[CACHE_SHARD_COUNT]; /** Shard collection partitioning key space. */
    uint32_t default_ttl_sec;                /** Global default entry expiration time. */
};

/* --- Internal Helpers: Math, Hashing & Time --- */

/** Rounds integer up to the nearest power of 2 for single-cycle bitwise masking. */
static inline size_t next_pow2(size_t v) {
    if (v < 16) {
        return 16;
    }
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v |= v >> 32;
    v++;
    return v;
}

/**
 * High-performance 64-bit hash.  XXH3-64 (vendored, inlined) processes
 * word-at-a-time and replaces the previous byte-at-a-time multiply loop,
 * which profiling showed at ~20-30% of get-path cycles for typical 30-60
 * byte keys.
 */
static inline uint64_t hash_bytes(const void* key, size_t len) { return XXH3_64bits(key, len); }

/** Extracts non-zero 16-bit tag from 64-bit hash digest. */
static inline uint16_t extract_tag(uint64_t hash) {
    uint16_t tag = (uint16_t)(hash >> 48);
    return (tag == TAG_EMPTY) ? 1 : tag;
}

/**
 * Wall-clock access.
 *
 * NOTE: a per-thread cached timestamp (refreshed every N ops) was tried
 * here and reverted.  Writes need `now` to compute absolute expiry, reads
 * need `now` to validate it — using two clocks let entries appear alive
 * after expiry (stale read clock) or die early (stale write clock), both
 * caught by cache_test's TTL cases.  Second-granular TTLs cannot absorb
 * unbounded staleness, so both paths pay the vDSO time(2).
 */
static inline uint64_t current_time_sec(void) { return (uint64_t)time(NULL); }

/* --- Internal Helpers: ABA-Safe Slab Allocator --- */

/** Initializes the slab pool stack using continuous block indexing. */
static bool slab_allocator_init(slab_allocator_t* slab, size_t num_blocks) {
    if (num_blocks == 0) {
        slab->blocks = NULL;
        slab->total_blocks = 0;
        atomic_init(&slab->head, ((uint64_t)0 << 32) | SLAB_NULL_INDEX);
        return true;
    }

    slab->blocks = calloc(num_blocks, sizeof(slab_block_t));
    if (slab->blocks == NULL) {
        return false;
    }

    slab->total_blocks = num_blocks;

    // Build initial free stack chain
    for (size_t i = 0; i < num_blocks - 1; ++i) {
        slab->blocks[i].next_idx = (uint32_t)(i + 1);
    }
    slab->blocks[num_blocks - 1].next_idx = SLAB_NULL_INDEX;

    // Packed 64-bit head initialization: [Generation = 0 | Index = 0]
    atomic_init(&slab->head, ((uint64_t)0 << 32) | 0U);
    return true;
}

/** Frees underlying dynamic buffer array of slab pool. */
static void slab_allocator_destroy(slab_allocator_t* slab) {
    free(slab->blocks);
    slab->blocks = NULL;
}

/** Pop dynamic block index from lock-free stack with ABA generation counter. */
static uint32_t slab_alloc(slab_allocator_t* slab) {
    if (slab->blocks == NULL) {
        return SLAB_NULL_INDEX;
    }

    uint64_t old_head = atomic_load_explicit(&slab->head, memory_order_relaxed);
    while (1) {
        uint32_t curr_idx = (uint32_t)(old_head & 0xFFFFFFFFU);
        if (curr_idx == SLAB_NULL_INDEX) {
            return SLAB_NULL_INDEX;  // Pool exhausted
        }

        uint32_t gen = (uint32_t)(old_head >> 32);
        uint32_t next_idx = slab->blocks[curr_idx].next_idx;

        // Increment generation count to prevent ABA race condition on pop
        uint64_t new_head = ((uint64_t)(gen + 1) << 32) | (uint64_t)next_idx;

        if (atomic_compare_exchange_weak_explicit(&slab->head, &old_head, new_head, memory_order_acquire,
                                                  memory_order_relaxed)) {
            return curr_idx;
        }
    }
}

/** Push dynamic block index back onto lock-free stack with ABA generation update. */
static void slab_free(slab_allocator_t* slab, uint32_t block_idx) {
    if (slab->blocks == NULL || block_idx >= slab->total_blocks) {
        return;
    }

    uint64_t old_head = atomic_load_explicit(&slab->head, memory_order_relaxed);
    while (1) {
        uint32_t gen = (uint32_t)(old_head >> 32);

        /* Note: writing block_idx's next_idx here is safe without atomics because
         * a block is only reachable by one thread at a time: either it's off-stack
         * and owned exclusively by the caller (this function), or it's on-stack
         * and only reachable via slab_alloc's CAS loop, never both simultaneously. */
        slab->blocks[block_idx].next_idx = (uint32_t)(old_head & 0xFFFFFFFFU);

        // Increment generation count to prevent ABA race condition on push
        uint64_t new_head = ((uint64_t)(gen + 1) << 32) | (uint64_t)block_idx;

        if (atomic_compare_exchange_weak_explicit(&slab->head, &old_head, new_head, memory_order_release,
                                                  memory_order_relaxed)) {
            break;
        }
    }
}

/* --- Public API Implementation --- */

cache_t* cache_create(const cache_config_t* config) {
    if (config == NULL || config->capacity_per_shard == 0) {
        return NULL;
    }

    cache_t* cache = malloc(sizeof(*cache));
    if (cache == NULL) {
        goto alloc_cache_failed;
    }

    cache->default_ttl_sec = (config->default_ttl_sec > 0) ? config->default_ttl_sec : CACHE_DEFAULT_TTL;

    // Initialize all shards with power-of-2 slot capacity
    for (size_t s = 0; s < CACHE_SHARD_COUNT; ++s) {
        cache_shard_t* shard = &cache->shards[s];

        // Enforce power-of-2 capacity to eliminate 35-cycle 'div' instructions
        shard->slot_capacity = next_pow2(config->capacity_per_shard);
        shard->slot_mask = shard->slot_capacity - 1;

        shard->slots = calloc(shard->slot_capacity, sizeof(cache_slot_t));
        if (shard->slots == NULL) {
            // Roll back previously allocated shards
            for (size_t r = 0; r < s; ++r) {
                slab_allocator_destroy(&cache->shards[r].slab);
                free(cache->shards[r].slots);
            }
            goto alloc_slots_failed;
        }

        for (size_t i = 0; i < shard->slot_capacity; ++i) {
            atomic_init(&shard->slots[i].sequence, 0);
            shard->slots[i].slab_idx = SLAB_NULL_INDEX;
        }

        if (!slab_allocator_init(&shard->slab, config->slab_blocks_per_shard)) {
            free(shard->slots);
            for (size_t r = 0; r < s; ++r) {
                slab_allocator_destroy(&cache->shards[r].slab);
                free(cache->shards[r].slots);
            }
            goto alloc_slots_failed;
        }
    }

    return cache;

alloc_slots_failed:
    free(cache);
alloc_cache_failed:
    return NULL;
}

void cache_destroy(cache_t* cache) {
    if (cache == NULL) {
        return;
    }

    for (size_t s = 0; s < CACHE_SHARD_COUNT; ++s) {
        cache_shard_t* shard = &cache->shards[s];
        slab_allocator_destroy(&shard->slab);
        free(shard->slots);
    }

    free(cache);
}

bool cache_put(cache_t* cache, const void* key, size_t key_len, const void* value, size_t val_len, uint32_t ttl_sec) {
    if (cache == NULL || key == NULL || value == NULL) {
        return false;
    }
    if (key_len == 0 || key_len > CACHE_MAX_KEY_LEN || val_len > CACHE_MAX_VALUE_LEN) {
        return false;
    }

    uint64_t hash = hash_bytes(key, key_len);
    uint16_t tag = extract_tag(hash);
    size_t shard_idx = hash & (CACHE_SHARD_COUNT - 1);
    cache_shard_t* shard = &cache->shards[shard_idx];

    // Single-cycle bitwise AND replaces 35-cycle integer division
    size_t mask = shard->slot_mask;
    size_t base_idx = (size_t)((hash >> 16) & mask);

    // Sample current time ONCE outside loop
    uint64_t now = current_time_sec();
    uint32_t ttl = (ttl_sec > 0) ? ttl_sec : cache->default_ttl_sec;
    uint64_t expire_at = now + ttl;

    size_t target_slot = shard->slot_capacity;  // Invalid sentinel

    // Open addressing probe sequence
    for (size_t probe = 0; probe < CACHE_PROBE_MAX; ++probe) {
        size_t idx = (base_idx + probe) & mask;
        cache_slot_t* slot = &shard->slots[idx];

        /* Hide the latency of the next slot's metadata line while we
         * evaluate this one (only line 0 matters until a tag matches). */
        if (probe + 1 < CACHE_PROBE_MAX) {
            __builtin_prefetch(&shard->slots[(base_idx + probe + 1) & mask].sequence, 0, 3);
        }

        uint16_t slot_tag = slot->tag;

        // Claim slot if empty, matching key, or expired entry
        if (slot_tag == TAG_EMPTY || slot->expire_at_sec <= now) {
            target_slot = idx;
            break;
        }

        if (slot_tag == tag && slot->key_len == (uint16_t)key_len) {
            if (memcmp(slot->key, key, key_len) == 0) {
                target_slot = idx;
                break;
            }
        }
    }

    if (target_slot == shard->slot_capacity) {
        return false;  // Shard table probe bucket limit reached
    }

    cache_slot_t* slot = &shard->slots[target_slot];

    // Allocate dynamic block if payload exceeds 160-byte inline storage limit
    uint32_t new_slab_idx = SLAB_NULL_INDEX;
    if (val_len > CACHE_INLINE_VAL_LEN) {
        new_slab_idx = slab_alloc(&shard->slab);
        if (new_slab_idx == SLAB_NULL_INDEX) {
            return false;  // Dynamic slab allocation failed
        }
        memcpy(shard->slab.blocks[new_slab_idx].data, value, val_len);
    }

    // --- Acquire Writer Seqlock Lock ---
    uint32_t seq = atomic_load_explicit(&slot->sequence, memory_order_relaxed);
    while (1) {
        if ((seq & 1U) == 0) {
            if (atomic_compare_exchange_weak_explicit(&slot->sequence, &seq, seq + 1, memory_order_acquire,
                                                      memory_order_relaxed)) {
                break;
            }
        } else {
            CACHE_PAUSE();
            seq = atomic_load_explicit(&slot->sequence, memory_order_relaxed);
        }
    }

    // Capture previous slab index to reclaim after update
    uint32_t old_slab_idx = slot->slab_idx;

    // Mutate entry payload safely under active write lock
    slot->tag = tag;
    slot->key_len = (uint16_t)key_len;
    slot->val_len = (uint32_t)val_len;
    slot->expire_at_sec = expire_at;
    slot->slab_idx = new_slab_idx;

    memcpy(slot->key, key, key_len);
    if (val_len <= CACHE_INLINE_VAL_LEN) {
        memcpy(slot->val_inline, value, val_len);
    }

    // Release Seqlock by advancing sequence counter to even value
    atomic_store_explicit(&slot->sequence, seq + 2, memory_order_release);

    // Free superseded slab allocation after completing write sequence
    if (old_slab_idx != SLAB_NULL_INDEX) {
        slab_free(&shard->slab, old_slab_idx);
    }

    return true;
}

bool cache_get(cache_t* cache, const void* key, size_t key_len, void* val_out, size_t val_cap, size_t* val_len) {
    if (cache == NULL || key == NULL || val_out == NULL || key_len == 0) {
        return false;
    }

    uint64_t hash = hash_bytes(key, key_len);
    uint16_t tag = extract_tag(hash);
    size_t shard_idx = hash & (CACHE_SHARD_COUNT - 1);
    const cache_shard_t* shard = &cache->shards[shard_idx];

    // Single-cycle bitwise AND replaces 35-cycle integer division
    size_t mask = shard->slot_mask;
    size_t base_idx = (size_t)((hash >> 16) & mask);

    // Sample current time ONCE outside probe loop
    uint64_t now = current_time_sec();

    for (size_t probe = 0; probe < CACHE_PROBE_MAX; ++probe) {
        size_t idx = (base_idx + probe) & mask;
        const cache_slot_t* slot = &shard->slots[idx];

        for (int retry = 0; retry < MAX_READ_RETRIES; ++retry) {
            uint32_t seq1 = atomic_load_explicit(&slot->sequence, memory_order_acquire);
            if ((seq1 & 1U) != 0) {
                CACHE_PAUSE();
                continue;  // Writer active, retry optimistic read loop
            }

            // Tag check pre-filter
            if (slot->tag != tag) {
                uint32_t seq2 = atomic_load_explicit(&slot->sequence, memory_order_relaxed);
                if (seq1 == seq2) {
                    if (slot->tag == TAG_EMPTY) {
                        return false;  // Terminal empty slot reached
                    }
                    break;  // Confirmed tag mismatch, probe next slot
                }
                continue;  // Inconsistent tag read due to race, retry
            }

            // Expiration validation
            if (slot->expire_at_sec <= now) {
                uint32_t seq2 = atomic_load_explicit(&slot->sequence, memory_order_relaxed);
                if (seq1 == seq2) {
                    return false;  // Entry expired
                }
                continue;
            }

            // Key equality comparison
            if (slot->key_len != (uint16_t)key_len || memcmp(slot->key, key, key_len) != 0) {
                uint32_t seq2 = atomic_load_explicit(&slot->sequence, memory_order_relaxed);
                if (seq1 == seq2) {
                    break;  // Confirmed key mismatch, probe next slot
                }
                continue;
            }

            // Entry matched! Copy out value payload
            uint32_t payload_len = slot->val_len;
            if (payload_len > val_cap) {
                return false;  // Buffer overflow safeguard
            }

            uint32_t slab_idx = slot->slab_idx;
            if (payload_len <= CACHE_INLINE_VAL_LEN) {
                memcpy(val_out, slot->val_inline, payload_len);
            } else if (slab_idx != SLAB_NULL_INDEX && shard->slab.blocks != NULL) {
                memcpy(val_out, shard->slab.blocks[slab_idx].data, payload_len);
            } else {
                return false;  // Corrupted slab state
            }

            // Final atomic memory fence check
            atomic_thread_fence(memory_order_acquire);
            uint32_t seq2 = atomic_load_explicit(&slot->sequence, memory_order_relaxed);

            if (seq1 == seq2) {
                if (val_len != NULL) {
                    *val_len = (size_t)payload_len;
                }
                return true;  // Consistent read validated!
            }
        }
    }

    return false;
}

bool cache_delete(cache_t* cache, const void* key, size_t key_len) {
    if (cache == NULL || key == NULL || key_len == 0) {
        return false;
    }

    uint64_t hash = hash_bytes(key, key_len);
    uint16_t tag = extract_tag(hash);
    size_t shard_idx = hash & (CACHE_SHARD_COUNT - 1);
    cache_shard_t* shard = &cache->shards[shard_idx];

    // Single-cycle bitwise AND replaces 35-cycle integer division
    size_t mask = shard->slot_mask;
    size_t base_idx = (size_t)((hash >> 16) & mask);

    for (size_t probe = 0; probe < CACHE_PROBE_MAX; ++probe) {
        size_t idx = (base_idx + probe) & mask;
        cache_slot_t* slot = &shard->slots[idx];

        uint32_t seq = atomic_load_explicit(&slot->sequence, memory_order_relaxed);
        if (slot->tag == TAG_EMPTY) {
            return false;
        }

        if (slot->tag == tag && slot->key_len == (uint16_t)key_len) {
            if (memcmp(slot->key, key, key_len) == 0) {
                // Acquire write lock
                while (1) {
                    if ((seq & 1U) == 0) {
                        if (atomic_compare_exchange_weak_explicit(&slot->sequence, &seq, seq + 1, memory_order_acquire,
                                                                  memory_order_relaxed)) {
                            break;
                        }
                    } else {
                        seq = atomic_load_explicit(&slot->sequence, memory_order_relaxed);
                    }
                }

                uint32_t freed_slab_idx = slot->slab_idx;

                // Clear slot headers
                slot->tag = TAG_EMPTY;
                slot->key_len = 0;
                slot->val_len = 0;
                slot->expire_at_sec = 0;
                slot->slab_idx = SLAB_NULL_INDEX;

                // Release write lock
                atomic_store_explicit(&slot->sequence, seq + 2, memory_order_release);

                // Reclaim slab resource
                if (freed_slab_idx != SLAB_NULL_INDEX) {
                    slab_free(&shard->slab, freed_slab_idx);
                }

                return true;
            }
        }
    }

    return false;
}
