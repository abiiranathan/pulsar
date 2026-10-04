/**
 * @file tcp_buffer.h
 * @brief Small growable byte buffer used for output backpressure.
 *
 * The buffer keeps a `head` cursor so consumed bytes are not memmoved on every
 * read/write; space is reclaimed lazily by tcp_buffer_compact(). It is used by
 * the tcp connection to queue bytes that the kernel socket buffer refused to
 * accept (EAGAIN). The common case -- a write that the socket accepts whole --
 * never touches this buffer at all.
 */

#ifndef TCP_BUFFER_H
#define TCP_BUFFER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tcp_buffer {
    uint8_t* data; /**< Heap storage (NULL until first append). */
    size_t cap;    /**< Allocated capacity in bytes. */
    size_t head;   /**< Offset of the first live byte. */
    size_t len;    /**< Number of live bytes (from head). */
} tcp_buffer_t;

/** Initialize an empty buffer. Safe on zero-initialized storage too. */
void tcp_buffer_init(tcp_buffer_t* b);

/** Release heap storage and reset the buffer to empty. */
void tcp_buffer_free(tcp_buffer_t* b);

/** @return Number of live bytes queued. */
static inline size_t tcp_buffer_size(const tcp_buffer_t* b) { return b ? b->len : 0; }

/** @return Non-zero when the buffer holds no bytes. */
static inline int tcp_buffer_empty(const tcp_buffer_t* b) { return !b || b->len == 0; }

/**
 * @brief Ensure at least @p extra additional bytes fit after the live data.
 *
 * May move live bytes to the front (compaction) and/or grow the allocation.
 *
 * @return 0 on success, -1 on allocation failure (errno ENOMEM).
 */
int tcp_buffer_reserve(tcp_buffer_t* b, size_t extra);

/**
 * @brief Append @p n bytes, growing as required.
 * @return 0 on success, -1 on allocation failure.
 */
int tcp_buffer_append(tcp_buffer_t* b, const void* data, size_t n);

/**
 * @brief Append an iovec array (gather-append).
 * @return 0 on success, -1 on allocation failure.
 */
int tcp_buffer_appendv(tcp_buffer_t* b, const struct iovec* iov, int iovcnt);

/**
 * @brief Drop the first @p n live bytes. Clamped to tcp_buffer_size().
 */
void tcp_buffer_consume(tcp_buffer_t* b, size_t n);

/**
 * @brief Move live bytes to the front so head becomes 0.
 *
 * Called before growing to avoid unbounded allocation while the front is
 * dead. Does nothing when head is already 0.
 */
void tcp_buffer_compact(tcp_buffer_t* b);

/** @return Pointer to the first live byte (may be NULL when empty). */
static inline uint8_t* tcp_buffer_data(tcp_buffer_t* b) {
    return b ? (b->data ? b->data + b->head : NULL) : NULL;
}

#ifdef __cplusplus
}
#endif

#endif /* TCP_BUFFER_H */
