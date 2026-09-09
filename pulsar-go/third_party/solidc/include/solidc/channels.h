/**
 * @file channels.h
 * @brief Go-style typed channels for thread communication.
 *
 * A Channel<T> is a thread-safe FIFO queue that lets threads exchange
 * values the way goroutines do in Go:
 *
 *   - `chan_send(c, &value)`  blocks until the value is queued (or the
 *     channel is closed).
 *   - `chan_recv(c, &out)`    blocks until a value is available, returning
 *     false once the channel is closed AND drained.
 *   - `chan_try_send` / `chan_try_recv` never block.
 *   - `chan_recv_timeout` blocks at most timeout_ms.
 *
 * Closing semantics mirror Go:
 *   - Send on a closed channel is an error (CHAN_CLOSED).
 *   - Receive from a closed channel drains buffered values first, then
 *     reports CHAN_CLOSED forever.
 *   - close() wakes all blocked receivers and senders.
 *   - close() is idempotent; double close returns CHAN_CLOSED.
 *
 * Channels are dynamically sized: they grow like a ring buffer when full
 * (senders never block on a healthy open channel unless chan_send_blocking
 * is used with a capacity bound — see chan_new).
 *
 * Thread safety: all operations are internally synchronized; a single
 * channel may be shared by any number of producer and consumer threads.
 *
 * Example:
 * @code
 *   Channel* ch = chan_new(sizeof(int), 0);
 *
 *   // producer thread
 *   for (int i = 0; i < 4; i++) chan_send(ch, &i);
 *   chan_close(ch);
 *
 *   // consumer (this thread)
 *   int v;
 *   while (chan_recv(ch, &v)) printf("%d\n", v);   // 0 1 2 3
 *   chan_free(ch);
 * @endcode
 */

#ifndef SOLIDC_CHANNELS_H
#define SOLIDC_CHANNELS_H

#include <macros.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "lock.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Error / status codes returned by channel operations. */
typedef enum {
    CHAN_OK = 0,          /**< Operation succeeded. */
    CHAN_CLOSED = 1,      /**< Channel is closed (send rejected, or recv drained). */
    CHAN_FULL = 2,        /**< Try-send failed: buffer at capacity. */
    CHAN_EMPTY = 3,       /**< Try-recv failed: no buffered value. */
    CHAN_TIMEOUT = 4,     /**< Timed recv expired before a value arrived. */
    CHAN_INVALID = 5,     /**< NULL channel or invalid argument. */
    CHAN_NOMEM = 6,       /**< Buffer growth allocation failed. */
    CHAN_WOULD_BLOCK = 7, /**< Non-blocking send rejected by a bounded channel. */
} ChanStatus;

/**
 * Opaque channel handle. Create with chan_new(), free with chan_free().
 * Safe for concurrent use by multiple producers and consumers.
 */
typedef struct Channel Channel;

/**
 * @brief Creates a channel carrying values of @p value_size bytes each.
 *
 * @param value_size    Size of each value in bytes (must be > 0). Values are
 *                      copied by value into the internal ring buffer.
 * @param capacity_hint Initial buffer capacity in values. 0 selects a
 *                      sensible default (16). The buffer still grows on
 *                      demand; this only avoids early reallocation.
 * @return New channel, or NULL if arguments are invalid or allocation fails.
 *
 * @note Free with chan_free(). The channel must not be in use by any thread
 *       when freed (synchronize producers/consumers first).
 */
Channel* chan_new(size_t value_size, size_t capacity_hint);

/**
 * @brief Sends a value by copying @p value_size bytes from @p value.
 *
 * Blocks while the channel is at capacity (only possible when a capacity
 * bound was requested) and wakes waiting receivers.
 *
 * @param c     Target channel.
 * @param value Pointer to the value to copy. Must not be NULL.
 * @return CHAN_OK on success; CHAN_INVALID if c/value is NULL;
 *         CHAN_CLOSED if the channel was closed (value not delivered);
 *         CHAN_NOMEM if buffer growth failed.
 */
ChanStatus chan_send(Channel* c, const void* value);

/**
 * @brief Receives the next value into @p out, blocking until one arrives.
 *
 * @param c   Source channel.
 * @param out Receives the value. Must not be NULL.
 * @return true if a value was received; false if the channel is closed and
 *         fully drained (out is left unmodified).
 */
bool chan_recv(Channel* c, void* out);

/**
 * @brief Non-blocking send.
 * @return CHAN_OK, CHAN_FULL (buffer at capacity), CHAN_CLOSED, or
 *         CHAN_INVALID.
 */
ChanStatus chan_try_send(Channel* c, const void* value);

/**
 * @brief Non-blocking receive.
 * @return CHAN_OK with *out populated, CHAN_EMPTY if nothing buffered,
 *         CHAN_CLOSED if closed and drained, or CHAN_INVALID.
 */
ChanStatus chan_try_recv(Channel* c, void* out);

/**
 * @brief Receives with a bounded wait.
 *
 * @param c          Source channel.
 * @param out        Receives the value.
 * @param timeout_ms Maximum wait in milliseconds; < 0 waits forever.
 * @return CHAN_OK, CHAN_TIMEOUT, CHAN_CLOSED, or CHAN_INVALID.
 */
ChanStatus chan_recv_timeout(Channel* c, void* out, int timeout_ms);

/**
 * @brief Closes the channel. Idempotent.
 *
 * Wake all blocked senders and receivers. Subsequent sends fail with
 * CHAN_CLOSED; receives keep draining buffered values, then report
 * CHAN_CLOSED.
 *
 * @param c Channel to close.
 * @return CHAN_OK on success (including double close), CHAN_INVALID if
 *         c is NULL.
 */
ChanStatus chan_close(Channel* c);

/**
 * @brief Number of values currently buffered.
 * @param c Channel to query.
 * @return Buffered value count, or 0 if c is NULL. Snapshot only.
 */
size_t chan_len(Channel* c);

/**
 * @brief Current buffer capacity in values.
 * @param c Channel to query.
 * @return Capacity, or 0 if c is NULL.
 */
size_t chan_cap(Channel* c);

/**
 * @brief Whether the channel has been closed.
 * @param c Channel to query.
 * @return true if closed (or c is NULL).
 */
bool chan_is_closed(Channel* c);

/**
 * @brief Size in bytes of the values this channel carries.
 * @param c Channel to query.
 * @return The value_size passed to chan_new(), or 0 if c is NULL.
 */
size_t chan_value_size(Channel* c);

/**
 * @brief Frees the channel and its buffer.
 *
 * @param c Channel to free; NULL is safely ignored.
 * @note No thread may be blocked on (or concurrently operating on) the
 *       channel when this is called. Close it and join/flush producers
 *       and consumers first.
 */
void chan_free(Channel* c);

#ifdef __cplusplus
}
#endif

#endif /* SOLIDC_CHANNELS_H */
