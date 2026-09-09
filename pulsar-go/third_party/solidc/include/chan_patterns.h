/**
 * @file chan_patterns.h
 * @brief High-level concurrency patterns built on channels.h.
 *
 * Three composable abstractions that cover most producer/consumer
 * workloads, so applications don't hand-roll fan-out, worker pools, or
 * multiplexing loops on top of raw channels:
 *
 *   Pub/Sub     - chan_pubsub_t: one publisher, N independent subscribers.
 *                 Every subscriber receives a copy of every published
 *                 value into its own bounded queue. A full subscriber
 *                 queue makes publish() report CHAN_FULL for it without
 *                 affecting other subscribers.
 *
 *   Worker pool - chan_workers_t: M worker threads pull values from a
 *                 shared work channel and run a caller callback. Submit
 *                 from any thread; shutdown() closes the channel, drains
 *                 it, and joins every worker (WaitGroup semantics).
 *
 *   Select      - chan_select(): wait on up to CHAN_SELECT_MAX channels
 *                 at once; returns the index of the first one holding a
 *                 value. Polls internally with a bounded wait, so it is
 *                 simple and dependency-free. For latency-critical
 *                 fan-in, prefer chan_merge() into one channel.
 *
 * All APIs are thread-safe unless documented otherwise.
 */

#ifndef SOLIDC_CHAN_PATTERNS_H
#define SOLIDC_CHAN_PATTERNS_H

#include "channels.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum channels accepted by chan_select(). */
#define CHAN_SELECT_MAX 32

/* =========================================================================
 * Pub/Sub
 * ========================================================================= */

/** Opaque publish/subscribe hub. */
typedef struct chan_pubsub chan_pubsub_t;

/** Returned by chan_pubsub_subscribe() when no slot is available. */
#define CHAN_PUBSUB_NO_SUB ((size_t)-1)

/**
 * @brief Creates a pub/sub hub.
 *
 * @param value_size   Size of each published value in bytes (> 0).
 * @param max_subs     Maximum number of subscribers (1..1024).
 * @param queue_depth  Per-subscriber queue depth in values (> 0). A
 *                     subscriber whose queue fills causes publish() to
 *                     report CHAN_FULL; other subscribers are unaffected.
 * @return New hub, or NULL on invalid args / allocation failure.
 */
chan_pubsub_t* chan_pubsub_new(size_t value_size, size_t max_subs, size_t queue_depth);

/**
 * @brief Registers a subscriber and returns its id.
 *
 * Thread-safe: may be called concurrently with publish() and other
 * subscribe() calls. The new subscriber sees only values published after
 * its subscription.
 *
 * @param ps Hub.
 * @return Subscriber id for chan_pubsub_queue()/unsubscribe(), or
 *         CHAN_PUBSUB_NO_SUB if ps is NULL, closed, or full.
 */
size_t chan_pubsub_subscribe(chan_pubsub_t* ps);

/**
 * @brief Publishes a value to every active subscriber (one copy each).
 *
 * @param ps    Hub.
 * @param value Value to copy. Must not be NULL.
 * @return CHAN_OK if every subscriber accepted the value; CHAN_CLOSED if
 *         the hub is closed; CHAN_FULL if at least one subscriber queue
 *         was full (other subscribers still received it); CHAN_INVALID on
 *         bad args.
 */
ChanStatus chan_pubsub_publish(chan_pubsub_t* ps, const void* value);

/**
 * @brief A subscriber's receive queue, usable as a plain Channel*.
 *
 * Consume it with chan_recv()/chan_try_recv()/chan_recv_timeout(). When
 * the hub is closed, each queue is closed after its buffered values are
 * drained.
 *
 * @param ps Hub.
 * @param id Subscriber id from chan_pubsub_subscribe().
 * @return The subscriber's queue, or NULL if ps is NULL or id invalid.
 * @note Owned by the hub; never chan_free() it. The pointer stays valid
 *       until chan_pubsub_unsubscribe() or chan_pubsub_free().
 */
Channel* chan_pubsub_queue(chan_pubsub_t* ps, size_t id);

/**
 * @brief Removes a subscriber and destroys its queue (pending values are
 *        discarded).
 *
 * @param ps Hub.
 * @param id Subscriber id.
 * @return CHAN_OK, or CHAN_INVALID if ps is NULL or id is not active.
 */
ChanStatus chan_pubsub_unsubscribe(chan_pubsub_t* ps, size_t id);

/**
 * @brief Closes the hub: every subscriber queue is closed (after draining)
 *        and publishing is rejected. Idempotent.
 * @return CHAN_OK or CHAN_INVALID.
 */
ChanStatus chan_pubsub_close(chan_pubsub_t* ps);

/**
 * @brief Number of currently active subscribers.
 * @return Active subscriber count, or 0 if ps is NULL.
 */
size_t chan_pubsub_subscriber_count(chan_pubsub_t* ps);

/**
 * @brief Frees the hub and all subscriber queues.
 * @note Close first and ensure no thread is using the hub or its queues.
 */
void chan_pubsub_free(chan_pubsub_t* ps);

/* =========================================================================
 * Worker pool
 * ========================================================================= */

/**
 * Worker callback. Invoked on a pool thread for every submitted value.
 * @param value  Pointer to the submitted value (valid only during the call).
 * @param user   Opaque pointer passed to chan_workers_new().
 */
typedef void (*chan_work_fn)(void* value, void* user);

/** Opaque worker pool. */
typedef struct chan_workers chan_workers_t;

/**
 * @brief Starts a worker pool: @p worker_count threads consuming from one
 *        shared work channel.
 *
 * @param worker_count  Number of worker threads (> 0).
 * @param value_size    Size of each work item in bytes (> 0).
 * @param queue_depth   Work channel capacity hint in items (0 = default).
 *                      The channel grows on demand, so this only affects
 *                      pre-allocation; submit() never blocks.
 * @param fn            Callback run per item on a worker thread. Required.
 * @param user          Opaque context passed to every callback invocation.
 * @return New pool, or NULL on invalid args / allocation failure.
 */
chan_workers_t* chan_workers_new(size_t worker_count, size_t value_size, size_t queue_depth, chan_work_fn fn,
                                 void* user);

/**
 * @brief Submits a work item (copied by value). Never blocks.
 *
 * @param w     Pool.
 * @param value Work item to copy. Must not be NULL.
 * @return CHAN_OK, CHAN_CLOSED if shutdown() was called, CHAN_NOMEM on
 *         growth failure, or CHAN_INVALID.
 */
ChanStatus chan_workers_submit(chan_workers_t* w, const void* value);

/**
 * @brief Number of items submitted but not yet completed.
 * @return Pending item count, or 0 if w is NULL. Snapshot only.
 */
size_t chan_workers_pending(chan_workers_t* w);

/**
 * @brief Shuts down: closes the work channel, waits for workers to drain
 *        every queued item, and joins all threads. Idempotent.
 *
 * @param w Pool.
 * @return CHAN_OK or CHAN_INVALID.
 * @note Call once from a single thread; other threads may keep submitting
 *       until the close takes effect (they will then get CHAN_CLOSED).
 */
ChanStatus chan_workers_shutdown(chan_workers_t* w);

/**
 * @brief Frees the pool. shutdown() must have been called first.
 */
void chan_workers_free(chan_workers_t* w);

/* =========================================================================
 * Select
 * ========================================================================= */

/** chan_select() result: no channel was ready before the timeout expired. */
#define CHAN_SELECT_TIMEOUT ((int)-1)

/**
 * @brief Waits until one of @p count channels holds a value, then receives
 *        it.
 *
 * Channels are polled in priority order (index 0 first) with a bounded
 * internal wait, so a lower-index channel that receives around the same
 * time as a higher-index one wins the race. Returns CHAN_SELECT_TIMEOUT if
 * no channel delivers within @p timeout_ms. A closed-and-drained channel
 * is skipped; if every channel is closed and drained, returns
 * CHAN_SELECT_TIMEOUT (callers typically treat that as termination).
 *
 * @param channels   Array of Channel pointers.
 * @param outs       Parallel array of receive destinations (may be NULL to
 *                   discard the received value of the winning channel).
 * @param count      Number of channels (1..CHAN_SELECT_MAX).
 * @param timeout_ms Total wait budget in milliseconds; < 0 waits forever.
 * @return Index of the channel whose value was received into outs[i]
 *         (0..count-1), or CHAN_SELECT_TIMEOUT.
 * @note Values arriving on non-winning channels stay buffered.
 */
int chan_select(Channel** channels, void** outs, size_t count, int timeout_ms);

/**
 * @brief Merges @p count source channels into one destination channel.
 *
 * A background forwarder thread moves every value from the sources to
 * dest until all sources are closed, then closes dest. This is the
 * latency-friendly alternative to polling with chan_select().
 *
 * @param dest       Destination channel (created by the caller).
 * @param sources    Array of source channels (not NULL).
 * @param count      Number of sources (1..CHAN_SELECT_MAX).
 * @return CHAN_OK, CHAN_INVALID on bad args, or CHAN_NOMEM if the
 *         forwarder thread could not start.
 * @note dest must remain valid until it is closed by the merger (i.e.
 *       until all sources are closed). Free the sources only after dest
 *       reports CHAN_CLOSED.
 */
ChanStatus chan_merge(Channel* dest, Channel** sources, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* SOLIDC_CHAN_PATTERNS_H */
