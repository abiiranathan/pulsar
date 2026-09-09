/**
 * @file poller_internal.h
 * @brief Shared state between the poller backends (epoll / kqueue / win32).
 *
 * Lifetime contract: the kernel must never hold pointers into the
 * registration table, because both growth (regs_grow) and removal
 * (backward-shift re-seat) relocate nodes. Backends therefore pass either
 * the raw fd (epoll ev.data.fd) or the caller's own pointer (kqueue udata)
 * to the kernel and resolve PollerReg entries by fd at wait time.
 *
 * The public API promises poller_event_fd() always works. WSAPoll reports
 * the fd directly; the map is still used there for mod/del bookkeeping.
 */

#ifndef SOLIDC_POLLER_INTERNAL_H
#define SOLIDC_POLLER_INTERNAL_H

#include "../../include/poller.h"

#include <stdlib.h>
#include <string.h>

/** Per-descriptor registration node. Internal only: never handed to the
 *  kernel, so it may be relocated by growth or rehash at any time. */
typedef struct PollerReg {
    int fd;
    void* data;
    int events; /**< Interest mask (POLLER_READ/WRITE); used by win32. */
    bool active;
} PollerReg;

/**
 * Open-addressing hash table keyed by fd. Power-of-two capacity, grows at
 * 50% load. Lookup is O(1); pollers handle thousands of fds, so this keeps
 * per-event dispatch constant-time.
 */
typedef struct PollerRegTable {
    PollerReg* slots;
    size_t capacity; /* power of two */
    size_t count;
} PollerRegTable;

/** Shared poller base embedded in every backend's Poller struct. */
typedef struct PollerBase {
    PollerRegTable regs;
} PollerBase;

/** Initializes the registration table. @return true on success. */
bool poller_regs_init(PollerBase* base);

/** Frees the registration table (not the descriptors). */
void poller_regs_free(PollerBase* base);

/** Inserts or updates the registration for @p fd. @return node, NULL on OOM. */
PollerReg* poller_regs_put(PollerBase* base, int fd, void* data);

/** Finds the registration for @p fd, or NULL. */
PollerReg* poller_regs_get(PollerBase* base, int fd);

/** Removes (deactivates) the registration for @p fd. @return true if found. */
bool poller_regs_remove(PollerBase* base, int fd);

#endif /* SOLIDC_POLLER_INTERNAL_H */
