/**
 * @file poller_common.c
 * @brief fd -> registration hash table shared by all poller backends.
 */

#include "poller_internal.h"

static size_t hash_fd(int fd, size_t capacity) {
    /* fd values are small, dense integers; multiplicative mix is plenty. */
    unsigned long long h = (unsigned long long)(fd + 1) * 0x9E3779B97F4A7C15ULL;
    return (size_t)(h >> 40) & (capacity - 1);
}

bool poller_regs_init(PollerBase* base) {
    base->regs.capacity = 64;
    base->regs.count = 0;
    base->regs.slots = (PollerReg*)calloc(base->regs.capacity, sizeof(PollerReg));
    return base->regs.slots != NULL;
}

void poller_regs_free(PollerBase* base) {
    free(base->regs.slots);
    base->regs.slots = NULL;
    base->regs.capacity = 0;
    base->regs.count = 0;
}

static bool regs_grow(PollerRegTable* t) {
    size_t new_cap = t->capacity * 2;
    PollerReg* ns = (PollerReg*)calloc(new_cap, sizeof(PollerReg));
    if (!ns) return false;

    for (size_t i = 0; i < t->capacity; i++) {
        if (!t->slots[i].active) continue;
        size_t j = hash_fd(t->slots[i].fd, new_cap);
        while (ns[j].active) j = (j + 1) & (new_cap - 1);
        ns[j] = t->slots[i];
    }
    free(t->slots);
    t->slots = ns;
    t->capacity = new_cap;
    return true;
}

PollerReg* poller_regs_put(PollerBase* base, int fd, void* data) {
    PollerRegTable* t = &base->regs;
    if (t->count + 1 > t->capacity / 2) {
        if (!regs_grow(t)) return NULL;
    }

    size_t i = hash_fd(fd, t->capacity);
    while (t->slots[i].active) {
        if (t->slots[i].fd == fd) {
            t->slots[i].data = data;
            return &t->slots[i];
        }
        i = (i + 1) & (t->capacity - 1);
    }

    t->slots[i].fd = fd;
    t->slots[i].data = data;
    t->slots[i].active = true;
    t->count++;
    return &t->slots[i];
}

PollerReg* poller_regs_get(PollerBase* base, int fd) {
    PollerRegTable* t = &base->regs;
    if (t->count == 0) return NULL;
    size_t i = hash_fd(fd, t->capacity);
    while (t->slots[i].active) {
        if (t->slots[i].fd == fd) return &t->slots[i];
        i = (i + 1) & (t->capacity - 1);
    }
    return NULL;
}

bool poller_regs_remove(PollerBase* base, int fd) {
    PollerRegTable* t = &base->regs;
    if (t->count == 0) return false;
    size_t i = hash_fd(fd, t->capacity);
    while (t->slots[i].active) {
        if (t->slots[i].fd == fd) {
            t->slots[i].active = false;
            t->slots[i].data = NULL;
            t->count--;
            /* Re-seat the cluster tail so probe chains stay intact. */
            size_t j = (i + 1) & (t->capacity - 1);
            while (t->slots[j].active) {
                PollerReg move = t->slots[j];
                t->slots[j].active = false;
                size_t h = hash_fd(move.fd, t->capacity);
                while (t->slots[h].active) h = (h + 1) & (t->capacity - 1);
                t->slots[h] = move;
                j = (j + 1) & (t->capacity - 1);
            }
            return true;
        }
        i = (i + 1) & (t->capacity - 1);
    }
    return false;
}
