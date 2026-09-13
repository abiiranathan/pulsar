#ifndef PULSAR_KEEPALIVE_H
#define PULSAR_KEEPALIVE_H

#include "../include/pulsar.h"
#include "pulsar_time.h"

typedef struct KeepAliveState {
    PulsarConn* head;
    PulsarConn* tail;
    size_t count;
} KeepAliveState;

// close_connection is defined in connection.c and called by the keep-alive
// timeout sweep below.
extern void close_connection(event_queue_t* queue, PulsarConn* conn, KeepAliveState* ka_state,
                             int worker_id);

#define conn_timedout(now, last_activity) ((now) - (last_activity) > CONNECTION_TIMEOUT)

INLINE void remove_keepalive_connection(PulsarConn* conn, KeepAliveState* state) {
    if (unlikely(!conn->in_keep_alive)) return;

    if (conn->prev)
        conn->prev->next = conn->next;
    else
        state->head = conn->next;

    if (conn->next)
        conn->next->prev = conn->prev;
    else
        state->tail = conn->prev;

    conn->prev = NULL;
    conn->next = NULL;
    state->count--;
    conn->in_keep_alive = false;
}

INLINE void AddKeepAliveConnection(PulsarConn* conn, KeepAliveState* state) {
    if (unlikely(conn->in_keep_alive)) return;

    conn->next = state->head;
    conn->prev = NULL;

    if (state->head)
        state->head->prev = conn;
    else
        state->tail = conn;

    state->head = conn;
    state->count++;
    conn->in_keep_alive = true;
}

INLINE void CheckKeepAliveTimeouts(KeepAliveState* state, event_queue_t* queue, int worker_id) {
    PulsarConn* current = state->head;
    time_t now = pulsar_mono_sec();
    while (current) {
        PulsarConn* next = current->next;
        if (conn_timedout(now, current->last_activity)) {
            close_connection(queue, current, state, worker_id);
        }
        current = next;
    }
}

#endif  // PULSAR_KEEPALIVE_H
