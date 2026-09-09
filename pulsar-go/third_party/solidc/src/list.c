#include "../include/list.h"

#include <stdalign.h>
#include <stdlib.h>
#include <string.h>

#define ALIGNMENT      8U
#define ALIGNMENT_MASK (ALIGNMENT - 1)

// Round up to proper alignment
static inline size_t aligned_size(size_t n) { return (n + ALIGNMENT_MASK) & ~(ALIGNMENT_MASK); }

// Node allocation: single malloc (node + element)
static list_node_t* list_node_new(size_t elem_size, void* data) {
    size_t total_size = sizeof(list_node_t) + aligned_size(elem_size);
    list_node_t* node = (list_node_t*)malloc(total_size);
    if (!node) return NULL;

    node->next = NULL;
    node->prev = NULL;
    node->data = (void*)(node + 1);  // element lives inline
    memcpy(node->data, data, elem_size);
    return node;
}

static void list_node_free(list_node_t* node) {
    free(node);  // single allocation
}

// ---- list implementation ----

list_t* list_new(size_t elem_size) {
    list_t* list = (list_t*)malloc(sizeof(list_t));
    if (!list) return NULL;
    list->head = list->tail = NULL;
    list->size = 0;
    list->elem_size = elem_size;
    return list;
}

void list_free(list_t* list) {
    if (!list) return;
    list_clear(list);
    free(list);
}

void list_clear(list_t* list) {
    if (!list) return;
    list_node_t* cur = list->head;
    while (cur) {
        list_node_t* next = cur->next;
        list_node_free(cur);
        cur = next;
    }
    list->head = list->tail = NULL;
    list->size = 0;
}

size_t list_size(const list_t* list) { return list ? list->size : 0; }

void list_push_back(list_t* list, void* elem) {
    if (!list) return;
    list_node_t* node = list_node_new(list->elem_size, elem);
    if (!node) return;

    if (!list->tail) {
        list->head = list->tail = node;
    } else {
        node->prev = list->tail;
        list->tail->next = node;
        list->tail = node;
    }
    list->size++;
}

void list_pop_back(list_t* list) {
    if (!list || !list->tail) return;
    list_node_t* n = list->tail;
    list->tail = n->prev;
    if (list->tail)
        list->tail->next = NULL;
    else
        list->head = NULL;
    list_node_free(n);
    list->size--;
}

void list_push_front(list_t* list, void* elem) {
    if (!list) return;
    list_node_t* node = list_node_new(list->elem_size, elem);
    if (!node) return;

    if (!list->head) {
        list->head = list->tail = node;
    } else {
        node->next = list->head;
        list->head->prev = node;
        list->head = node;
    }
    list->size++;
}

void list_pop_front(list_t* list) {
    if (!list || !list->head) return;
    list_node_t* n = list->head;
    list->head = n->next;
    if (list->head)
        list->head->prev = NULL;
    else
        list->tail = NULL;
    list_node_free(n);
    list->size--;
}

void* list_get(const list_t* list, size_t index) {
    if (!list || index >= list->size) return NULL;
    list_node_t* cur = list->head;
    for (size_t i = 0; i < index; i++) cur = cur->next;
    return cur ? cur->data : NULL;
}

int list_index_of(const list_t* list, void* elem) {
    if (!list) return -1;
    list_node_t* cur = list->head;
    int idx = 0;
    while (cur) {
        if (memcmp(cur->data, elem, list->elem_size) == 0) return idx;
        cur = cur->next;
        idx++;
    }
    return -1;
}

void list_insert(list_t* list, size_t index, void* elem) {
    if (!list || index > list->size) return;
    if (index == 0) {
        list_push_front(list, elem);
        return;
    }
    if (index == list->size) {
        list_push_back(list, elem);
        return;
    }

    list_node_t* cur = list->head;
    for (size_t i = 0; i < index; i++) cur = cur->next;

    list_node_t* node = list_node_new(list->elem_size, elem);
    if (!node) return;

    node->next = cur;
    node->prev = cur->prev;
    if (cur->prev) cur->prev->next = node;
    cur->prev = node;
    if (cur == list->head) list->head = node;
    list->size++;
}

void list_remove(list_t* list, void* elem) {
    if (!list) return;
    int idx = list_index_of(list, elem);
    if (idx == -1) return;

    list_node_t* cur = list->head;
    for (int i = 0; i < idx; i++) cur = cur->next;

    if (cur->prev)
        cur->prev->next = cur->next;
    else
        list->head = cur->next;

    if (cur->next)
        cur->next->prev = cur->prev;
    else
        list->tail = cur->prev;

    list_node_free(cur);
    list->size--;
}

void list_insert_after(list_t* list, void* elem, void* after) {
    int idx = list_index_of(list, after);
    if (idx == -1) return;
    list_insert(list, (size_t)idx + 1, elem);
}

void list_insert_before(list_t* list, void* elem, void* before) {
    int idx = list_index_of(list, before);
    if (idx == -1) return;
    list_insert(list, (size_t)idx, elem);
}
