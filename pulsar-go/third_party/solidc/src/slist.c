#include "../include/slist.h"

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "macros.h"

/* Payload must be suitably aligned for any fundamental type.
 * Use the centralized SOLIDC_MAX_ALIGN from macros.h, which handles
 * MSVC's missing max_align_t. */
#define ALIGNMENT      SOLIDC_MAX_ALIGN
#define ALIGNMENT_MASK SOLIDC_MAX_ALIGN_MASK

// Round up to proper alignment. Returns 0 on overflow.
static inline size_t aligned_size(size_t n) {
    if (n > SIZE_MAX - ALIGNMENT_MASK) return 0;
    return (n + ALIGNMENT_MASK) & ~(size_t)ALIGNMENT_MASK;
}

slist* slist_new(size_t elem_size) {
    if (elem_size == 0) return NULL; /* zero-sized elements are meaningless and unsafe */
    slist* list = (slist*)malloc(sizeof(slist));
    if (!list) return NULL;

    list->head = NULL;
    list->tail = NULL;
    list->size = 0;
    list->elem_size = elem_size;
    return list;
}

void slist_free(slist* list) {
    if (!list) return;
    slist_clear(list);
    free(list);
}

size_t slist_size(const slist* list) { return list ? list->size : 0; }

void slist_clear(slist* list) {
    if (!list) return;

    slist_node_t* current = list->head;
    while (current) {
        slist_node_t* next = current->next;
        slist_node_free(current);
        current = next;
    }
    list->head = list->tail = NULL;
    list->size = 0;
}

slist_node_t* slist_node_new(size_t elem_size, void* data) {
    if (elem_size == 0) return NULL;

    /* Overflow guard: node header + aligned payload must not wrap. */
    size_t payload = aligned_size(elem_size);
    if (payload == 0 || payload > SIZE_MAX - sizeof(slist_node_t)) return NULL;
    size_t total_size = sizeof(slist_node_t) + payload;
    slist_node_t* node = (slist_node_t*)malloc(total_size);
    if (!node) return NULL;

    node->next = NULL;
    node->data = (void*)(node + 1);  // data lives right after struct
    if (data) memcpy(node->data, data, elem_size);
    return node;
}

void slist_node_free(slist_node_t* node) {
    free(node);  // single allocation
}

void slist_push_front(slist* list, void* elem) {
    if (!list) return;
    slist_node_t* node = slist_node_new(list->elem_size, elem);
    if (!node) return;

    node->next = list->head;
    list->head = node;
    if (!list->tail) list->tail = node;  // first element
    list->size++;
}

void slist_push_back(slist* list, void* elem) {
    if (!list) return;
    slist_node_t* node = slist_node_new(list->elem_size, elem);
    if (!node) return;

    if (!list->head) {
        list->head = list->tail = node;
    } else {
        list->tail->next = node;
        list->tail = node;
    }
    list->size++;
}

void slist_pop_front(slist* list) {
    if (!list || !list->head) return;
    slist_node_t* temp = list->head;
    list->head = temp->next;
    if (!list->head) list->tail = NULL;
    slist_node_free(temp);
    list->size--;
}

void slist_insert(slist* list, size_t index, void* elem) {
    if (!list || index > list->size) return;

    if (index == 0) {
        slist_push_front(list, elem);
        return;
    }
    if (index == list->size) {
        slist_push_back(list, elem);
        return;
    }

    slist_node_t* current = list->head;
    for (size_t i = 0; i < index - 1; i++) {
        current = current->next;
    }

    slist_node_t* node = slist_node_new(list->elem_size, elem);
    if (!node) return;

    node->next = current->next;
    current->next = node;
    list->size++;
}

void slist_remove(slist* list, size_t index) {
    if (!list || index >= list->size) return;

    if (index == 0) {
        slist_pop_front(list);
        return;
    }

    slist_node_t* current = list->head;
    for (size_t i = 0; i < index - 1; i++) {
        current = current->next;
    }

    slist_node_t* temp = current->next;
    current->next = temp->next;
    if (temp == list->tail) list->tail = current;
    slist_node_free(temp);
    list->size--;
}

void* slist_get(const slist* list, size_t index) {
    if (!list || index >= list->size) return NULL;

    slist_node_t* current = list->head;
    for (size_t i = 0; i < index; i++) {
        current = current->next;
    }
    return current->data;
}

int slist_index_of(const slist* list, void* elem) {
    if (!list || !elem) return -1;

    slist_node_t* current = list->head;
    int index = 0;
    while (current) {
        if (memcmp(current->data, elem, list->elem_size) == 0) return index;
        current = current->next;
        index++;
    }
    return -1;
}

void slist_insert_after(slist* list, void* elem, void* after) {
    int idx = slist_index_of(list, after);
    if (idx >= 0 && (size_t)idx < list->size) slist_insert(list, (size_t)idx + 1, elem);
}

void slist_insert_before(slist* list, void* elem, void* before) {
    int idx = slist_index_of(list, before);
    /*
     * FIX (off-by-one): inserting "immediately before" the node at idx
     * means occupying idx itself and shifting the rest right.  The old
     * code inserted at idx-1, which landed before the PREDECESSOR of the
     * target element instead.
     */
    if (idx > 0 && (size_t)idx < list->size)
        slist_insert(list, (size_t)idx, elem);
    else if (idx == 0)
        slist_push_front(list, elem);
}

void slist_print_asint(const slist* list) {
    SLIST_FOR_EACH(list, node) { printf("%d ", *(int*)node->data); }
    printf("\n");
}

void slist_print_aschar(const slist* list) {
    SLIST_FOR_EACH(list, node) { printf("%c ", *(char*)node->data); }
    printf("\n");
}
