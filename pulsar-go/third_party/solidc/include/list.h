/**
 * @file list.h
 * @brief Doubly linked list implementation with memory management.
 */

#ifndef LIST_H
#define LIST_H

#include <stddef.h>  // for size_t
#include <stdio.h>   // for potential debug/print functions

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * A node in a doubly-linked list.
 * Each node contains a pointer to element data and bidirectional links.
 */
typedef struct list_node {
    /** Pointer to element data stored inline after the node structure. */
    void* data;
    /** Pointer to the next node in the list. NULL if this is the tail. */
    struct list_node* next;
    /** Pointer to the previous node in the list. NULL if this is the head. */
    struct list_node* prev;
} list_node_t;

/**
 * A doubly-linked list data structure.
 * Maintains both head and tail pointers for bidirectional traversal.
 * Stores elements of uniform size specified at list creation.
 */
typedef struct {
    /** Pointer to the first node in the list. NULL if empty. */
    list_node_t* head;
    /** Pointer to the last node in the list. NULL if empty. */
    list_node_t* tail;
    /** Number of elements currently in the list. */
    size_t size;
    /** Size in bytes of each element stored in the list. */
    size_t elem_size;
} list_t;

/**
 * Creates a new empty doubly-linked list.
 * @param elem_size Size in bytes of each element to be stored in the list.
 * @return Pointer to newly allocated list on success, NULL on allocation failure.
 * @note Caller must free the list using list_free() when done.
 */
list_t* list_new(size_t elem_size);

/**
 * Frees all resources associated with a doubly-linked list.
 * Deallocates all nodes and their data, then the list structure itself.
 * @param list Pointer to the list to free. Safe to pass NULL.
 */
void list_free(list_t* list);

/**
 * Removes all elements from the list.
 * Deallocates all nodes and their data, leaving the list empty.
 * @param list Pointer to the list to clear. Must not be NULL.
 */
void list_clear(list_t* list);

/**
 * Returns the number of elements in the list.
 * @param list Pointer to the list. Must not be NULL.
 * @return Number of elements currently stored in the list.
 */
size_t list_size(const list_t* list);

/**
 * Appends an element to the back of the list.
 * Creates a new node with a copy of the element data and makes it the new tail.
 * Operation is O(1) due to tail pointer maintenance.
 * @param list Pointer to the list. Must not be NULL.
 * @param elem Pointer to the element data to append. Must not be NULL.
 */
void list_push_back(list_t* list, void* elem);

/**
 * Removes the last element from the list.
 * Deallocates the tail node and its data. Updates tail to the previous node.
 * @param list Pointer to the list. Must not be NULL.
 * @note Does nothing if the list is empty.
 */
void list_pop_back(list_t* list);

/**
 * Inserts an element at the front of the list.
 * Creates a new node with a copy of the element data and makes it the new head.
 * Operation is O(1).
 * @param list Pointer to the list. Must not be NULL.
 * @param elem Pointer to the element data to insert. Must not be NULL.
 */
void list_push_front(list_t* list, void* elem);

/**
 * Removes the first element from the list.
 * Deallocates the head node and its data. Updates head to the next node.
 * Operation is O(1).
 * @param list Pointer to the list. Must not be NULL.
 * @note Does nothing if the list is empty.
 */
void list_pop_front(list_t* list);

/**
 * Retrieves a pointer to the element at the specified index.
 * Traverses the list to find the element at the given position.
 * @param list Pointer to the list. Must not be NULL.
 * @param index Zero-based position of the element to retrieve. Must be < list size.
 * @return Pointer to the element data on success, NULL if index is out of bounds.
 * @note Returned pointer is valid until the list is modified or freed. Operation is O(n).
 */
void* list_get(const list_t* list, size_t index);

/**
 * Finds the index of the first occurrence of an element in the list.
 * Compares element addresses, not content (pointer equality).
 * @param list Pointer to the list. Must not be NULL.
 * @param elem Pointer to the element data to find. Must not be NULL.
 * @return Zero-based index of the element if found, -1 otherwise.
 */
int list_index_of(const list_t* list, void* elem);

/**
 * Inserts an element at the specified index in the list.
 * Creates a new node with a copy of the element data at position index.
 * Existing elements at index and beyond are shifted right.
 * @param list Pointer to the list. Must not be NULL.
 * @param index Zero-based position at which to insert. Must be <= list size.
 * @param elem Pointer to the element data to insert. Must not be NULL.
 * @note If index equals list size, appends to the end. Operation is O(n).
 */
void list_insert(list_t* list, size_t index, void* elem);

/**
 * Removes the first occurrence of an element from the list.
 * Searches for the element by pointer equality and removes it.
 * Deallocates the matching node and its data.
 * @param list Pointer to the list. Must not be NULL.
 * @param elem Pointer to the element data to remove. Must not be NULL.
 * @note Does nothing if the element is not found in the list.
 */
void list_remove(list_t* list, void* elem);

/**
 * Inserts an element immediately after a specified element in the list.
 * Creates a new node with a copy of elem and inserts it after the node containing after.
 * @param list Pointer to the list. Must not be NULL.
 * @param elem Pointer to the element data to insert. Must not be NULL.
 * @param after Pointer to the element data after which to insert. Must not be NULL.
 * @note Does nothing if after is not found in the list.
 */
void list_insert_after(list_t* list, void* elem, void* after);

/**
 * Inserts an element immediately before a specified element in the list.
 * Creates a new node with a copy of elem and inserts it before the node containing before.
 * @param list Pointer to the list. Must not be NULL.
 * @param elem Pointer to the element data to insert. Must not be NULL.
 * @param before Pointer to the element data before which to insert. Must not be NULL.
 * @note Does nothing if before is not found in the list.
 */
void list_insert_before(list_t* list, void* elem, void* before);

/**
 * Forward iteration macro for traversing all nodes in a list.
 * Iterates from head to tail.
 * Usage: LIST_FOR_EACH(my_list, node) { ... use node->data ... }
 * @param list Pointer to the list to iterate over.
 * @param node Name of the list_node_t* variable to use in the loop body.
 */
#define LIST_FOR_EACH(list, node) for (list_node_t * (node) = (list)->head; (node); (node) = (node)->next)

/**
 * Reverse iteration macro for traversing all nodes in a list.
 * Iterates from tail to head.
 * Usage: LIST_FOR_EACH_REVERSE(my_list, node) { ... use node->data ... }
 * @param list Pointer to the list to iterate over.
 * @param node Name of the list_node_t* variable to use in the loop body.
 */
#define LIST_FOR_EACH_REVERSE(list, node) for (list_node_t * (node) = (list)->tail; (node); (node) = (node)->prev)

#if defined(__cplusplus)
}
#endif

#endif /* LIST_H */
