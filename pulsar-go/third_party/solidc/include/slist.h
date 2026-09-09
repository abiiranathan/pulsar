/**
 * @file slist.h
 * @brief Singly linked list implementation for efficient insertions and deletions.
 */

#ifndef __SLISTS__H
#define __SLISTS__H

#include <stddef.h>  // for size_t
#include <stdlib.h>  // for malloc, free

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * A node in a singly-linked list.
 * Each node contains a pointer to element data and a pointer to the next node.
 */
typedef struct slist_node {
    /** Pointer to element data stored inline in the node. */
    void* data;
    /** Pointer to the next node in the list. NULL if this is the tail. */
    struct slist_node* next;
} slist_node_t;

/**
 * A singly-linked list data structure.
 * Maintains head and tail pointers for O(1) append operations.
 * Stores elements of uniform size specified at list creation.
 */
typedef struct {
    /** Pointer to the first node in the list. NULL if empty. */
    slist_node_t* head;
    /** Pointer to the last node in the list for O(1) append. NULL if empty. */
    slist_node_t* tail;
    /** Number of elements currently in the list. */
    size_t size;
    /** Size in bytes of each element stored in the list. */
    size_t elem_size;
} slist;

/**
 * Creates a new empty singly-linked list.
 * @param elem_size Size in bytes of each element to be stored in the list.
 *                  Must be greater than zero.
 * @return Pointer to newly allocated list on success, NULL on allocation
 *         failure or if @p elem_size is zero.
 * @note Caller must free the list using slist_free() when done.
 */
slist* slist_new(size_t elem_size);

/**
 * Frees all resources associated with a singly-linked list.
 * Deallocates all nodes and their data, then the list structure itself.
 * @param list Pointer to the list to free. Safe to pass NULL.
 */
void slist_free(slist* list);

/**
 * Returns the number of elements in the list.
 * @param list Pointer to the list. Must not be NULL.
 * @return Number of elements currently stored in the list.
 */
size_t slist_size(const slist* list);

/**
 * Removes all elements from the list.
 * Deallocates all nodes and their data, leaving the list empty.
 * @param list Pointer to the list to clear. Must not be NULL.
 */
void slist_clear(slist* list);

/**
 * Creates a new list node with a copy of the provided data.
 * @param elem_size Size in bytes of the element data. Must be greater than zero.
 * @param data Pointer to the element data to copy into the node. May be NULL,
 *             in which case the payload is left uninitialized.
 * @return Pointer to newly allocated node on success, NULL on allocation
 *         failure, zero @p elem_size, or size overflow.
 * @note Internal helper function. Caller is responsible for freeing returned node.
 */
slist_node_t* slist_node_new(size_t elem_size, void* data);

/**
 * Frees a single list node and its associated data.
 * @param node Pointer to the node to free. Safe to pass NULL.
 */
void slist_node_free(slist_node_t* node);

/**
 * Inserts an element at the front of the list.
 * Creates a new node with a copy of the element data and makes it the new head.
 * @param list Pointer to the list. Must not be NULL.
 * @param elem Pointer to the element data to insert. Must not be NULL.
 */
void slist_push_front(slist* list, void* elem);

/**
 * Appends an element to the back of the list.
 * Creates a new node with a copy of the element data and makes it the new tail.
 * Operation is O(1) due to tail pointer maintenance.
 * @param list Pointer to the list. Must not be NULL.
 * @param elem Pointer to the element data to append. Must not be NULL.
 */
void slist_push_back(slist* list, void* elem);

/**
 * Removes the first element from the list.
 * Deallocates the head node and its data. Updates head to the next node.
 * @param list Pointer to the list. Must not be NULL.
 * @note Does nothing if the list is empty.
 */
void slist_pop_front(slist* list);

/**
 * Inserts an element at the specified index in the list.
 * Creates a new node with a copy of the element data at position index.
 * Existing elements at index and beyond are shifted right.
 * @param list Pointer to the list. Must not be NULL.
 * @param index Zero-based position at which to insert. Must be <= list size.
 * @param elem Pointer to the element data to insert. Must not be NULL.
 * @note If index equals list size, appends to the end.
 */
void slist_insert(slist* list, size_t index, void* elem);

/**
 * Removes the element at the specified index from the list.
 * Deallocates the node at position index and its data.
 * @param list Pointer to the list. Must not be NULL.
 * @param index Zero-based position of element to remove. Must be < list size.
 * @note Does nothing if index is out of bounds.
 */
void slist_remove(slist* list, size_t index);

/**
 * Retrieves a pointer to the element at the specified index.
 * @param list Pointer to the list. Must not be NULL.
 * @param index Zero-based position of the element to retrieve. Must be < list size.
 * @return Pointer to the element data on success, NULL if index is out of bounds.
 * @note Returned pointer is valid until the list is modified or freed.
 */
void* slist_get(const slist* list, size_t index);

/**
 * Finds the index of the first occurrence of an element in the list.
 * Compares element CONTENT byte-by-byte with memcmp() over @c elem_size,
 * not pointer identity.
 * @param list Pointer to the list. Must not be NULL.
 * @param elem Pointer to the element data to find. Must not be NULL.
 * @return Zero-based index of the element if found, -1 otherwise
 *         (including when @p elem is NULL). Indices above INT_MAX are
 *         unreachable through this int return value.
 */
int slist_index_of(const slist* list, void* elem);

/**
 * Inserts an element immediately after a specified element in the list.
 * Creates a new node with a copy of elem and inserts it after the node containing after.
 * @param list Pointer to the list. Must not be NULL.
 * @param elem Pointer to the element data to insert. Must not be NULL.
 * @param after Pointer to the element data after which to insert. Must not be NULL.
 * @note Does nothing if after is not found in the list.
 */
void slist_insert_after(slist* list, void* elem, void* after);

/**
 * Inserts an element immediately before a specified element in the list.
 * Creates a new node with a copy of elem and inserts it before the node containing before.
 * @param list Pointer to the list. Must not be NULL.
 * @param elem Pointer to the element data to insert. Must not be NULL.
 * @param before Pointer to the element data before which to insert. Must not be NULL.
 * @note Does nothing if before is not found in the list.
 */
void slist_insert_before(slist* list, void* elem, void* before);

/**
 * Prints all elements in the list as integers.
 * Assumes each element is stored as an int. Prints to stdout.
 * @param list Pointer to the list. Must not be NULL.
 * @note Debug utility function. Elements must be of type int.
 */
void slist_print_asint(const slist* list);

/**
 * Prints all elements in the list as characters.
 * Assumes each element is stored as a char. Prints to stdout.
 * @param list Pointer to the list. Must not be NULL.
 * @note Debug utility function. Elements must be of type char.
 */
void slist_print_aschar(const slist* list);

/**
 * Iteration macro for traversing all nodes in a list.
 * Usage: SLIST_FOR_EACH(my_list, node) { ... use node->data ... }
 * @param list Pointer to the list to iterate over.
 * @param node Name of the slist_node_t* variable to use in the loop body.
 * @warning Do not free the current node or otherwise invalidate it inside
 *          the loop body; the loop dereferences @p node->next afterwards.
 */
#define SLIST_FOR_EACH(list, node) for (slist_node_t * (node) = (list)->head; (node); (node) = (node)->next)

#if defined(__cplusplus)
}
#endif

#endif /* __SLISTS__H */
