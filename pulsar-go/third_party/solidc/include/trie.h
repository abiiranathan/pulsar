/**
 * @file trie.h
 * @brief Trie data structure implementation for efficient string storage and retrieval.
 */

#include "arena.h"  // Include the Arena library

#include <stdbool.h>  // for bool type
#include <stdint.h>   // for uint32_t
#include <stdio.h>    // for fprintf, stderr
#include <stdlib.h>   // for malloc, free, calloc
#include <string.h>   // for memset

/** Root structure for the Trie data structure. */
typedef struct _trie trie_t;

/** Helper structure for collecting autocomplete suggestions. */
typedef struct {
    /** Array of suggestion strings. */
    char** suggestions;
    /** Current number of suggestions. */
    size_t count;
    /** Maximum capacity of suggestions array. */
    size_t capacity;
    /** Maximum number of suggestions to collect. */
    size_t limit;
} suggestions_collector_t;

/**
 * Creates a new Trie data structure.
 * @return Pointer to new Trie on success, NULL on allocation failure.
 * @note Caller must free using trie_destroy().
 */
trie_t* trie_create(void);

/**
 * Destroys a Trie and frees all associated memory.
 * @param trie Trie to destroy (can be NULL).
 */
void trie_destroy(trie_t* trie);

/**
 * Inserts a word into the Trie.
 * @param trie The Trie structure.
 * @param word The word to insert (null-terminated).
 * @return true on success, false on failure (invalid input or allocation error).
 */
bool trie_insert(trie_t* trie, const char* word);
/**
 * Searches for an exact word in the Trie.
 * @param trie The Trie structure.
 * @param word The word to search for (null-terminated).
 * @return true if word exists in Trie, false otherwise.
 */
bool trie_search(const trie_t* trie, const char* word);
/**
 * Checks if any word in the Trie starts with the given prefix.
 * @param trie The Trie structure.
 * @param prefix The prefix to search for (null-terminated).
 * @return true if prefix exists, false otherwise.
 */
bool trie_starts_with(const trie_t* trie, const char* prefix);

/**
 * Deletes a word from the Trie.
 * @param trie The Trie structure.
 * @param word The word to delete (null-terminated).
 * @return true if word was deleted, false if word doesn't exist.
 * @note This only marks the word as deleted; nodes are not freed to maintain O(1) deletion.
 */
bool trie_delete(trie_t* trie, const char* word);

/**
 * Gets the frequency count for a word.
 * @param trie The Trie structure.
 * @param word The word to query (null-terminated).
 * @return Frequency count, or 0 if word doesn't exist.
 */
uint32_t trie_get_frequency(const trie_t* trie, const char* word);

/**
 * Gets the total number of unique words in the Trie.
 * @param trie The Trie structure.
 * @return Number of unique words, or 0 if trie is NULL.
 */
size_t trie_get_word_count(const trie_t* trie);
/**
 * Checks if the Trie is empty.
 * @param trie The Trie structure.
 * @return true if empty or NULL, false otherwise.
 */
bool trie_is_empty(const trie_t* trie);

/**
 * Autocomplete function that returns all words with a given prefix.
 * Stores the result array and suggestion strings in the provided Arena.
 *
 * @param trie The Trie structure.
 * @param prefix The prefix to search for (null-terminated).
 * @param max_suggestions Maximum number of suggestions to return.
 * @param out_count Output parameter for number of suggestions found.
 * @param arena The Arena allocator to use for the results.
 * @return Array of suggestion strings (allocated in arena), or NULL on error/not found.
 * @note The returned array and strings are owned by the Arena and freed when arena_destroy is called.
 */
const char** trie_autocomplete(const trie_t* trie, const char* prefix, size_t max_suggestions, size_t* out_count,
                               Arena* arena);
