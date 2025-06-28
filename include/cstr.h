#ifndef CSTR_H
#define CSTR_H

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STR_NPOS -1

/**
 * @brief A dynamically resizable C-string with Small String Optimization (SSO).
 *
 * This structure implements an efficient string type that stores small strings
 * (up to SSO_MAX_SIZE (24 bytes) ) directly in the structure to avoid heap allocation,
 * and larger strings on the heap. This provides optimal performance for both
 * small and large strings while maintaining a consistent API.
 *
 * The structure uses a union to overlay stack and heap storage modes:
 * - Stack mode: For strings up to SSO_MAX_SIZE-1 characters
 * - Heap mode: For larger strings, indicated by the MSB of capacity field
 *
 * @note All strings are null-terminated regardless of storage mode.
 * @note The structure size is optimized to fit common cache line sizes.
 */
typedef struct cstr cstr;

// Lightweight string view that points to a const char * data
// with pre-computed length. Avoid overhead of strlen.
typedef struct {
    const char* data;  // Pointer to string data
    size_t length;     // Length of the view
} str_view;

/**
 * @brief Creates a new empty cstr with specified initial capacity.
 *
 * Creates a new dynamically allocated cstr with at least the requested capacity.
 * The string is initialized to empty but can grow up to the specified capacity
 * without reallocation.
 *
 * @param initial_capacity Requested initial capacity including null terminator
 * @return Pointer to new cstr on success, NULL on allocation failure
 * @note Caller must call str_free() to release memory
 * @note Actual capacity may be larger than requested for optimization
 */
[[nodiscard]] cstr* cstr_init(size_t initial_capacity);

/**
 * @brief Creates a new cstr from a C string.
 *
 * Creates a new cstr containing a copy of the input C string. The new string
 * will have exactly the capacity needed to store the input plus room for growth.
 *
 * @param input C string to copy (must be null-terminated, can be NULL)
 * @return Pointer to new cstr on success, NULL on allocation failure or if input is NULL
 * @note Caller must call str_free() to release memory
 */
[[nodiscard]] cstr* cstr_new(const char* input);

// Debug function to print all string details
void cstr_debug(const cstr* s);

/**
 * @brief Checks if the string uses heap storage.
 *
 * @param s Pointer to the cstr (can be NULL)
 * @return true if heap-allocated, false if stack-allocated or NULL
 */
bool cstr_allocated(const cstr* s);

/**
 * @brief Frees a cstr and all associated memory.
 *
 * Releases all memory associated with the cstr, including heap-allocated
 * string data if applicable. After calling this function, the pointer
 * becomes invalid and must not be used.
 *
 * @param s Pointer to the cstr to free (can be NULL)
 * @note Safe to call with NULL pointer
 */
void cstr_free(cstr* s);

// ========== Information ==========

/**
 * @brief Returns the length of the string.
 *
 * @param s Pointer to the cstr (can be NULL)
 * @return Length excluding null terminator, or 0 if s is NULL
 */
size_t cstr_len(const cstr* s);

/**
 * @brief Returns the current capacity of the string.
 *
 * @param s Pointer to the cstr (can be NULL)
 * @return Current capacity including null terminator, or 0 if s is NULL
 */
size_t cstr_capacity(const cstr* s);

/**
 * @brief Checks if the string is empty.
 *
 * @param s Pointer to the cstr (can be NULL)
 * @return true if NULL or empty, false otherwise
 */
bool cstr_empty(const cstr* s);

/**
 * @brief Resizes the string's capacity.
 *
 * Ensures the string has at least the specified capacity. If the current
 * capacity is already sufficient, no operation is performed.
 *
 * @param s Pointer to the cstr (must not be NULL)
 * @param new_capacity Minimum required capacity including null terminator
 * @return true on success, false on allocation failure or if s is NULL
 */
bool cstr_resize(cstr* s, size_t capacity);

// ============ Modification ============

/**
 * @brief Appends a C string to the cstr.
 *
 * Appends the entire source string to the end of the destination string,
 * automatically reallocating if necessary.
 *
 * @param s Pointer to the destination cstr (must not be NULL)
 * @param append_str C string to append (must not be NULL)
 * @return true on success, false on allocation failure or invalid input
 */
bool cstr_append(cstr* s, const char* append);

/**
 * @brief Fast append assuming sufficient capacity.
 *
 * Appends a C string without checking or expanding capacity. The caller
 * must ensure sufficient capacity exists.
 *
 * @param s Pointer to the destination cstr (must not be NULL)
 * @param append_str C string to append (must not be NULL)
 * @return true on success, false on invalid input
 * @pre Sufficient capacity must exist for the append operation
 */
bool cstr_append_fast(cstr* s, const char* append);

/**
 * @brief Creates a new cstr from a formatted string (printf-style).
 *
 * Creates a new cstr by formatting the input according to the format string,
 * similar to sprintf but with automatic memory management.
 *
 * @param format Printf-style format string (must not be NULL)
 * @param ... Arguments for the format string
 * @return Pointer to new formatted cstr on success, NULL on failure
 * @note Caller must call str_free() to release memory
 */
__attribute__((format(printf, 1, 2))) cstr* cstr_format(const char* format, ...);

/**
 * @brief Appends a formatted string to the cstr.
 *
 * Appends text formatted according to printf-style format string and arguments
 * to the end of the existing string content.
 *
 * @param s Pointer to the destination cstr (must not be NULL)
 * @param format Printf-style format string (must not be NULL)
 * @param ... Arguments for the format string
 * @return true on success, false on allocation failure or formatting error
 */
bool cstr_append_fmt(cstr* s, const char* format, ...);

/**
 * @brief Appends a single character to the cstr.
 *
 * @param s Pointer to the destination cstr (must not be NULL)
 * @param c Character to append
 * @return true on success, false on allocation failure or invalid input
 */
bool cstr_append_char(cstr* s, char c);

/**
 * @brief Prepends a C string to the beginning of the cstr.
 *
 * Inserts the source string at the beginning of the destination string,
 * shifting existing content to the right.
 *
 * @param s Pointer to the destination cstr (must not be NULL)
 * @param prepend_str C string to prepend (must not be NULL)
 * @return true on success, false on allocation failure or invalid input
 */
bool cstr_prepend(cstr* s, const char* prepend);

/**
 * @brief Fast prepend assuming sufficient capacity.
 *
 * Prepends a C string without checking or expanding capacity. The caller
 * must ensure sufficient capacity exists.
 *
 * @param s Pointer to the destination cstr (must not be NULL)
 * @param prepend_str C string to prepend (must not be NULL)
 * @return true on success, false on invalid input
 * @pre Sufficient capacity must exist for the prepend operation
 */
bool cstr_prepend_fast(cstr* s, const char* prepend);

/**
 * @brief Inserts a C string at the specified position.
 *
 * Inserts the source string at the given index, shifting existing content
 * to make room. Index must be within the current string length.
 *
 * @param s Pointer to the destination cstr (must not be NULL)
 * @param index Position to insert at (0-based, must be <= current length)
 * @param insert_str C string to insert (must not be NULL)
 * @return true on success, false on allocation failure or invalid input/index
 */
bool cstr_insert(cstr* s, size_t index, const char* insert);

/**
 * @brief Removes a range of characters from the cstr.
 *
 * Removes 'count' characters starting from 'index'. If 'index' + 'count'
 * extends beyond the string's length, characters are removed until the end.
 *
 * @param s Pointer to the cstr (must not be NULL)
 * @param index Starting index of the range to remove.
 * @param count Number of characters to remove.
 * @return True on success, false on invalid input or index.
 */
bool cstr_remove(cstr* s, size_t index, size_t count);

/**
 * @brief Clears the cstr, setting its length to 0.
 *
 * Sets the string's length to zero and null-terminates the first character.
 * The capacity remains unchanged.
 *
 * @param s Pointer to the cstr (can be NULL).
 */
void cstr_clear(cstr* s);

// ============ Access ============

/**
 * @brief Removes all occurrences of a substring from the cstr.
 *
 * Removes all instances of the specified substring from the string.
 *
 * @param s Pointer to the cstr (must not be NULL).
 * @param substr Substring to remove (must not be NULL and not empty).
 * @return Number of occurrences removed. Returns 0 on invalid input or if substring is not found.
 */
size_t cstr_remove_all(cstr* s, const char* substr);

/**
 * @brief Returns the character at the specified index.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param index Index of the character (0-based).
 * @return The character at the index, or '\0' if s is NULL or index is out of bounds.
 */
char cstr_at(const cstr* s, size_t index);

/**
 * @brief Returns a mutable pointer to the cstr's data.
 *
 * Provides direct access to the underlying character buffer. Use with caution,
 * as modifying the buffer without updating the string's length can lead to
 * inconsistencies.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @return Pointer to the null-terminated string, or NULL if s is NULL.
 */
[[nodiscard]] char* cstr_data(cstr* s);

/**
 * @brief Returns a const pointer to the cstr's data.
 *
 * Provides read-only access to the underlying character buffer.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @return Const pointer to the null-terminated string, or NULL if s is NULL.
 */
[[nodiscard]] const char* cstr_data_const(const cstr* s);

/**
 * @brief Converts the cstr to a string view.
 *
 * Creates a read-only view of the cstr's data and length.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @return A str_view representing the cstr's data and length. If s is NULL,
 * an empty str_view is returned.
 */
str_view cstr_as_view(const cstr* s);

// =========== Comparison and search ==================

/**
 * @brief Compares two cstrs lexicographically.
 *
 * Compares the strings based on their character sequences.
 *
 * @param s1 First cstr (can be NULL).
 * @param s2 Second cstr (can be NULL).
 * @return Negative if s1 < s2, zero if s1 == s2, positive if s1 > s2.
 *         NULL strings are considered less than non-NULL strings. Two NULL
 *         strings are considered equal.
 */
int cstr_compare(const cstr* s1, const cstr* s2);

/**
 * @brief Checks if two cstrs are equal.
 *
 * Checks if the strings have the same length and the same character sequences.
 *
 * @param s1 First cstr (can be NULL).
 * @param s2 Second cstr (can be NULL).
 * @return True if the cstrs are equal, false otherwise. Two NULL strings are
 *         considered equal.
 */
bool cstr_equals(const cstr* s1, const cstr* s2);

/**
 * @brief Checks if the cstr starts with the given prefix.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param prefix Prefix to check (can be NULL).
 * @return True if the cstr starts with the prefix, false otherwise.
 *         Returns false if s is NULL or prefix is NULL. An empty prefix
 *         is considered a prefix of any string.
 */
bool cstr_starts_with(const cstr* s, const char* prefix);

/**
 * @brief Checks if the cstr ends with the given suffix.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param suffix Suffix to check (can be NULL).
 * @return True if the cstr ends with the suffix, false otherwise.
 *         Returns false if s is NULL or suffix is NULL. An empty suffix
 *         is considered a suffix of any string.
 */
bool cstr_ends_with(const cstr* s, const char* suffix);

/**
 * @brief Finds the first occurrence of a substring in the cstr.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param substr Substring to find (can be NULL).
 * @return Index of the first occurrence (0-based), or STR_NPOS (-1) if not found or invalid input.
 */
int cstr_find(const cstr* s, const char* substr);

/**
 * @brief Finds the last occurrence of a substring in the cstr.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param substr Substring to find (can be NULL).
 * @return Index of the last occurrence (0-based), or STR_NPOS (-1) if not found or invalid input.
 */
int cstr_rfind(const cstr* s, const char* substr);

// ============== Transformation ====================

/**
 * @brief Converts the cstr to lowercase in place.
 *
 * Converts all uppercase characters in the string to their lowercase equivalents.
 *
 * @param s Pointer to the cstr (can be NULL).
 */
void cstr_lower(cstr* s);

/**
 * @brief Converts the cstr to uppercase in place.
 *
 * Converts all lowercase characters in the string to their uppercase equivalents.
 *
 * @param s Pointer to the cstr (can be NULL).
 */
void cstr_upper(cstr* s);

/**
 * @brief Converts the cstr to snake_case in place.
 *
 * Converts a string like "CamelCaseString" or "PascalCaseString" to
 * "camel_case_string". Inserts underscores before uppercase letters
 * (except the first) and converts all characters to lowercase.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @return true on success, false on allocation failure or invalid input.
 */
bool cstr_snakecase(cstr* s);

/**
 * @brief Converts the cstr to camelCase in place.
 *
 * Converts a string like "snake_case_string" or "PascalCaseString" to
 * "camelCaseString". Removes underscores/spaces and capitalizes the following letter.
 * The first character is converted to lowercase.
 *
 * @param s Pointer to the cstr (can be NULL).
 */
void cstr_camelcase(cstr* s);

/**
 * @brief Converts the cstr to PascalCase in place.
 *
 * Converts a string like "snake_case_string" or "camelCaseString" to
 * "PascalCaseString". Removes underscores/spaces and capitalizes the following letter.
 * The first character is converted to uppercase.
 *
 * @param s Pointer to the cstr (can be NULL).
 */
void cstr_pascalcase(cstr* s);

/**
 * @brief Converts the cstr to Title Case in place.
 *
 * Capitalizes the first character of each word and converts the rest to lowercase.
 * Words are delimited by spaces.
 *
 * @param s Pointer to the cstr (can be NULL).
 */
void cstr_titlecase(cstr* str);

/**
 * @brief Removes leading and trailing whitespace from the cstr in place.
 *
 * Removes whitespace characters (as defined by `isspace()`) from both the
 * beginning and the end of the string.
 *
 * @param s Pointer to the cstr (can be NULL).
 */
void cstr_trim(cstr* s);

/**
 * @brief Removes trailing whitespace from the cstr in place.
 *
 * Removes whitespace characters (as defined by `isspace()`) from the end
 * of the string.
 *
 * @param s Pointer to the cstr (can be NULL).
 */
void cstr_rtrim(cstr* s);

/**
 * @brief Removes leading whitespace from the cstr in place.
 *
 * Removes whitespace characters (as defined by `isspace()`) from the beginning
 * of the string.
 *
 * @param s Pointer to the cstr (can be NULL).
 */
void cstr_ltrim(cstr* s);

/**
 * @brief Removes leading and trailing characters from the cstr in place based on a set of characters.
 *
 * Removes characters specified in the 'chars' string from both the beginning
 * and the end of the string.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param chars C string containing characters to remove (can be NULL or empty).
 */
void cstr_trim_chars(cstr* str, const char* chars);

/**
 * @brief Count the number of occurrences of a substring within the string.
 *
 * @param str Pointer to the cstr (can be NULL).
 * @param substr Substring to count (can be NULL).
 * @return Number of occurrences. Returns 0 on invalid input or if substring is not found.
 */
size_t cstr_count_substr(const cstr* str, const char* substr);

/**
 * @brief Remove characters in str from `start` index, up to `start + length`.
 * @param str Pointer to cstr.
 * @param start Start index of substring in str.
 * @param substr_length Length of the substring.
 */
void cstr_remove_substr(cstr* str, size_t start, size_t substr_length);

/**
 * @brief Removes all occurrences of a character from the cstr.
 *
 * Removes all instances of the specified character from the string.
 *
 * @param s Pointer to the cstr (must not be NULL).
 * @param c Character to remove.
 */
void cstr_remove_char(cstr* s, char c);

// ============== Substrings and replacements ==============

/**
 * @brief Extracts a substring from the cstr.
 *
 * Creates a new cstr containing a portion of the original string starting
 * at 'start' index with the specified 'length'. If 'start' is out of bounds
 * or 'start' + 'length' exceeds the original string's length, the substring
 * will be truncated accordingly.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param start Starting index of the substring (0-based).
 * @param length Length of the substring.
 * @return Pointer to the new cstr containing the substring, or NULL on invalid input or allocation failure.
 */
[[nodiscard]] cstr* cstr_substr(const cstr* s, size_t start, size_t length);

/**
 * @brief Replaces the first occurrence of a substring with another in the cstr.
 *
 * Creates a new cstr where the first occurrence of 'old_str' is replaced by 'new_str'.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param old_str Substring to replace (can be NULL). Cannot be empty.
 * @param new_str Replacement substring (can be NULL).
 * @return Pointer to the new cstr with the first occurrence replaced, or NULL on invalid input or allocation
 * failure.
 */
[[nodiscard]] cstr* cstr_replace(const cstr* s, const char* old, const char* new_str);

/**
 * @brief Replaces all occurrences of a substring with another.
 *
 * Creates a new cstr where all non-overlapping occurrences of 'old_sub'
 * are replaced by 'new_sub'.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param old_sub Substring to replace (can be NULL). Cannot be empty.
 * @param new_sub Replacement substring (can be NULL).
 * @return Pointer to the new cstr with replacements, or NULL on invalid input or allocation failure.
 */
[[nodiscard]] cstr* cstr_replace_all(const cstr* s, const char* old, const char* new_str);

// ========== Splitting and joining ===========

/**
 * @brief Splits the cstr into substrings based on a delimiter.
 *
 * Divides the string into an array of new cstr objects, using the delimiter
 * as the separator. Consecutive delimiters result in empty strings in the output array.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param delim Delimiter string (can be NULL). If empty, returns an array containing a copy of the original
 * string.
 * @param count_out Pointer to store the number of resulting substrings (must not be NULL).
 * @return Array of cstr pointers, or NULL on invalid input or allocation failure.
 *         The caller is responsible for freeing the array and each cstr within it.
 */
[[nodiscard]] cstr** cstr_split(const cstr* s, const char* delim, size_t* count);

/**
 * @brief Joins multiple cstrs with a delimiter.
 *
 * Concatenates an array of cstrs into a single new cstr, separated by the
 * specified delimiter.
 *
 * @param strings Array of cstr pointers (can be NULL or empty). Each cstr pointer must not be NULL.
 * @param count Number of cstrs in the array.
 * @param delim Delimiter string (can be NULL for no delimiter).
 * @return Pointer to the new cstr with joined strings, or NULL on invalid input or allocation failure.
 *         Returns a new empty cstr if the input array is empty.
 */
[[nodiscard]] cstr* cstr_join(const cstr** strings, size_t count, const char* delim);

/**
 * @brief Creates a new cstr with the contents of the input cstr reversed.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @return Pointer to the new reversed cstr, or NULL on invalid input or allocation failure.
 */
[[nodiscard]] cstr* cstr_reverse(const cstr* s);

/**
 * @brief Removes leading and trailing characters from the cstr in place based on a set of characters.
 *
 * Removes characters specified in the 'chars' string from both the beginning
 * and the end of the string.
 *
 * @param s Pointer to the cstr (can be NULL).
 * @param chars C string containing characters to remove (can be NULL or empty).
 */
void cstr_reverse_inplace(cstr* s);

#ifdef __cplusplus
}
#endif

#endif  // CSTR_H
