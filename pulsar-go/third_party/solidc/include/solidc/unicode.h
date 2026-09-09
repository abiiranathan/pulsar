#ifndef SOLIDC_UNICODE_H
#define SOLIDC_UNICODE_H

/**
 * @file unicode.h
 * @brief Unicode handling library for C with UTF-8 encoding support.
 *
 * This library provides comprehensive UTF-8 string manipulation capabilities
 * including encoding/decoding, validation, searching, transformation, and
 * character classification using Unicode standards.
 *
 * UTF-8 is a variable-length encoding that uses 1-4 bytes per codepoint:
 * - 1 byte:  U+0000 to U+007F    (ASCII compatible)
 * - 2 bytes: U+0080 to U+07FF
 * - 3 bytes: U+0800 to U+FFFF
 * - 4 bytes: U+10000 to U+10FFFF
 *
 * @note All functions that modify strings in-place require null-terminated input.
 * @note Thread safety depends on the underlying C library (particularly locale functions).
 * @version 1.0
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Unicode version supported by this library. */
#define UNICODE_VERSION 0x0100  // 1.0

/** Maximum valid Unicode codepoint (last valid: U+10FFFF). */
#define UNICODE_MAX_CODEPOINT 0x10FFFF  // 1,114,111

/** Maximum number of bytes in a UTF-8 encoded character. */
#define UNICODE_MAX_UTF8_BYTES 4

#define UTF8_MAX_LEN (UNICODE_MAX_UTF8_BYTES + 1)

/**
 * @brief Represents a mutable UTF-8 encoded string with metadata.
 *
 * This structure maintains both the UTF-8 byte data and precomputed
 * statistics about the string for efficient operations.
 *
 * @note Implementation detail, not part of the contract callers rely on:
 *       `data` points into memory immediately following this struct within
 *       a single allocation (struct + data live in one malloc'd block).
 *       `data` must therefore never be passed to realloc()/free() on its
 *       own; always operate on the utf8_string* itself (e.g. via
 *       utf8_free(), or internally via realloc() on `s`, not `s->data`).
 *       This is purely an implementation detail: utf8_data(s), s->data,
 *       and free(s) all continue to work exactly as before.
 */
typedef struct utf8_string {
    char* data; /**< Null-terminated UTF-8 string data. Points into this struct's own allocation; never free or realloc
                   it separately. */
    size_t length;   /**< Total number of bytes in use (excluding null terminator). */
    size_t count;    /**< Number of Unicode codepoints (characters). */
    size_t capacity; /**< Bytes allocated for data, excluding the implicit null terminator byte. */
} utf8_string;

/* ============================================================================
 * Core Encoding/Decoding Functions
 * ============================================================================ */

/**
 * @brief Converts a Unicode codepoint to its UTF-8 byte sequence.
 * @param codepoint The Unicode codepoint to encode (must be <= 0x10FFFF).
 * @param utf8 Output buffer (minimum 5 bytes) that receives null-terminated UTF-8 string.
 * @note Invalid codepoints result in utf8[0] = '\0'.
 */
void ucp_to_utf8(uint32_t codepoint, char utf8[UTF8_MAX_LEN]);

/**
 * @brief Decodes a UTF-8 byte sequence to its Unicode codepoint.
 * @param utf8 Pointer to UTF-8 encoded byte sequence. Must not be NULL.
 * @return The decoded codepoint, or 0xFFFD (replacement char) if invalid.
 * @note Only examines the first complete UTF-8 sequence.
 */
uint32_t utf8_to_codepoint(const char* utf8);

/**
 * @brief Counts the number of Unicode codepoints in a UTF-8 string.
 * @param utf8 Null-terminated UTF-8 string. NULL returns 0.
 * @return Number of codepoints (characters, not bytes).
 */
size_t utf8_count_codepoints(const char* utf8);

/**
 * @brief Counts the number of valid UTF-8 bytes in a string.
 * @param s Null-terminated string. NULL returns 0.
 * @return Total bytes in all valid UTF-8 sequences.
 * @note Invalid sequences are skipped (counted as 0 bytes).
 */
size_t utf8_valid_byte_count(const char* s);

/**
 * @brief Determines the byte length of a UTF-8 character from its first byte.
 * @param str Pointer to the first byte. Must not be NULL.
 * @return Byte length (1-4), or 0 if invalid.
 */
size_t utf8_char_length(const char* str);

/* ============================================================================
 * Validation Functions
 * ============================================================================ */

/**
 * @brief Validates whether a codepoint is within the valid Unicode range.
 * @param codepoint The codepoint to validate.
 * @return true if in range [0, 0x10FFFF], false otherwise.
 */
bool is_valid_codepoint(uint32_t codepoint);

/**
 * @brief Comprehensively validates a UTF-8 encoded string.
 * @param utf8 Null-terminated UTF-8 string. NULL returns false.
 * @return true if entire string is valid UTF-8, false otherwise.
 * @note Checks structure, overlong encodings, surrogates, and range.
 */
bool is_valid_utf8(const char* utf8);

/* ============================================================================
 * Character Classification Functions
 * ============================================================================ */

/**
 * @brief Checks if a codepoint represents whitespace.
 * @param codepoint The codepoint to test.
 * @return true if whitespace per current locale.
 */
bool is_codepoint_whitespace(uint32_t codepoint);

/**
 * @brief Checks if a UTF-8 character represents whitespace.
 * @param utf8 Pointer to UTF-8 character. Must not be NULL.
 * @return true if whitespace, false otherwise or on error.
 */
bool is_utf8_whitespace(const char* utf8);

/**
 * @brief Checks if a codepoint represents a digit.
 * @param codepoint The codepoint to test.
 * @return true if digit per current locale.
 */
bool is_codepoint_digit(uint32_t codepoint);

/**
 * @brief Checks if a UTF-8 character represents a digit.
 * @param utf8 Pointer to UTF-8 character. Must not be NULL.
 * @return true if digit, false otherwise or on error.
 */
bool is_utf8_digit(const char* utf8);

/**
 * @brief Checks if a codepoint represents an alphabetic character.
 * @param codepoint The codepoint to test.
 * @return true if alphabetic per current locale.
 */
bool is_codepoint_alpha(uint32_t codepoint);

/**
 * @brief Checks if a UTF-8 character represents an alphabetic character.
 * @param utf8 Pointer to UTF-8 character. Must not be NULL.
 * @return true if alphabetic, false otherwise or on error.
 */
bool is_utf8_alpha(const char* utf8);

/**
 * @brief Checks if a codepoint represents an alphanumeric character.
 * @param codepoint The codepoint to test.
 * @return true if alphanumeric.
 */
bool is_codepoint_alnum(uint32_t codepoint);

/**
 * @brief Checks if a UTF-8 character represents an alphanumeric character.
 * @param utf8 Pointer to UTF-8 character. Must not be NULL.
 * @return true if alphanumeric, false otherwise or on error.
 */
bool is_utf8_alnum(const char* utf8);

/**
 * @brief Checks if a codepoint represents a punctuation character.
 * @param codepoint The codepoint to test.
 * @return true if punctuation per current locale.
 */
bool is_codepoint_punct(uint32_t codepoint);

/**
 * @brief Checks if a UTF-8 character represents a punctuation character.
 * @param utf8 Pointer to UTF-8 character. Must not be NULL.
 * @return true if punctuation, false otherwise or on error.
 */
bool is_utf8_punct(const char* utf8);

/* ============================================================================
 * String Object Lifecycle Functions
 * ============================================================================ */

/**
 * @brief Creates a new utf8_string object from a C string.
 * @param data Null-terminated UTF-8 string. NULL returns NULL.
 * @return Newly allocated utf8_string, or NULL on failure.
 * @note Caller must free using utf8_free().
 */
utf8_string* utf8_new(const char* data);

/**
 * @brief Creates an empty utf8_string with preallocated capacity.
 * @param capacity Initial byte capacity to allocate.
 * @return Newly allocated empty utf8_string, or NULL on failure.
 * @note Caller must free using utf8_free().
 */
utf8_string* utf8_new_with_capacity(size_t capacity);

/**
 * @brief Frees all resources associated with a utf8_string.
 * @param s The utf8_string to free. NULL is safely ignored.
 */
void utf8_free(utf8_string* s);

/**
 * @brief Creates a copy of a UTF-8 string containing only valid UTF-8 sequences.
 * @param data Null-terminated UTF-8 string. NULL returns NULL.
 * @return Newly allocated copy, or NULL on failure.
 * @note Caller must free using free().
 */
char* utf8_copy(const char* data);

/**
 * @brief Duplicates a utf8_string object.
 * @param s The utf8_string to duplicate. Must not be NULL.
 * @return Newly allocated copy, or NULL on failure.
 * @note Caller must free using utf8_free().
 */
utf8_string* utf8_clone(const utf8_string* s);

/* ============================================================================
 * String Access and Information Functions
 * ============================================================================ */

/**
 * @brief Returns a pointer to the internal UTF-8 data buffer.
 * @param s The utf8_string object. Must not be NULL.
 * @return Pointer to internal null-terminated UTF-8 string, or NULL if s is NULL.
 * @note The pointer is owned by the utf8_string and should not be freed.
 */
const char* utf8_data(const utf8_string* s);

/**
 * @brief Prints the UTF-8 string content to stdout followed by a newline.
 * @param s The utf8_string to print. Must not be NULL.
 */
void utf8_print(const utf8_string* s);

/**
 * @brief Prints metadata about the UTF-8 string to stdout.
 * @param s The utf8_string to inspect. Must not be NULL.
 */
void utf8_print_info(const utf8_string* s);

/**
 * @brief Prints the Unicode codepoints in U+XXXX format to stdout.
 * @param s The utf8_string to print. Must not be NULL.
 */
void utf8_print_codepoints(const utf8_string* s);

/* ============================================================================
 * String Search and Comparison Functions
 * ============================================================================ */

/**
 * @brief Finds the byte index of the first occurrence of a substring.
 * @param s The utf8_string to search in. Must not be NULL.
 * @param utf8 The substring to search for. Must not be NULL.
 * @return Byte index of first occurrence, or -1 if not found or on error.
 */
int utf8_index_of(const utf8_string* s, const char* utf8);

/**
 * @brief Finds the byte index of the last occurrence of a substring.
 * @param s The utf8_string to search in. Must not be NULL.
 * @param utf8 The substring to search for. Must not be NULL.
 * @return Byte index of last occurrence, or -1 if not found or on error.
 */
int utf8_last_index_of(const utf8_string* s, const char* utf8);

/**
 * @brief Checks if a string starts with a given prefix.
 * @param str Null-terminated UTF-8 string. Must not be NULL.
 * @param prefix The prefix to test for. Must not be NULL.
 * @return true if str starts with prefix, false otherwise.
 */
bool utf8_starts_with(const char* str, const char* prefix);

/**
 * @brief Checks if a string ends with a given suffix.
 * @param str Null-terminated UTF-8 string. Must not be NULL.
 * @param suffix The suffix to test for. Must not be NULL.
 * @return true if str ends with suffix, false otherwise.
 */
bool utf8_ends_with(const char* str, const char* suffix);

/**
 * @brief Checks if a string contains a substring.
 * @param str Null-terminated UTF-8 string. Must not be NULL.
 * @param substr The substring to search for. Must not be NULL.
 * @return true if substr is found in str, false otherwise.
 */
bool utf8_contains(const char* str, const char* substr);

/**
 * @brief Compares two UTF-8 strings lexicographically.
 * @param s1 First UTF-8 string. NULL is treated as empty.
 * @param s2 Second UTF-8 string. NULL is treated as empty.
 * @return 0 if equal, <0 if s1 < s2, >0 if s1 > s2.
 */
int utf8_compare(const char* s1, const char* s2);

/**
 * @brief Compares two UTF-8 strings for equality.
 * @param s1 First UTF-8 string. Must not be NULL.
 * @param s2 Second UTF-8 string. Must not be NULL.
 * @return true if strings are byte-for-byte identical, false otherwise.
 */
bool utf8_equals(const char* s1, const char* s2);

/* ============================================================================
 * String Modification Functions
 * ============================================================================ */

/**
 * @brief Appends UTF-8 data to the end of a utf8_string.
 * @param s_ptr Address of the utf8_string to append to. Must not be NULL,
 *              and *s_ptr must not be NULL. On success, *s_ptr is updated
 *              to point at the (possibly relocated) string; the caller
 *              must use *s_ptr afterward and must not dereference the
 *              value *s_ptr held before the call.
 * @param data Null-terminated UTF-8 string to append. NULL is safely ignored.
 * @return true on success, false on allocation failure (in which case
 *         *s_ptr is left unchanged and still valid).
 * @note Takes utf8_string** rather than utf8_string* because the struct
 *       and its data buffer share a single allocation; growing the buffer
 *       can move the entire block, including the struct itself.
 */
bool utf8_append(utf8_string** s_ptr, const char* data);

/**
 * @brief Extracts a substring by byte range.
 * @param s The source utf8_string. Must not be NULL.
 * @param index The starting byte index.
 * @param utf8_byte_len The number of bytes to extract.
 * @return Newly allocated substring, or NULL on failure.
 * @note Caller must free using free().
 */
char* utf8_substr(const utf8_string* s, size_t index, size_t utf8_byte_len);

/**
 * @brief Inserts UTF-8 data at a specific byte index.
 * @param s_ptr Address of the utf8_string to modify. Must not be NULL, and
 *              *s_ptr must not be NULL. On success, *s_ptr is updated to
 *              point at the (possibly relocated) string.
 * @param index The byte index at which to insert.
 * @param data Null-terminated UTF-8 string to insert. NULL is safely ignored.
 * @return true on success, false on allocation failure or invalid index
 *         (in which case *s_ptr is left unchanged and still valid).
 * @note Takes utf8_string** for the same reason as utf8_append(): the
 *       struct and its data buffer share one allocation, so growing the
 *       buffer can relocate the struct.
 */
bool utf8_insert(utf8_string** s_ptr, size_t index, const char* data);

/**
 * @brief Removes a specified number of codepoints starting at a byte index.
 * @param s The utf8_string to modify. Must not be NULL.
 * @param index The starting byte index.
 * @param count The number of codepoints (not bytes) to remove.
 * @return true on success, false if parameters are invalid.
 */
bool utf8_remove(utf8_string* s, size_t index, size_t count);

/**
 * @brief Replaces the first occurrence of a substring with another string.
 * @param s_ptr Address of the utf8_string to modify. Must not be NULL, and
 *              *s_ptr must not be NULL. On success, *s_ptr is updated to
 *              point at the (possibly relocated) string.
 * @param old_str The substring to find and replace. Must not be NULL.
 * @param new_str The replacement string. Must not be NULL.
 * @return true if replacement occurred, false if old_str not found, on
 *         allocation failure, or on invalid parameters. *s_ptr is left
 *         unchanged and still valid in all false-returning cases.
 * @note Takes utf8_string** for the same reason as utf8_append(): the
 *       struct and its data buffer share one allocation, so growing the
 *       buffer (when new_str is longer than old_str) can relocate the
 *       struct.
 */
bool utf8_replace(utf8_string** s_ptr, const char* old_str, const char* new_str);

/**
 * @brief Replaces all occurrences of a substring with another string.
 * @param s_ptr Address of the utf8_string to modify. Must not be NULL, and
 *              *s_ptr must not be NULL. On success, *s_ptr is updated to
 *              point at the (possibly relocated) string.
 * @param old_str The substring to find and replace. Must not be NULL or empty.
 * @param new_str The replacement string. Must not be NULL (can be empty).
 * @return Number of replacements made, or 0 if none found or on error.
 *         *s_ptr reflects all replacements completed even if a later one
 *         fails partway through (see implementation note in unicode.c).
 * @note Takes utf8_string** for the same reason as utf8_append(): the
 *       struct and its data buffer share one allocation, so growing the
 *       buffer can relocate the struct.
 */
size_t utf8_replace_all(utf8_string** s_ptr, const char* old_str, const char* new_str);

/**
 * @brief Reverses a UTF-8 string by codepoints.
 * @param s The utf8_string to reverse. Must not be NULL.
 * @return A new utf8_string* success, NULL failure.
 */
utf8_string* utf8_reverse(const utf8_string* s);

/**
 * @brief Concatenates two utf8_string objects into a new string.
 * @param s1 First utf8_string. Must not be NULL.
 * @param s2 Second utf8_string. Must not be NULL.
 * @return Newly allocated utf8_string containing s1 + s2, or NULL on error.
 * @note Caller must free using utf8_free().
 */
utf8_string* utf8_concat(const utf8_string* s1, const utf8_string* s2);

/* ============================================================================
 * String Transformation Functions (In-Place)
 * ============================================================================ */

/**
 * @brief Removes leading whitespace from a UTF-8 string in-place.
 * @param str Null-terminated UTF-8 string to modify. NULL is safely ignored.
 */
void utf8_ltrim(char* str);

/**
 * @brief Removes trailing whitespace from a UTF-8 string in-place.
 * @param str Null-terminated UTF-8 string to modify. NULL is safely ignored.
 */
void utf8_rtrim(char* str);

/**
 * @brief Removes leading and trailing whitespace from a UTF-8 string in-place.
 * @param str Null-terminated UTF-8 string to modify. NULL is safely ignored.
 */
void utf8_trim(char* str);

/**
 * @brief Removes leading and trailing characters from a UTF-8 string in-place.
 * @param str Null-terminated UTF-8 string to modify. NULL is safely ignored.
 * @param c String containing codepoints to trim. NULL is safely ignored.
 */
void utf8_trim_chars(char* str, const char* c);

/**
 * @brief Removes leading and trailing occurrences of a single character.
 * @param str Null-terminated UTF-8 string to modify. NULL is safely ignored.
 * @param c The ASCII character to trim (single-byte only).
 */
void utf8_trim_char(char* str, char c);

/**
 * @brief Converts all uppercase characters to lowercase in-place.
 * @param str Null-terminated UTF-8 string to modify. NULL is safely ignored.
 * @note Uses locale-aware conversion. May change string length.
 */
void utf8_tolower(char* str);

/**
 * @brief Converts all lowercase characters to uppercase in-place.
 * @param str Null-terminated UTF-8 string to modify. NULL is safely ignored.
 * @note Uses locale-aware conversion. May change string length.
 */
void utf8_toupper(char* str);

/* ============================================================================
 * String Splitting and Array Functions
 * ============================================================================ */

/**
 * @brief Splits a UTF-8 string into parts using a delimiter.
 * @param str The utf8_string to split. Must not be NULL.
 * @param delim The delimiter string. Must not be NULL or empty.
 * @param num_parts Output parameter receiving the number of parts. Must not be NULL.
 * @return Array of utf8_string pointers, or NULL on error.
 * @note Caller must free using utf8_split_free().
 */
utf8_string** utf8_split(const utf8_string* str, const char* delim, size_t* num_parts);

/**
 * @brief Frees an array of utf8_string objects returned by utf8_split().
 * @param str The array of utf8_string pointers. NULL is safely ignored.
 * @param size The number of elements in the array.
 */
void utf8_split_free(utf8_string** str, size_t size);

/**
 * @brief Removes an element from a utf8_string array and frees it.
 * @param array The array of utf8_string pointers. Must not be NULL.
 * @param size The current size of the array.
 * @param index The index to remove. Must be < size.
 */
void utf8_array_remove(utf8_string** array, size_t size, size_t index);

/* ============================================================================
 * File I/O Functions
 * ============================================================================ */

/**
 * @brief Writes a utf8_string to a file.
 * @param s The utf8_string to write. Must not be NULL.
 * @param filename The file path. Existing files are overwritten. Must not be NULL.
 * @return Number of bytes written, or -1 on error.
 */
long utf8_writeto(const utf8_string* s, const char* filename);

/**
 * @brief Reads a UTF-8 string from a file.
 * @param filename The file path to read from. Must not be NULL.
 * @return Newly allocated utf8_string containing file contents, or NULL on error.
 * @note Caller must free using utf8_free().
 */
utf8_string* utf8_readfrom(const char* filename);

/* ============================================================================
 * Pattern Matching Functions
 * ============================================================================ */

/**
 * @brief Tests if a string matches a regular expression pattern.
 * @param str Null-terminated UTF-8 string to test. Must not be NULL.
 * @param pattern Regular expression pattern. Must not be NULL.
 * @return true if str matches pattern, false otherwise.
 * @note Pattern syntax depends on the underlying regex implementation.
 */
bool regex_match(const char* str, const char* pattern);

#ifdef __cplusplus
}
#endif

#endif /* SOLIDC_UNICODE_H */
