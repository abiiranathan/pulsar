/**
 * @file regex.h
 * @brief A robust, idiomatic C API wrapping the PCRE2 library.
 *
 * Design principles:
 *   - Caller owns all memory; the library never hides allocations.
 *   - Compiled patterns are opaque, ref-counted, and thread-safe to share.
 *   - Match results are plain structs; no dynamic allocation on the hot path
 *     when the caller supplies a stack-allocated ovector.
 *   - Every failure path surfaces a rich error description.
 *
 * Thread safety:
 *   - regex_t objects are safe for concurrent use after compilation.
 *   - regex_match_t objects are per-call and must not be shared.
 *   - regex_ctx_t carries per-thread PCRE2 match data; do not share across
 *     threads.
 */
#pragma once

#include <stdbool.h> /* for bool */
#include <stddef.h>  /* for size_t */
#include <stdint.h>  /* for uint32_t */
#include <stdio.h>

/* Pull in PCRE2 with the 8-bit code unit width we target. */
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------------
 * Limits & constants
 * ------------------------------------------------------------------------- */

/** Maximum number of capture groups (including group 0) supported by this API.
 *  PCRE2 itself supports up to 65535; we cap at a practical value to allow
 *  stack allocation of regex_match_t. */
#define REGEX_MAX_GROUPS 64

/* ---------------------------------------------------------------------------
 * Error codes
 * ------------------------------------------------------------------------- */

/** Result codes returned by all regex_* functions. */
typedef enum {
    REGEX_OK = 0,           /**< Operation succeeded.                        */
    REGEX_NO_MATCH = 1,     /**< Pattern did not match the subject.           */
    REGEX_ERROR = -1,       /**< General / PCRE2 internal error.              */
    REGEX_ERROR_NOMEM = -2, /**< Memory allocation failed.                   */
    REGEX_ERROR_ARGS = -3,  /**< Invalid arguments supplied by the caller.   */
    REGEX_ERROR_LIMIT = -4, /**< Pattern has more groups than REGEX_MAX_GROUPS. */
} regex_status_t;

/* ---------------------------------------------------------------------------
 * Compile flags (thin alias over PCRE2_* options for API isolation)
 * ------------------------------------------------------------------------- */

/** Flags controlling pattern compilation. Combinable with bitwise OR. */
typedef uint32_t regex_flags_t;

#define REGEX_FLAG_NONE      (0u)              /*< No special compilation flags.              */
#define REGEX_FLAG_CASELESS  (PCRE2_CASELESS)  /**< Case-insensitive matching.         */
#define REGEX_FLAG_MULTILINE (PCRE2_MULTILINE) /**< ^ and $ match embedded newlines.   */
#define REGEX_FLAG_DOTALL    (PCRE2_DOTALL)    /**< . matches newline characters.      */
#define REGEX_FLAG_EXTENDED  (PCRE2_EXTENDED)  /**< Ignore unescaped whitespace.       */
#define REGEX_FLAG_UTF       (PCRE2_UTF)       /**< Treat pattern and subject as UTF-8.*/
#define REGEX_FLAG_UCP       (PCRE2_UCP)       /**< Use Unicode properties for \d etc.*/
#define REGEX_FLAG_UNGREEDY  (PCRE2_UNGREEDY)  /**< Invert greediness of quantifiers.  */
#define REGEX_FLAG_ANCHORED  (PCRE2_ANCHORED)  /**< Force anchoring at start.          */

/* ---------------------------------------------------------------------------
 * Core types
 * ------------------------------------------------------------------------- */

/**
 * An opaque, ref-counted compiled regular expression.
 *
 * Obtain via regex_compile(); release via regex_free().
 * Safe for concurrent use by multiple threads once compiled.
 */
typedef struct regex_s regex_t;

/**
 * A per-thread execution context holding PCRE2 match data.
 *
 * Avoids repeated allocation of the PCRE2 match-data block on the hot path.
 * Create one per thread with regex_ctx_create(); destroy with regex_ctx_free().
 * Must NOT be shared across threads.
 */
typedef struct regex_ctx_s regex_ctx_t;

/**
 * A single captured substring span within a subject string.
 *
 * Both offsets are byte positions, not character positions, unless
 * REGEX_FLAG_UTF is set, in which case they are still byte positions but
 * will align to UTF-8 character boundaries.
 */
typedef struct {
    size_t start; /**< Byte offset of the first character of the match.   */
    size_t end;   /**< Byte offset one past the last character.            */
} regex_span_t;

/**
 * The result of a single match operation.
 *
 * group[0] is always the whole match span. group[1..count-1] are capturing
 * groups in left-to-right order. A group that did not participate in the
 * match has start == end == PCRE2_UNSET.
 */
typedef struct {
    regex_span_t group[REGEX_MAX_GROUPS]; /**< Per-group spans.              */
    uint32_t count;                       /**< Number of groups (incl. g0).  */
} regex_match_t;

/**
 * Iterator for finding all non-overlapping matches of a pattern.
 *
 * Obtain via regex_iter_init(); advance with regex_iter_next();
 * release with regex_iter_free().  Must not be shared across threads.
 */
typedef struct regex_iter_s regex_iter_t;

/* ---------------------------------------------------------------------------
 * Compilation
 * ------------------------------------------------------------------------- */

/**
 * Compiles a NUL-terminated pattern string into a reusable regex_t.
 *
 * @param pattern  NUL-terminated UTF-8 pattern string.  Must not be NULL.
 * @param flags    Combination of REGEX_FLAG_* constants, or REGEX_FLAG_NONE.
 * @param out      On success, written with a pointer to the new regex_t.
 *                 On failure, written with NULL.  Must not be NULL.
 * @param errbuf   Optional buffer to receive a human-readable error message.
 *                 May be NULL if not needed.
 * @param errbuf_len  Capacity of errbuf in bytes.  Ignored if errbuf is NULL.
 * @return REGEX_OK on success, REGEX_ERROR on pattern error,
 *         REGEX_ERROR_NOMEM on allocation failure,
 *         REGEX_ERROR_ARGS if pattern or out is NULL.
 */
regex_status_t regex_compile(const char* pattern, regex_flags_t flags, regex_t** out, char* errbuf, size_t errbuf_len);

/**
 * Increments the reference count of a compiled regex.
 *
 * @param re  A non-NULL regex_t pointer previously obtained from regex_compile.
 * @return re, for convenient chaining.
 */
regex_t* regex_retain(regex_t* re);

/**
 * Decrements the reference count and frees the regex if it reaches zero.
 *
 * @param re  Pointer to a compiled regex_t, or NULL (no-op).
 */
void regex_free(regex_t* re);

/* ---------------------------------------------------------------------------
 * Execution context (per-thread)
 * ------------------------------------------------------------------------- */

/**
 * Creates a per-thread execution context for use with regex_exec.
 *
 * Allocating a context pre-allocates the PCRE2 match data block, avoiding
 * per-call heap traffic on the hot path.  A single context may be reused
 * across calls to regex_exec with different patterns, provided the subject
 * string group count does not exceed REGEX_MAX_GROUPS.
 *
 * @param out  Written with a pointer to the new context on success.
 *             Must not be NULL.
 * @return REGEX_OK or REGEX_ERROR_NOMEM.
 */
regex_status_t regex_ctx_create(regex_ctx_t** out);

/**
 * Destroys an execution context created by regex_ctx_create.
 *
 * @param ctx  Context to destroy, or NULL (no-op).
 */
void regex_ctx_free(regex_ctx_t* ctx);

/* ---------------------------------------------------------------------------
 * Matching
 * ------------------------------------------------------------------------- */

/**
 * Executes the compiled pattern against a byte subject at a given offset.
 *
 * @param re       Compiled pattern.  Must not be NULL.
 * @param ctx      Per-thread context.  Must not be NULL.
 * @param subject  Subject byte string.  Need not be NUL-terminated.
 * @param len      Byte length of the subject.
 * @param offset   Byte offset within subject at which to start matching.
 * @param match    Receives match spans on success.  Must not be NULL.
 * @return REGEX_OK on match, REGEX_NO_MATCH if the pattern did not match,
 *         REGEX_ERROR on a PCRE2 internal error,
 *         REGEX_ERROR_ARGS if any pointer argument is NULL or offset > len.
 */
regex_status_t regex_exec(const regex_t* re, regex_ctx_t* ctx, const char* subject, size_t len, size_t offset,
                          regex_match_t* match);

/**
 * Convenience wrapper: match a NUL-terminated string from its beginning.
 *
 * Equivalent to regex_exec(re, ctx, subject, strlen(subject), 0, match).
 *
 * @param re       Compiled pattern.  Must not be NULL.
 * @param ctx      Per-thread context.  Must not be NULL.
 * @param subject  NUL-terminated subject string.  Must not be NULL.
 * @param match    Receives match spans on success.  Must not be NULL.
 * @return Same status codes as regex_exec.
 */
regex_status_t regex_match(const regex_t* re, regex_ctx_t* ctx, const char* subject, regex_match_t* match);

/**
 * Returns true if the pattern matches anywhere within the subject string.
 *
 * Convenience predicate; does not surface match spans.
 *
 * @param re       Compiled pattern.  Must not be NULL.
 * @param ctx      Per-thread context.  Must not be NULL.
 * @param subject  NUL-terminated subject string.  Must not be NULL.
 * @param len      Byte length of the subject.
 * @return true on match, false on no match or error.
 */
bool regex_is_match(const regex_t* re, regex_ctx_t* ctx, const char* subject, size_t len);

/* ---------------------------------------------------------------------------
 * Iterator: find all non-overlapping matches
 * ------------------------------------------------------------------------- */

/**
 * Initialises an iterator that yields successive non-overlapping matches.
 *
 * The iterator holds a reference to re (via regex_retain) and a pointer to
 * subject; the caller must ensure subject remains valid for the iterator's
 * lifetime.
 *
 * @param re       Compiled pattern.  Must not be NULL.
 * @param ctx      Per-thread context.  Must not be NULL.
 * @param subject  Subject byte string (need not be NUL-terminated).
 * @param len      Byte length of the subject.
 * @param out      Written with the new iterator on success.  Must not be NULL.
 * @return REGEX_OK or REGEX_ERROR_NOMEM.
 */
regex_status_t regex_iter_init(regex_t* re, regex_ctx_t* ctx, const char* subject, size_t len, regex_iter_t** out);

/**
 * Advances the iterator and writes the next match into match.
 *
 * @param iter   Iterator obtained from regex_iter_init.  Must not be NULL.
 * @param match  Receives the next match.  Must not be NULL.
 * @return REGEX_OK on a successful advance, REGEX_NO_MATCH when exhausted,
 *         REGEX_ERROR on a PCRE2 internal error.
 */
regex_status_t regex_iter_next(regex_iter_t* iter, regex_match_t* match);

/**
 * Frees the iterator and releases its reference to the compiled pattern.
 *
 * @param iter  Iterator to free, or NULL (no-op).
 */
void regex_iter_free(regex_iter_t* iter);

/* ---------------------------------------------------------------------------
 * Substitution
 * ------------------------------------------------------------------------- */

/**
 * Replaces the first match of re in subject with replacement.
 *
 * Replacement may contain $0..$9 or ${name} back-references.
 * The result is written into out_buf; out_len is updated with the used length
 * (excluding the NUL terminator).  If the buffer is too small the function
 * returns REGEX_ERROR and writes the required size (including NUL) into
 * out_len.
 *
 * @param re           Compiled pattern.  Must not be NULL.
 * @param ctx          Per-thread context.  Must not be NULL.
 * @param subject      Subject string (need not be NUL-terminated).
 * @param subject_len  Byte length of the subject.
 * @param replacement  NUL-terminated replacement string.  Must not be NULL.
 * @param out_buf      Buffer to receive the result.  Must not be NULL.
 * @param out_len      In: capacity of out_buf.  Out: bytes written (excl. NUL).
 * @return REGEX_OK on success, REGEX_NO_MATCH if no substitution occurred,
 *         REGEX_ERROR on failure (check out_len for required capacity),
 *         REGEX_ERROR_ARGS on invalid arguments.
 */
regex_status_t regex_sub(const regex_t* re, regex_ctx_t* ctx, const char* subject, size_t subject_len,
                         const char* replacement, char* out_buf, size_t* out_len);

/**
 * Replaces all non-overlapping matches of re in subject with replacement.
 *
 * Semantics identical to regex_sub except that every match is substituted.
 *
 * @param re           Compiled pattern.  Must not be NULL.
 * @param ctx          Per-thread context.  Must not be NULL.
 * @param subject      Subject string (need not be NUL-terminated).
 * @param subject_len  Byte length of the subject.
 * @param replacement  NUL-terminated replacement string.  Must not be NULL.
 * @param out_buf      Buffer to receive the result.  Must not be NULL.
 * @param out_len      In: capacity of out_buf.  Out: bytes written (excl. NUL).
 * @return REGEX_OK on success, REGEX_NO_MATCH if no substitution occurred,
 *         REGEX_ERROR on failure, REGEX_ERROR_ARGS on invalid arguments.
 */
regex_status_t regex_gsub(const regex_t* re, regex_ctx_t* ctx, const char* subject, size_t subject_len,
                          const char* replacement, char* out_buf, size_t* out_len);

/* ---------------------------------------------------------------------------
 * Introspection
 * ------------------------------------------------------------------------- */

/**
 * Returns the number of capturing groups in the compiled pattern (excl. g0).
 *
 * @param re  Compiled pattern.  Must not be NULL.
 * @return Number of capture groups, or 0 on error.
 */
uint32_t regex_group_count(const regex_t* re);

/**
 * Returns the original pattern string used to compile the regex.
 *
 * @param re  Compiled pattern.  Must not be NULL.
 * @return NUL-terminated pattern string.  Lifetime is that of re.
 */
const char* regex_pattern(const regex_t* re);

/**
 * Writes a human-readable description of a status code into buf.
 *
 * @param status   A regex_status_t value.
 * @param buf      Destination buffer.  Must not be NULL.
 * @param buf_len  Capacity of buf in bytes.
 */
void regex_strerror(regex_status_t status, char* buf, size_t buf_len);

/**
 * Compiles a pattern and aborts the program if compilation fails.
 * @param pattern  Pattern string to compile.
 * @param flags    Compilation flags.
 * @return Compiled regex_t on success; does not return on failure.
 */
static inline regex_t* regex_must_compile(const char* pattern, regex_flags_t flags) {
    char errbuf[256];
    regex_t* re = NULL;
    regex_status_t st = regex_compile(pattern, flags, &re, errbuf, sizeof(errbuf));
    if (st != REGEX_OK) {
        fprintf(stderr, "%s:%d: regex_compile(\"%s\") failed: %s\n", __FILE__, __LINE__, pattern, errbuf);
        exit(1);
    }
    return re;
}

/**
 * Creates an execution context; calls fail_at and returns NULL on error.
 */
static inline regex_ctx_t* regex_ctx_must_create(void) {
    regex_ctx_t* ctx = NULL;
    regex_status_t st = regex_ctx_create(&ctx);
    if (st != REGEX_OK) {
        fprintf(stderr, "%s:%d: regex_ctx_create failed\n", __FILE__, __LINE__);
        exit(1);
    }
    return ctx;
}

/**
 * Prints a regex match result to stdout.
 *
 * Prints the full match (group 0) followed by each numbered capture group.
 * Capture groups that were present in the pattern but did not participate in
 * the match (PCRE2_UNSET offsets) are silently skipped.
 *
 * @param subject The original subject string passed to the match function.
 * @param match   The populated match result to display. Must not be NULL.
 */
void regex_print_match(const char* subject, const regex_match_t* match);

/**
 * Allocates and returns a null-terminated copy of a capture group substring.
 *
 * Use this when the caller needs to own the extracted string beyond the
 * lifetime of the subject buffer. The returned pointer must be freed with
 * free().
 *
 * @param subject   The original subject string passed to the match function.
 * @param match     The populated match result. Must not be NULL.
 * @param group_num Capture group index; 0 is the full match, 1+ are subgroups.
 * @return A newly allocated, null-terminated string on success, or NULL if
 *         any argument is invalid, the group did not participate in the match,
 *         or memory allocation fails.
 * @note Caller is responsible for freeing the returned string.
 */
char* regex_group_dup(const char* subject, const regex_match_t* match, uint32_t group_num);

/**
 * Copies a capture group substring into a caller-supplied buffer.
 *
 * Prefer this over regex_group_dup() in hot paths or when the caller already
 * has a suitably-sized buffer, as it avoids a heap allocation.
 *
 * @param subject   The original subject string passed to the match function.
 * @param match     The populated match result. Must not be NULL.
 * @param group_num Capture group index; 0 is the full match, 1+ are subgroups.
 * @param buf       Destination buffer. Must not be NULL.
 * @param buf_len   Capacity of buf in bytes, including space for the null
 *                  terminator. Must be at least (group length + 1).
 * @return buf on success, or NULL if any argument is invalid, the group did
 *         not participate in the match, or buf is too small.
 */
char* regex_group_copy(const char* subject, const regex_match_t* match, uint32_t group_num, char* buf, size_t buf_len);

#ifdef __cplusplus
}
#endif
