#include "../include/regex.h"

#include <assert.h>   /* for assert */
#include <inttypes.h> /* PRIu32 */
#include <stdatomic.h>/* for atomic_fetch_add, atomic_fetch_sub */
#include <stdio.h>    /* for snprintf */
#include <stdlib.h>   /* for malloc, free */
#include <string.h>   /* for strlen */

/**
 * Internal representation of a compiled regular expression.
 * The public API exposes only the opaque regex_t alias.
 */
struct regex_s {
    pcre2_code* code;     /**< PCRE2 compiled code object.             */
    char* pattern;        /**< Copy of the original pattern string.    */
    uint32_t group_count; /**< Number of capture groups (excl. g0).    */
    atomic_int refcount;  /**< Reference count; freed when it hits 0.  */
};

/**
 * Per-thread execution context.  Wraps a PCRE2 match-data block that is
 * pre-allocated to REGEX_MAX_GROUPS pairs so we avoid per-call allocation.
 */
struct regex_ctx_s {
    pcre2_match_data* match_data; /**< Pre-allocated PCRE2 match-data block. */
};

/**
 * State for the non-overlapping-match iterator.
 */
struct regex_iter_s {
    regex_t* re;         /**< Retained reference to the compiled pattern.   */
    regex_ctx_t* ctx;    /**< Borrowed reference; caller must keep alive.   */
    const char* subject; /**< Borrowed pointer; caller must keep alive.     */
    size_t len;          /**< Byte length of subject.                       */
    size_t offset;       /**< Current byte offset into subject.             */
};

/* ---------------------------------------------------------------------------
 * Internal helpers
 * ------------------------------------------------------------------------- */

/** Copies the PCRE2 error message for @p errcode into @p buf, falling back to "PCRE2 error N (no message available)"
 * when the lookup fails. @param errcode A PCRE2 error code (negative integer). @param buf Destination buffer. @param
 * buf_len Capacity of buf. */
static void pcre2_err_message(int errcode, char* buf, size_t buf_len) {
    PCRE2_UCHAR8 tmp[256];
    if (pcre2_get_error_message(errcode, tmp, sizeof(tmp)) < 0) {
        snprintf(buf, buf_len, "PCRE2 error %d (no message available)", errcode);
    } else {
        snprintf(buf, buf_len, "%s", (const char*)tmp);
    }
}

/** Populates @p match from the PCRE2 ovector: copies spans for groups 0..re->group_count (capped at REGEX_MAX_GROUPS) —
 * non-participating groups carry PCRE2_UNSET offsets verbatim — and zeroes all trailing slots. @param re Compiled regex
 * whose group count is authoritative. @param md PCRE2 match-data block returned from pcre2_match. @param rc The
 * positive return value from pcre2_match (used only implicitly via the ovector). @param match Output structure to
 * populate. */
static void fill_match(const regex_t* re, pcre2_match_data* md, int rc, regex_match_t* match) {
    const PCRE2_SIZE* ov = pcre2_get_ovector_pointer(md);

    /* The match count from pcre2_match is the number of *filled* pairs;
     * groups beyond that still exist but were not captured this run.       */
    uint32_t total = re->group_count + 1; /* include g0 */
    if (total > REGEX_MAX_GROUPS) {
        total = REGEX_MAX_GROUPS;
    }
    match->count = total;

    for (uint32_t i = 0; i < total; i++) {
        match->group[i].start = ov[2 * i];
        match->group[i].end = ov[2 * i + 1];
    }

    /* Zero out any trailing slots not covered by this match. */
    for (uint32_t i = total; i < REGEX_MAX_GROUPS; i++) {
        match->group[i].start = 0;
        match->group[i].end = 0;
    }

    (void)rc; /* rc is used implicitly via the ovector; suppress unused warning */
}

/** @brief Compiles a NUL-terminated pattern via PCRE2 (with JIT when available), rejecting patterns whose capture
 * groups exceed REGEX_MAX_GROUPS. The pattern string is duplicated for introspection and the wrapper starts with
 * refcount 1. @param pattern NUL-terminated UTF-8 pattern string; must not be NULL. @param flags Combination of
 * REGEX_FLAG_* constants, or REGEX_FLAG_NONE. @param out On success written with the new regex_t, on failure with NULL.
 * @param errbuf Optional buffer receiving a human-readable error message (offset included for pattern errors). @param
 * errbuf_len Capacity of errbuf in bytes; ignored if errbuf is NULL. @return REGEX_OK on success, REGEX_ERROR on
 * pattern error, REGEX_ERROR_LIMIT on too many groups, REGEX_ERROR_NOMEM on allocation failure, REGEX_ERROR_ARGS if
 * pattern or out is NULL. */
regex_status_t regex_compile(const char* pattern, regex_flags_t flags, regex_t** out, char* errbuf, size_t errbuf_len) {
    if (pattern == NULL || out == NULL) {
        return REGEX_ERROR_ARGS;
    }
    *out = NULL;

    /* Compile via PCRE2. */
    int errcode = 0;
    PCRE2_SIZE erroffset = 0;

    pcre2_code* code = pcre2_compile((PCRE2_SPTR8)pattern, PCRE2_ZERO_TERMINATED, (uint32_t)flags, &errcode, &erroffset,
                                     NULL /* use default compile context */);

    if (code == NULL) {
        if (errbuf != NULL && errbuf_len > 0) {
            PCRE2_UCHAR8 tmp[256];
            pcre2_get_error_message(errcode, tmp, sizeof(tmp));
            snprintf(errbuf, errbuf_len, "pattern error at offset %zu: %s", (size_t)erroffset, (const char*)tmp);
        }
        return REGEX_ERROR;
    }

    /* Study / JIT-compile for speed if JIT is available. */
    pcre2_jit_compile(code, PCRE2_JIT_COMPLETE);

    /* Query capture group count before committing. */
    uint32_t group_count = 0;
    pcre2_pattern_info(code, PCRE2_INFO_CAPTURECOUNT, &group_count);

    if (group_count + 1 > REGEX_MAX_GROUPS) {
        /* The total slots needed (groups + g0) exceed our cap. */
        pcre2_code_free(code);
        if (errbuf != NULL && errbuf_len > 0) {
            snprintf(errbuf, errbuf_len, "pattern has %u capture groups; limit is %d", group_count,
                     REGEX_MAX_GROUPS - 1);
        }
        return REGEX_ERROR_LIMIT;
    }

    /* Duplicate the pattern string for later introspection. */
    char* pat_dup = strdup(pattern);
    if (pat_dup == NULL) {
        pcre2_code_free(code);
        return REGEX_ERROR_NOMEM;
    }

    /* Allocate and initialise the regex_t wrapper. */
    regex_t* re = malloc(sizeof(*re));
    if (re == NULL) {
        free(pat_dup);
        pcre2_code_free(code);
        return REGEX_ERROR_NOMEM;
    }

    *re = (regex_t){
        .code = code,
        .pattern = pat_dup,
        .group_count = group_count,
        /* refcount initialised below via atomic store */
    };
    atomic_store(&re->refcount, 1);

    *out = re;
    return REGEX_OK;
}

/** @brief Atomically increments the reference count of a compiled regex. @param re A non-NULL regex_t pointer
 * previously obtained from regex_compile; NULL is tolerated. @return re, for convenient chaining. */
regex_t* regex_retain(regex_t* re) {
    if (re != NULL) {
        atomic_fetch_add(&re->refcount, 1);
    }
    return re;
}

/** @brief Atomically decrements the reference count and releases the PCRE2 code, pattern copy, and wrapper when it
 * reaches zero. @param re Pointer to a compiled regex_t, or NULL (no-op). */
void regex_free(regex_t* re) {
    if (re == NULL) {
        return;
    }

    if (atomic_fetch_sub(&re->refcount, 1) == 1) {
        /* Last reference: tear down. */
        pcre2_code_free(re->code);
        free(re->pattern);
        free(re);
    }
}

/* ---------------------------------------------------------------------------
 * Execution context
 * ------------------------------------------------------------------------- */

/** @brief Allocates a per-thread context holding a PCRE2 match-data block pre-sized to REGEX_MAX_GROUPS pairs, so
 * hot-path matching never allocates. @param out Written with the new context on success, NULL on failure; must not be
 * NULL. @return REGEX_OK or REGEX_ERROR_NOMEM (REGEX_ERROR_ARGS if out is NULL). */
regex_status_t regex_ctx_create(regex_ctx_t** out) {
    if (out == NULL) {
        return REGEX_ERROR_ARGS;
    }
    *out = NULL;

    regex_ctx_t* ctx = malloc(sizeof(*ctx));
    if (ctx == NULL) {
        return REGEX_ERROR_NOMEM;
    }

    /* Allocate the match-data block for up to REGEX_MAX_GROUPS pairs.
     * We use the "from pattern" variant with a NULL code pointer so we can
     * pass an explicit pair count.  That variant is pcre2_match_data_create,
     * which takes an ovector pair count directly. */
    ctx->match_data = pcre2_match_data_create(REGEX_MAX_GROUPS, NULL);
    if (ctx->match_data == NULL) {
        free(ctx);
        return REGEX_ERROR_NOMEM;
    }

    *out = ctx;
    return REGEX_OK;
}

/** @brief Releases the context's match-data block and the context itself. @param ctx Context to destroy, or NULL
 * (no-op). */
void regex_ctx_free(regex_ctx_t* ctx) {
    if (ctx == NULL) {
        return;
    }
    pcre2_match_data_free(ctx->match_data);
    free(ctx);
}

/* ---------------------------------------------------------------------------
 * Matching
 * ------------------------------------------------------------------------- */

/** @brief Runs the compiled pattern against @p subject starting at @p offset using the context's pre-allocated match
 * data, then copies the spans into @p match via fill_match(). @param re Compiled pattern; must not be NULL. @param ctx
 * Per-thread context providing the match-data block; must not be NULL. @param subject Subject byte string; need not be
 * NUL-terminated. @param len Byte length of the subject. @param offset Byte offset within subject at which to start
 * matching; must be <= len. @param match Receives match spans on success. @return REGEX_OK on match, REGEX_NO_MATCH if
 * no match, REGEX_ERROR on a PCRE2 internal error, REGEX_ERROR_ARGS on invalid arguments. */
regex_status_t regex_exec(const regex_t* re, regex_ctx_t* ctx, const char* subject, size_t len, size_t offset,
                          regex_match_t* match) {
    if (re == NULL || ctx == NULL || subject == NULL || match == NULL) {
        return REGEX_ERROR_ARGS;
    }
    if (offset > len) {
        return REGEX_ERROR_ARGS;
    }

    int rc = pcre2_match(re->code, (PCRE2_SPTR8)subject, (PCRE2_SIZE)len, (PCRE2_SIZE)offset, 0 /* no extra flags */,
                         ctx->match_data, NULL /* use default match context */);

    if (rc == PCRE2_ERROR_NOMATCH) {
        return REGEX_NO_MATCH;
    }
    if (rc < 0) {
        return REGEX_ERROR;
    }

    fill_match(re, ctx->match_data, rc, match);
    return REGEX_OK;
}

/** @brief Convenience wrapper: regex_exec() over strlen(subject) starting at offset 0. @param re Compiled pattern; must
 * not be NULL. @param ctx Per-thread context; must not be NULL. @param subject NUL-terminated subject string; must not
 * be NULL. @param match Receives match spans on success. @return Same status codes as regex_exec(). */
regex_status_t regex_match(const regex_t* re, regex_ctx_t* ctx, const char* subject, regex_match_t* match) {
    if (subject == NULL) {
        return REGEX_ERROR_ARGS;
    }
    return regex_exec(re, ctx, subject, strlen(subject), 0, match);
}

/** @brief Predicate form of regex_exec(): true when the pattern matches anywhere in the subject; match spans are not
 * produced. @param re Compiled pattern; must not be NULL. @param ctx Per-thread context; must not be NULL. @param
 * subject Subject byte string; must not be NULL. @param len Byte length of the subject. @return true on match, false on
 * no match, invalid arguments, or PCRE2 error. */
bool regex_is_match(const regex_t* re, regex_ctx_t* ctx, const char* subject, size_t len) {
    if (re == NULL || ctx == NULL || subject == NULL) {
        return false;
    }

    int rc = pcre2_match(re->code, (PCRE2_SPTR8)subject, (PCRE2_SIZE)len, 0, 0, ctx->match_data, NULL);

    return rc > 0;
}

/* ---------------------------------------------------------------------------
 * Iterator
 * ------------------------------------------------------------------------- */

/** @brief Creates an iterator for successive non-overlapping matches. It retains @p re and borrows @p ctx and @p
 * subject — both must outlive the iterator. @param re Compiled pattern; must not be NULL. @param ctx Per-thread
 * context; must not be NULL. @param subject Subject byte string (need not be NUL-terminated); must remain valid. @param
 * len Byte length of the subject. @param out Written with the new iterator on success, NULL on failure; must not be
 * NULL. @return REGEX_OK or REGEX_ERROR_NOMEM (REGEX_ERROR_ARGS if any pointer argument is NULL). */
regex_status_t regex_iter_init(regex_t* re, regex_ctx_t* ctx, const char* subject, size_t len, regex_iter_t** out) {
    if (re == NULL || ctx == NULL || subject == NULL || out == NULL) {
        return REGEX_ERROR_ARGS;
    }
    *out = NULL;

    regex_iter_t* iter = malloc(sizeof(*iter));
    if (iter == NULL) {
        return REGEX_ERROR_NOMEM;
    }

    *iter = (regex_iter_t){
        .re = regex_retain(re),
        .ctx = ctx,
        .subject = subject,
        .len = len,
        .offset = 0,
    };

    *out = iter;
    return REGEX_OK;
}

/** @brief Advances the iterator: matches from the current offset, fills @p match, and moves the offset past the match —
 * advancing one extra byte on zero-length matches to avoid an infinite loop (as Perl/Python/Go do). @param iter
 * Iterator obtained from regex_iter_init; must not be NULL. @param match Receives the next match; must not be NULL.
 * @return REGEX_OK on a successful advance, REGEX_NO_MATCH when exhausted, REGEX_ERROR on a PCRE2 internal error,
 * REGEX_ERROR_ARGS on NULL arguments. */
regex_status_t regex_iter_next(regex_iter_t* iter, regex_match_t* match) {
    if (iter == NULL || match == NULL) {
        return REGEX_ERROR_ARGS;
    }
    if (iter->offset > iter->len) {
        return REGEX_NO_MATCH;
    }

    int rc = pcre2_match(iter->re->code, (PCRE2_SPTR8)iter->subject, (PCRE2_SIZE)iter->len, (PCRE2_SIZE)iter->offset, 0,
                         iter->ctx->match_data, NULL);

    if (rc == PCRE2_ERROR_NOMATCH) {
        return REGEX_NO_MATCH;
    }
    if (rc < 0) {
        return REGEX_ERROR;
    }

    fill_match(iter->re, iter->ctx->match_data, rc, match);

    /* Advance the offset past this match to avoid re-matching.
     * If the match is zero-length we must advance by at least one byte to
     * prevent an infinite loop.  This mirrors the behaviour of most regex
     * engines (Perl, Python, Go) for zero-width matches. */
    size_t end = match->group[0].end;
    if (end == iter->offset) {
        iter->offset = end + 1;
    } else {
        iter->offset = end;
    }

    return REGEX_OK;
}

/** @brief Frees the iterator and releases its reference to the compiled pattern. Borrowed context and subject are left
 * untouched. @param iter Iterator to free, or NULL (no-op). */
void regex_iter_free(regex_iter_t* iter) {
    if (iter == NULL) {
        return;
    }
    regex_free(iter->re);
    free(iter);
}

/* ---------------------------------------------------------------------------
 * Substitution (shared implementation)
 * ------------------------------------------------------------------------- */

/** Shared body for regex_sub()/regex_gsub(), differing only in @p pcre2_flags. Runs pcre2_substitute with
 * SUBSTITUTE_EXTENDED and SUBSTITUTE_OVERFLOW_LENGTH so an undersized out_buf yields REGEX_ERROR with *out_len holding
 * the required size (including NUL) instead of a bare failure. @param re Compiled pattern; must not be NULL. @param ctx
 * Per-thread context providing match data; must not be NULL. @param subject Subject byte string; must not be NULL.
 * @param subject_len Byte length of the subject. @param replacement NUL-terminated replacement with $0..$9 / ${name}
 * references; must not be NULL. @param out_buf Buffer receiving the result; must not be NULL. @param out_len In:
 * capacity of out_buf. Out: bytes written (excl. NUL), or required size on overflow. @param pcre2_flags Extra PCRE2
 * substitute flags (0 for first-match, PCRE2_SUBSTITUTE_GLOBAL for all). @return REGEX_OK, REGEX_NO_MATCH when nothing
 * matched, REGEX_ERROR on overflow or other errors, REGEX_ERROR_ARGS on NULL arguments. */
static regex_status_t sub_impl(const regex_t* re, regex_ctx_t* ctx, const char* subject, size_t subject_len,
                               const char* replacement, char* out_buf, size_t* out_len, uint32_t pcre2_flags) {
    if (re == NULL || ctx == NULL || subject == NULL || replacement == NULL || out_buf == NULL || out_len == NULL) {
        return REGEX_ERROR_ARGS;
    }

    PCRE2_SIZE result_len = (PCRE2_SIZE)*out_len;

    /*
     * FIX: PCRE2_SUBSTITUTE_OVERFLOW_LENGTH was missing, so the documented
     * "check out_len for required capacity" contract never worked — pcre2
     * bailed out with NOMEMORY without reporting how big the buffer must
     * be.  With the flag set, an undersized buffer returns
     * PCRE2_ERROR_NOMEMORY and result_len holds the required size
     * (including NUL), which we forward via out_len.
     */
    int rc = pcre2_substitute(re->code, (PCRE2_SPTR8)subject, (PCRE2_SIZE)subject_len, 0 /* start offset */,
                              pcre2_flags | PCRE2_SUBSTITUTE_EXTENDED | PCRE2_SUBSTITUTE_OVERFLOW_LENGTH,
                              ctx->match_data, NULL /* match context */, (PCRE2_SPTR8)replacement,
                              PCRE2_ZERO_TERMINATED, (PCRE2_UCHAR8*)out_buf, &result_len);

    if (rc == PCRE2_ERROR_NOMATCH || rc == 0) {
        return REGEX_NO_MATCH;
    }
    if (rc == PCRE2_ERROR_NOMEMORY) {
        /* result_len now holds the required size including NUL.
         * Guard against a bogus zero from the engine so callers can
         * always distinguish "no info" from "need 0 bytes". */
        if (result_len == 0) {
            result_len = *out_len + 1;
        }
        *out_len = (size_t)result_len;
        return REGEX_ERROR;
    }
    if (rc < 0) {
        return REGEX_ERROR;
    }

    /* result_len is the number of code units written, excluding NUL. */
    *out_len = (size_t)result_len;
    return REGEX_OK;
}

/** @brief Replaces the first match of re in subject with replacement (which may contain $0..$9 / ${name}
 * back-references), writing the result to out_buf. If the buffer is too small, REGEX_ERROR is returned with *out_len
 * set to the required size including NUL. @param re Compiled pattern; must not be NULL. @param ctx Per-thread context;
 * must not be NULL. @param subject Subject string (need not be NUL-terminated). @param subject_len Byte length of the
 * subject. @param replacement NUL-terminated replacement string; must not be NULL. @param out_buf Buffer to receive the
 * result; must not be NULL. @param out_len In: capacity of out_buf. Out: bytes written (excl. NUL), or required
 * capacity on overflow. @return REGEX_OK on success, REGEX_NO_MATCH if no substitution occurred, REGEX_ERROR on failure
 * (check out_len for required capacity), REGEX_ERROR_ARGS on invalid arguments. */
regex_status_t regex_sub(const regex_t* re, regex_ctx_t* ctx, const char* subject, size_t subject_len,
                         const char* replacement, char* out_buf, size_t* out_len) {
    return sub_impl(re, ctx, subject, subject_len, replacement, out_buf, out_len, 0 /* replace first match only */);
}

/** @brief Replaces all non-overlapping matches of re in subject with replacement. Semantics identical to regex_sub()
 * except every match is substituted (PCRE2_SUBSTITUTE_GLOBAL). @param re Compiled pattern; must not be NULL. @param ctx
 * Per-thread context; must not be NULL. @param subject Subject string (need not be NUL-terminated). @param subject_len
 * Byte length of the subject. @param replacement NUL-terminated replacement string; must not be NULL. @param out_buf
 * Buffer to receive the result; must not be NULL. @param out_len In: capacity of out_buf. Out: bytes written (excl.
 * NUL), or required capacity on overflow. @return REGEX_OK on success, REGEX_NO_MATCH if no substitution occurred,
 * REGEX_ERROR on failure, REGEX_ERROR_ARGS on invalid arguments. */
regex_status_t regex_gsub(const regex_t* re, regex_ctx_t* ctx, const char* subject, size_t subject_len,
                          const char* replacement, char* out_buf, size_t* out_len) {
    return sub_impl(re, ctx, subject, subject_len, replacement, out_buf, out_len, PCRE2_SUBSTITUTE_GLOBAL);
}

/* ---------------------------------------------------------------------------
 * Introspection
 * ------------------------------------------------------------------------- */

/** @brief Returns the number of capturing groups in the compiled pattern, excluding group 0. @param re Compiled
 * pattern; NULL yields 0. @return Capture group count, or 0 on error. */
uint32_t regex_group_count(const regex_t* re) {
    if (re == NULL) {
        return 0;
    }
    return re->group_count;
}

/** @brief Returns the original pattern string recorded at compile time; its lifetime is that of re. @param re Compiled
 * pattern. @return NUL-terminated pattern string, or "" if re is NULL. */
const char* regex_pattern(const regex_t* re) {
    if (re == NULL) {
        return "";
    }
    return re->pattern;
}

/** @brief Writes a human-readable description of @p status into buf (truncated to fit, always NUL-terminated). Unknown
 * codes map to "unknown status code". @param status A regex_status_t value. @param buf Destination buffer; must not be
 * NULL (silently ignored with buf_len == 0). @param buf_len Capacity of buf in bytes. */
void regex_strerror(regex_status_t status, char* buf, size_t buf_len) {
    if (buf == NULL || buf_len == 0) {
        return;
    }
    const char* msg;
    switch (status) {
        case REGEX_OK:
            msg = "success";
            break;
        case REGEX_NO_MATCH:
            msg = "no match";
            break;
        case REGEX_ERROR:
            msg = "general error";
            break;
        case REGEX_ERROR_NOMEM:
            msg = "memory allocation failed";
            break;
        case REGEX_ERROR_ARGS:
            msg = "invalid arguments";
            break;
        case REGEX_ERROR_LIMIT:
            msg = "too many capture groups";
            break;
        default:
            msg = "unknown status code";
            break;
    }
    snprintf(buf, buf_len, "%s", msg);
}

// ============ HELPERS FROM EXTRACTING MATCH GROUPS ============

/** @brief Prints the full match (group 0) and each participating capture group of @p match to stdout; groups with
 * PCRE2_UNSET offsets are skipped, and a zero count prints "No match". @param subject The original subject string
 * passed to the match function. @param match The populated match result to display; NULL arguments print an error to
 * stderr. */
void regex_print_match(const char* subject, const regex_match_t* match) {
    if (!subject || !match) {
        fprintf(stderr, "regex_print_match: NULL subject or match\n");
        return;
    }

    if (match->count == 0) {
        printf("No match\n");
        return;
    }

    printf("Full match: '%.*s'\n", (int)(match->group[0].end - match->group[0].start), subject + match->group[0].start);

    for (uint32_t i = 1; i < match->count; i++) {
        size_t start = match->group[i].start;
        size_t end = match->group[i].end;

        /* Groups in the pattern that did not participate have PCRE2_UNSET offsets. */
        if (start == PCRE2_UNSET || end == PCRE2_UNSET) {
            continue;
        }

        printf("Group %" PRIu32 ": '%.*s'\n", i, (int)(end - start), subject + start);
    }
}

/** @brief Allocates a NUL-terminated heap copy of capture group @p group_num from the subject; groups that did not
 * participate (PCRE2_UNSET offsets) yield NULL. @param subject The original subject string passed to the match
 * function. @param match The populated match result; must not be NULL. @param group_num Group index: 0 is the full
 * match, 1+ are subgroups. @return Newly allocated string the caller must free(), or NULL on invalid arguments, unset
 * group, or allocation failure. */
char* regex_group_dup(const char* subject, const regex_match_t* match, uint32_t group_num) {
    if (!subject || !match || group_num >= match->count) {
        return NULL;
    }

    size_t start = match->group[group_num].start;
    size_t end = match->group[group_num].end;

    /* A group present in the pattern but not reached during matching carries
     * PCRE2_UNSET (~(size_t)0) in both offsets. */
    if (start == PCRE2_UNSET || end == PCRE2_UNSET) {
        return NULL;
    }

    size_t len = end - start;
    char* result = malloc(len + 1);
    if (!result) {
        return NULL;
    }

    /* Length is exact; memcpy is correct and avoids strncpy's padding overhead. */
    memcpy(result, subject + start, len);
    result[len] = '\0';
    return result;
}

/** @brief Copies capture group @p group_num into a caller-supplied buffer (allocation-free alternative to
 * regex_group_dup); unset groups yield NULL. @param subject The original subject string passed to the match function.
 * @param match The populated match result; must not be NULL. @param group_num Group index: 0 is the full match, 1+ are
 * subgroups. @param buf Destination buffer; must not be NULL. @param buf_len Capacity of buf including the NUL
 * terminator; must exceed the group length. @return buf on success, or NULL on invalid arguments, unset group, or
 * insufficient capacity. */
char* regex_group_copy(const char* subject, const regex_match_t* match, uint32_t group_num, char* buf, size_t buf_len) {
    if (!subject || !match || !buf || buf_len == 0 || group_num >= match->count) {
        return NULL;
    }

    size_t start = match->group[group_num].start;
    size_t end = match->group[group_num].end;

    if (start == PCRE2_UNSET || end == PCRE2_UNSET) {
        return NULL;
    }

    size_t len = end - start;

    /* buf_len must accommodate the text and its null terminator. */
    if (len >= buf_len) {
        return NULL;
    }

    memcpy(buf, subject + start, len);
    buf[len] = '\0';
    return buf;
}
