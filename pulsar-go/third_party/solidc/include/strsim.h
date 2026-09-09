#ifndef STRSIM_H
#define STRSIM_H

/**
 * @file strsim.h
 * @brief String similarity algorithms: cosine similarity, Levenshtein distance,
 *        Damerau-Levenshtein distance, Jaro-Winkler similarity, and Jaccard
 *        similarity on character bigrams.
 *
 * All functions are thread-safe provided callers do not share mutable state
 * across threads.  The implementations operate on NUL-terminated C strings and
 * treat each byte as a distinct character token.  Strings containing embedded
 * NUL bytes are not supported.
 */

#include <stddef.h> /* for size_t */

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Cosine similarity
 * ------------------------------------------------------------------------- */

/**
 * Computes the cosine similarity between two strings using character-level
 * term-frequency vectors over the full byte range [0, 255].
 *
 * The similarity is defined as:
 *
 *   cos(a, b) = dot(tf_a, tf_b) / (||tf_a|| * ||tf_b||)
 *
 * where tf_x[c] is the frequency of byte value c in string x.
 *
 * @param a              First NUL-terminated string.  Must not be NULL.
 * @param b              Second NUL-terminated string.  Must not be NULL.
 * @param[out] out_similarity  On success, set to a value in [0.0, 1.0] where
 *             1.0 means identical character distributions and 0.0 means
 *             completely disjoint.  Undefined on failure.
 *
 * @return  0 on success.
 * @return -1 if any pointer argument is NULL.
 * @return -2 if either @p a or @p b is empty (cosine is undefined).
 *
 * @note Thread-safe.  No heap allocation is performed.
 */
int strsim_cosine(const char* a, const char* b, double* out_similarity);

/* -------------------------------------------------------------------------
 * Levenshtein (edit) distance
 * ------------------------------------------------------------------------- */

/**
 * Computes the Levenshtein edit distance between two strings.
 *
 * Edit distance is the minimum number of single-character insertions,
 * deletions, or substitutions required to transform @p a into @p b.
 *
 * Uses a space-optimised DP with a single allocation backing two rows of
 * length O(min(|a|, |b|)).
 *
 * @param a              First NUL-terminated string.  Must not be NULL.
 * @param b              Second NUL-terminated string.  Must not be NULL.
 * @param[out] out_distance  On success, set to the edit distance >= 0.
 *             Undefined on failure.
 *
 * @return  0 on success.
 * @return -1 if any pointer argument is NULL.
 * @return -2 if heap allocation failed (errno set to ENOMEM).
 *
 * @note Thread-safe.  Allocates O(min(|a|, |b|)) bytes on the heap.
 */
int strsim_levenshtein(const char* a, const char* b, size_t* out_distance);

/* -------------------------------------------------------------------------
 * Damerau-Levenshtein distance
 * ------------------------------------------------------------------------- */

/**
 * Computes the unrestricted Damerau-Levenshtein edit distance between two
 * strings.
 *
 * Extends Levenshtein by also counting adjacent transpositions as a single
 * edit operation, making it more accurate for typical typographical errors
 * (e.g. "teh" -> "the" = 1, not 2).
 *
 * The implementation uses the full O(|a| * |b|) DP matrix (OSA is avoided
 * to preserve the triangle inequality) with an additional last-seen row
 * array of size ALPHABET_SIZE for transposition detection.
 *
 * @param a              First NUL-terminated string.  Must not be NULL.
 * @param b              Second NUL-terminated string.  Must not be NULL.
 * @param[out] out_distance  On success, set to the edit distance >= 0.
 *             Undefined on failure.
 *
 * @return  0 on success.
 * @return -1 if any pointer argument is NULL.
 * @return -2 if heap allocation failed (errno set to ENOMEM).
 *
 * @note Thread-safe.  Allocates O(|a| * |b|) bytes on the heap.
 */
int strsim_damerau_levenshtein(const char* a, const char* b, size_t* out_distance);

/* -------------------------------------------------------------------------
 * Jaro-Winkler similarity
 * ------------------------------------------------------------------------- */

/**
 * Computes the Jaro-Winkler similarity between two strings.
 *
 * Jaro-Winkler extends the Jaro similarity by applying a prefix bonus: strings
 * that share a common prefix (up to 4 characters) receive a boosted score.
 * It is particularly well-suited to short strings such as personal names.
 *
 * The Jaro similarity is:
 *
 *   jaro(a, b) = (m/|a| + m/|b| + (m - t/2) / m) / 3
 *
 * where m is the number of matching characters (within a match window of
 * floor(max(|a|,|b|)/2) - 1) and t is the number of transpositions.
 *
 * The Jaro-Winkler score is:
 *
 *   jaro_winkler(a, b) = jaro + p * l * (1 - jaro)
 *
 * where l is the length of the common prefix (capped at 4) and p = 0.1
 * is the standard scaling factor.
 *
 * @param a              First NUL-terminated string.  Must not be NULL.
 * @param b              Second NUL-terminated string.  Must not be NULL.
 * @param[out] out_similarity  On success, set to a value in [0.0, 1.0].
 *             Undefined on failure.
 *
 * @return  0 on success.
 * @return -1 if any pointer argument is NULL.
 * @return -2 if heap allocation for the match bitmap failed (errno set to
 *         ENOMEM).
 *
 * @note Thread-safe.
 */
int strsim_jaro_winkler(const char* a, const char* b, double* out_similarity);

/* -------------------------------------------------------------------------
 * Jaccard similarity on character bigrams
 * ------------------------------------------------------------------------- */

/**
 * Computes the Jaccard similarity between two strings based on the multiset
 * of their character bigrams (overlapping pairs of adjacent bytes).
 *
 * Jaccard similarity is defined as:
 *
 *   jaccard(a, b) = |bigrams(a) ∩ bigrams(b)| / |bigrams(a) ∪ bigrams(b)|
 *
 * The intersection and union sizes are computed over the multisets, so a
 * bigram appearing k times in both strings contributes min(k_a, k_b) to the
 * intersection and max(k_a, k_b) to the union.
 *
 * Strings of length < 2 have no bigrams; the function returns 1.0 if both
 * are empty and 0.0 if exactly one is (or has fewer than 2 characters).
 *
 * @param a              First NUL-terminated string.  Must not be NULL.
 * @param b              Second NUL-terminated string.  Must not be NULL.
 * @param[out] out_similarity  On success, set to a value in [0.0, 1.0].
 *             Undefined on failure.
 *
 * @return  0 on success.
 * @return -1 if any pointer argument is NULL.
 * @return -2 if heap allocation for bigram frequency tables failed
 *         (errno set to ENOMEM).
 *
 * @note Thread-safe.
 */
int strsim_jaccard_bigram(const char* a, const char* b, double* out_similarity);

#ifdef __cplusplus
}
#endif

#endif /* STRSIM_H */
