/**
 * @file stdstreams.h
 * @brief High-performance standard stream handling utilities with Small String Optimization (SSO).
 *
 * Two-layer API:
 *   Layer 1 — type-specialized fast paths  (string_stream_copy_fast, etc.)
 *   Layer 2 — generic fallback             (io_copy, io_copy_n, read_until)
 *
 * Error contract (unified, POSIX-style):
 *   > 0  → bytes read / written
 *     0  → EOF
 *    -1  → error
 */

#ifndef STDSTREAMS_H
#define STDSTREAMS_H

#include "platform.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -----------------------------------------------------------------------
 * Compiler Portability, Attributes & Branch Hints
 * --------------------------------------------------------------------- */

#if defined(__GNUC__) || defined(__clang__)
    #define STREAM_LIKELY(x)   __builtin_expect(!!(x), 1)
    #define STREAM_UNLIKELY(x) __builtin_expect(!!(x), 0)
    #define STREAM_INLINE      inline __attribute__((always_inline))
    #define STREAM_RESTRICT    __restrict__
#else
    #define STREAM_LIKELY(x)   (x)
    #define STREAM_UNLIKELY(x) (x)
    #define STREAM_INLINE      inline
    #define STREAM_RESTRICT
#endif

#ifndef NDEBUG
    #include <assert.h>
    #define STREAM_ASSERT(x) assert(x)
#else
    #define STREAM_ASSERT(x) ((void)0)
#endif

/** Inline buffer capacity for Small String Optimization (SSO). */
#define STRING_STREAM_SSO_CAP 128

/* -----------------------------------------------------------------------
 * Terminal Helpers
 * --------------------------------------------------------------------- */

/**
 * @brief Read a line from stdin, optionally printing a prompt first.
 *
 * @param prompt     Optional prompt string (can be NULL).
 * @param buffer     Destination buffer.
 * @param buffer_len Total size of the buffer.
 * @return true on success, false on EOF / error.
 */
bool readline(const char* prompt, char* buffer, size_t buffer_len);

/**
 * @brief Read a password from the terminal with echo disabled.
 *
 * @param prompt     Optional prompt string (can be NULL).
 * @param buffer     Destination buffer.
 * @param buffer_len Total size of the buffer.
 * @return The number of characters stored in buffer, or -1 on error.
 */
int getpassword(const char* prompt, char* buffer, size_t buffer_len);

/**
 * @brief Opaque handle to a stream instance.
 *
 * A @c stream_t may wrap either a `FILE*`-backed stream (see
 * create_file_stream()) or an in-memory growable string buffer with SSO
 * (see create_string_stream()). Callers must not access the underlying
 * structure directly; use the accessor and mutator functions declared in
 * this header. Not safe for concurrent use on the same handle by multiple
 * threads without external synchronization.
 */
typedef struct stream* stream_t;

/**
 * @struct string_stream
 * @brief String stream internal state structure with SSO support.
 *
 * @note This layout is exposed for sizing/allocation purposes only.
 *       Treat all fields as private; use the string_stream_* API to
 *       read or mutate stream contents. When @c size is small enough
 *       to fit @c inline_buf, @c data points into @c inline_buf rather
 *       than a heap allocation.
 */
typedef struct string_stream {
    char* data;                             /**< Direct pointer to current data buffer */
    size_t size;                            /**< Length of string in bytes (excluding NUL) */
    size_t capacity;                        /**< Physical capacity including NUL byte */
    size_t pos;                             /**< Seek cursor position */
    char inline_buf[STRING_STREAM_SSO_CAP]; /**< Small String Optimization stack/inline buffer */
} string_stream;

/** Signed result type for stream I/O operations;
follows the POSIX-style error contract described above. */
typedef ssize_t stream_result_t;

/**
 * @brief Wraps an existing `FILE*` in a @c stream_t.
 *
 * @param fp Open file stream to wrap. Ownership of @p fp is not transferred;
 *           the caller remains responsible for closing it, unless otherwise
 *           documented by a higher-level API that consumes the result.
 * @return New stream handle on success, NULL on allocation failure or if
 *         @p fp is NULL.
 * @note The returned handle must be released with stream_destroy().
 */
stream_t create_file_stream(FILE* fp);

/**
 * @brief Creates an in-memory string stream backed by SSO.
 *
 * Buffers up to #STRING_STREAM_SSO_CAP bytes are stored inline without
 * heap allocation; larger content transparently spills onto the heap.
 *
 * @param initial_capacity Suggested initial heap capacity in bytes. May be
 *                          0, in which case only the inline buffer is used
 *                          until it is exceeded.
 * @return New stream handle on success, NULL on allocation failure.
 * @note The returned handle must be released with stream_destroy().
 */
stream_t create_string_stream(size_t initial_capacity);

/**
 * @brief Releases all resources associated with a stream.
 *
 * @param stream Stream to destroy. May be NULL, in which case this is a
 *               no-op. For file-backed streams, the wrapped `FILE*` is
 *               not closed; only the wrapper's own resources are freed.
 */
void stream_destroy(stream_t stream);

/**
 * @brief Repositions the stream's internal cursor.
 *
 * @param stream Target stream.
 * @param offset Offset in bytes, interpreted relative to @p whence.
 * @param whence One of `SEEK_SET`, `SEEK_CUR`, or `SEEK_END`.
 * @return 0 on success, -1 on error (invalid stream, invalid whence, or
 *         resulting position out of range).
 */
int stream_seek(stream_t stream, long offset, int whence);

/**
 * @brief Reads raw data from a file-backed stream.
 *
 * Semantics mirror `fread`: reads up to @p count elements of @p size
 * bytes each into @p ptr.
 *
 * @param s     Source stream. Must be file-backed.
 * @param ptr   Destination buffer; must be at least `size * count` bytes.
 * @param size  Size in bytes of each element.
 * @param count Number of elements to read.
 * @return Number of complete elements successfully read. This may be
 *         less than @p count on EOF or error; use the underlying
 *         `FILE*`'s `feof`/`ferror` to disambiguate if needed.
 */
size_t file_stream_read(stream_t s, void* STREAM_RESTRICT ptr, size_t size, size_t count);

/**
 * @brief Appends a NUL-terminated string to a stream.
 *
 * @param stream Destination stream.
 * @param str    NUL-terminated string to append. Must not be NULL.
 * @return 0 on success, -1 on error (e.g. allocation failure for a
 *         string stream, or write failure for a file-backed stream).
 */
int string_stream_write(stream_t stream, const char* str);

/**
 * @brief Appends exactly @p n bytes from @p str to a stream.
 *
 * Unlike string_stream_write(), the input need not be NUL-terminated;
 * embedded NUL bytes are copied verbatim.
 *
 * @param stream Destination stream.
 * @param str    Source buffer; must be at least @p n bytes.
 * @param n      Number of bytes to append.
 * @return 0 on success, -1 on error (e.g. allocation failure for a
 *         string stream, or write failure for a file-backed stream).
 */
int string_stream_write_len(stream_t stream, const char* str, size_t n);

/**
 * @brief Returns a read-only pointer to a string stream's buffered data.
 *
 * @param stream Source stream. Must be string-backed.
 * @return Pointer to a NUL-terminated internal buffer, valid until the
 *         next mutating call on @p stream or until stream_destroy() is
 *         called. Returns NULL if @p stream is NULL or not string-backed.
 */
const char* string_stream_data(stream_t stream);

/**
 * @brief Reads from a stream up to and including a delimiter byte.
 *
 * @param stream      Source stream.
 * @param delim       Delimiter byte to search for, passed as an `int`
 *                     (as with `fgetc`).  The delimiter is CONSUMED from
 *                     the stream but is NOT copied into @p buffer; it is
 *                     replaced by the terminating NUL.  (Earlier revisions
 *                     of this documentation incorrectly stated that the
 *                     delimiter was included.)
 * @param buffer      Destination buffer.
 * @param buffer_size Size of @p buffer in bytes, including room for the
 *                     terminating NUL that will be written.
 * @return Number of bytes written to @p buffer (excluding the NUL
 *         terminator) on success, 0 on immediate EOF, -1 on error
 *         (including a @p buffer_size too small to hold any data).
 */
ssize_t read_until(stream_t stream, int delim, char* buffer, size_t buffer_size);

/**
 * @brief Fast-path bulk copy between two string streams.
 *
 * Bypasses the generic io_copy() chunking logic when both @p dst and
 * @p src are known to be string-backed, allowing a direct memory copy.
 *
 * @param dst Destination string stream.
 * @param src Source string stream.
 * @return Number of bytes copied.
 * @note Behavior is undefined if either stream is not string-backed;
 *       use io_copy() for the generic case.
 */
unsigned long string_stream_copy_fast(stream_t dst, stream_t src);

/**
 * @brief Copies all remaining data from one stream to another.
 *
 * Generic fallback that works for any combination of file-backed and
 * string-backed streams, reading from @p reader until EOF and writing
 * each chunk to @p writer.
 *
 * @param writer Destination stream.
 * @param reader Source stream.
 * @return Total number of bytes copied.
 */
unsigned long io_copy(stream_t writer, stream_t reader);

/**
 * @brief Copies at most @p n bytes from one stream to another.
 *
 * @param writer Destination stream.
 * @param reader Source stream.
 * @param n      Maximum number of bytes to copy.
 * @return Number of bytes actually copied, which may be less than
 *         @p n if @p reader reaches EOF first.
 */
unsigned long io_copy_n(stream_t writer, stream_t reader, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* STDSTREAMS_H */
