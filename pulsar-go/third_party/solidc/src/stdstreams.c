#include "stdstreams.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include "../include/platform.h"
#else
    #include <sys/stat.h>
    #include <termios.h>
    #include <unistd.h>
    #include "macros.h"
#endif

/* Unlocked stdio — centralized via macros.h.
 * SOLIDC_HAS_GETC_UNLOCKED covers character-level (getc_unlocked);
 * SOLIDC_HAS_FREAD_UNLOCKED covers block-level (fread_unlocked). */
#define HAS_UNLOCKED_CHAR_IO  SOLIDC_HAS_GETC_UNLOCKED
#define HAS_UNLOCKED_BLOCK_IO SOLIDC_HAS_FREAD_UNLOCKED

/* =========================================================================
 * Stream Structure Definition
 * ====================================================================== */

enum stream_type { INVALID_STREAM = -1, FILE_STREAM = 0, STRING_STREAM = 1 };

struct stream {
    ssize_t (*read)(void* handle, void* ptr, size_t n);
    ssize_t (*write)(void* handle, const void* ptr, size_t n);
    int (*read_char)(void* handle);
    int (*eof)(void* handle);
    int (*seek)(void* handle, long offset, int whence);
    int (*flush)(void* handle);

    void* handle;
    enum stream_type type;
};

/* =========================================================================
 * Fast Capacity Expansion Helper
 * ====================================================================== */

/** Computes the next string-stream capacity >= @p needed by doubling from max(@p current, STRING_STREAM_SSO_CAP),
 * clamping to @p needed when doubling would overflow. @param current Current capacity in bytes. @param needed Required
 * capacity in bytes (including NUL). @return New capacity, or 0 if @p needed cannot be represented in SIZE_MAX. */
static STREAM_INLINE size_t calculate_growth(size_t current, size_t needed) {
    if (needed > SIZE_MAX - 1) return 0;  // Overflow guard

    size_t new_cap = current == 0 ? STRING_STREAM_SSO_CAP : current;
    while (new_cap < needed) {
        if (new_cap > SIZE_MAX / 2) {
            new_cap = needed;
            break;
        }
        new_cap *= 2;
    }
    return new_cap;
}

/** Guarantees the stream buffer can hold @p needed bytes, migrating from the SSO inline buffer to a heap allocation
 * (malloc + copy of size+1 bytes) or realloc'ing in place. @param ss Target string-stream state. @param needed Total
 * bytes required, including the NUL terminator. @return true on success; false on allocation failure with contents left
 * untouched. */
static bool string_stream_ensure_capacity(string_stream* ss, size_t needed) {
    if (STREAM_LIKELY(needed <= ss->capacity)) return true;

    size_t new_cap = calculate_growth(ss->capacity, needed);
    if (STREAM_UNLIKELY(new_cap == 0)) return false;

    char* new_data = NULL;
    if (ss->data == ss->inline_buf) {
        // Transition from SSO inline buffer to heap allocation
        new_data = (char*)malloc(new_cap);
        if (STREAM_UNLIKELY(!new_data)) return false;
        memcpy(new_data, ss->inline_buf, ss->size + 1);
    } else {
        new_data = (char*)realloc(ss->data, new_cap);
        if (STREAM_UNLIKELY(!new_data)) return false;
    }

    ss->data = new_data;
    ss->capacity = new_cap;
    return true;
}

/* =========================================================================
 * Terminal I/O Implementations
 * ====================================================================== */

/** @brief Reads one line from stdin after optionally printing @p prompt, stripping the trailing newline. If the line
 * exceeds the buffer, the remainder (up to newline) is drained so later reads start on the next line. @param prompt
 * Optional prompt string (can be NULL). @param buffer Destination buffer. @param buffer_len Total size of the buffer.
 * @return true on success, false on EOF, error, or invalid arguments. */
bool readline(const char* prompt, char* buffer, size_t buffer_len) {
    if (STREAM_UNLIKELY(!buffer || buffer_len == 0)) return false;

    if (prompt) {
        fputs(prompt, stdout);
        fflush(stdout);
    }

    if (fgets(buffer, (int)buffer_len, stdin) == NULL) return false;

    // Single-pass scan using memchr to strip newline
    char* nl = (char*)memchr(buffer, '\n', buffer_len);
    if (nl) {
        *nl = '\0';
    } else {
        // Drain overflowing input characters if line exceeded buffer_len - 1
        size_t len = strlen(buffer);
        if (len == buffer_len - 1) {
            int c;
#if HAS_UNLOCKED_CHAR_IO
            flockfile(stdin);
            while ((c = getc_unlocked(stdin)) != EOF && c != '\n');
            funlockfile(stdin);
#else
            while ((c = getchar()) != EOF && c != '\n');
#endif
        }
    }
    return true;
}

/** @brief Reads a password from the terminal with echo disabled (termios ECHO toggle on POSIX, console mode on
 * Windows), printing @p prompt first and a newline afterwards; terminal state is always restored. @param prompt
 * Optional prompt string (can be NULL). @param buffer Destination buffer, always NUL-terminated. @param buffer_len
 * Total size of the buffer. @return Number of characters stored (excluding NUL), or -1 if stdin is not a terminal or an
 * error occurs. */
int getpassword(const char* prompt, char* buffer, size_t buffer_len) {
    if (STREAM_UNLIKELY(!buffer || buffer_len == 0)) return -1;

#ifdef _WIN32
    if (prompt) {
        fputs(prompt, stdout);
        fflush(stdout);
    }

    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode, count, i = 0;

    if (hStdin == INVALID_HANDLE_VALUE || !GetConsoleMode(hStdin, &mode)) return -1;
    if (!SetConsoleMode(hStdin, mode & ~ENABLE_ECHO_INPUT)) return -1;

    for (i = 0; i < (DWORD)(buffer_len - 1); i++) {
        if (!ReadConsoleA(hStdin, &buffer[i], 1, &count, NULL) || count == 0) break;
        if (buffer[i] == '\n' || buffer[i] == '\r') break;
    }
    buffer[i] = '\0';

    SetConsoleMode(hStdin, mode);
    putchar('\n');
    return (int)i;
#else
    struct termios old_t, new_t;
    int fd = fileno(stdin);

    if (tcgetattr(fd, &old_t) != 0) return -1;

    new_t = old_t;
    new_t.c_lflag &= (tcflag_t)~ECHO;

    if (tcsetattr(fd, TCSAFLUSH, &new_t) != 0) return -1;

    bool ok = readline(prompt, buffer, buffer_len);

    tcsetattr(fd, TCSAFLUSH, &old_t);
    putchar('\n');

    return ok ? (int)strlen(buffer) : -1;
#endif
}

/* =========================================================================
 * Stream Implementations
 * ====================================================================== */

/** @brief Repositions the stream cursor by dispatching to the implementation's seek handler. @param stream Target
 * stream. @param offset Offset in bytes, interpreted relative to @p whence. @param whence SEEK_SET, SEEK_CUR, or
 * SEEK_END. @return 0 on success, -1 on invalid stream, whence, or out-of-range position. */
int stream_seek(stream_t stream, long offset, int whence) {
    /* Explicit guard: STREAM_ASSERT compiles out under NDEBUG. */
    if (STREAM_UNLIKELY(!stream)) return -1;
    return stream->seek(stream->handle, offset, whence);
}

/* -------------------------------------------------------------------------
 * File Stream VTable Implementations
 * ---------------------------------------------------------------------- */

/** File-stream vtable read: fread under flockfile (unlocked stdio fast path on POSIX). Maps a 0-byte result to 0 on EOF
 * and -1 on error, per the POSIX-style error contract. @param handle The wrapped FILE*. @param ptr Destination buffer.
 * @param n Maximum bytes to read. @return Bytes read (>0), 0 on EOF, -1 on error. */
static ssize_t file_read_impl(void* handle, void* ptr, size_t n) {
    FILE* fp = (FILE*)handle;
#if HAS_UNLOCKED_BLOCK_IO
    flockfile(fp);
    size_t r = fread_unlocked(ptr, 1, n, fp);
    funlockfile(fp);
#else
    size_t r = fread(ptr, 1, n, fp);
#endif
    if (r == 0) return ferror(fp) ? -1 : 0;
    return (ssize_t)r;
}

/** File-stream vtable write: fwrite under flockfile (unlocked stdio fast path on POSIX). Returns -1 only when nothing
 * was written and the stream error flag is set. */
static ssize_t file_write_impl(void* handle, const void* ptr, size_t n) {
    FILE* fp = (FILE*)handle;
#if HAS_UNLOCKED_BLOCK_IO
    flockfile(fp);
    size_t w = fwrite_unlocked(ptr, 1, n, fp);
    funlockfile(fp);
#else
    size_t w = fwrite(ptr, 1, n, fp);
#endif
    return (w == 0 && ferror(fp)) ? -1 : (ssize_t)w;
}

/** File-stream vtable single-byte read (getc_unlocked fast path where available). @return The byte as an unsigned char
 * value, or EOF. */
static int file_read_char_impl(void* handle) {
    FILE* fp = (FILE*)handle;
#if HAS_UNLOCKED_CHAR_IO
    return getc_unlocked(fp);
#else
    return fgetc(fp);
#endif
}

/** File-stream vtable EOF probe; thin wrapper over feof(). */
static int file_eof_impl(void* handle) { return feof((FILE*)handle); }

/** File-stream vtable flush; thin wrapper over fflush(). @return 0 on success, EOF on error. */
static int file_flush_impl(void* handle) { return fflush((FILE*)handle); }

/** File-stream vtable seek; thin wrapper over fseek(). @return 0 on success, -1 on error. */
static int file_seek_impl(void* handle, long offset, int whence) { return fseek((FILE*)handle, offset, whence); }

/** @brief Wraps an existing FILE* in a stream_t with the file-stream vtable. Ownership of @p fp is NOT transferred; the
 * caller remains responsible for closing it. @param fp Open file stream to wrap. @return New stream handle to release
 * with stream_destroy(), or NULL if @p fp is NULL or allocation fails. */
stream_t create_file_stream(FILE* fp) {
    if (STREAM_UNLIKELY(!fp)) return NULL;

    stream_t s = (stream_t)malloc(sizeof(struct stream));
    if (STREAM_UNLIKELY(!s)) return NULL;

    s->read = file_read_impl;
    s->write = file_write_impl;
    s->flush = file_flush_impl;
    s->seek = file_seek_impl;
    s->eof = file_eof_impl;
    s->read_char = file_read_char_impl;
    s->handle = fp;
    s->type = FILE_STREAM;
    return s;
}

/** @brief fread-style element read from a file-backed stream, continuing from the current position (no rewind), so
 * sequential reads work. @param s Source stream; must be file-backed. @param ptr Destination buffer of at least
 * size*count bytes. @param size Size in bytes of each element. @param count Number of elements to read. @return Number
 * of complete elements read; 0 on EOF, error, or invalid/wrong-type arguments. */
size_t file_stream_read(stream_t s, void* STREAM_RESTRICT ptr, size_t size, size_t count) {
    if (STREAM_UNLIKELY(!s || !ptr || s->type != FILE_STREAM)) return 0;
    /*
     * FIX (Bug #22): this used to seek to offset 0 before every read,
     * both violating the documented "mirrors fread" streaming contract
     * and making sequential reads impossible (every call returned the
     * first bytes).  Reads now continue from the current position.
     */
    FILE* fp = (FILE*)s->handle;
    return fread(ptr, size, count, fp);
}

/* -------------------------------------------------------------------------
 * String Stream VTable Implementations
 * ---------------------------------------------------------------------- */

/** String-stream vtable read: copies up to @p n bytes from the cursor into @p ptr, clamped to the remaining size, and
 * advances the cursor. @return Bytes copied (>0), or 0 once pos has reached size. */
static ssize_t string_read_impl(void* handle, void* ptr, size_t n) {
    string_stream* ss = (string_stream*)handle;
    if (ss->pos >= ss->size) return 0;

    size_t avail = ss->size - ss->pos;
    if (n > avail) n = avail;

    memcpy(ptr, ss->data + ss->pos, n);
    ss->pos += n;
    return (ssize_t)n;
}

/** String-stream vtable write: appends @p n bytes at the cursor, growing the buffer via
 * string_stream_ensure_capacity(), extending size when writing past it, and keeping the buffer NUL-terminated. @return
 * @p n on success, -1 on size_t overflow or allocation failure. */
static ssize_t string_write_impl(void* handle, const void* ptr, size_t n) {
    string_stream* ss = (string_stream*)handle;
    if (STREAM_UNLIKELY(n == 0)) return 0;

    if (STREAM_UNLIKELY(n > SIZE_MAX - ss->pos - 1)) return -1;
    size_t needed_cap = ss->pos + n + 1;

    if (!string_stream_ensure_capacity(ss, needed_cap)) return -1;

    memcpy(ss->data + ss->pos, ptr, n);
    ss->pos += n;

    if (ss->pos > ss->size) {
        ss->size = ss->pos;
    }
    ss->data[ss->size] = '\0';

    return (ssize_t)n;
}

/** String-stream vtable single-byte read. @return The byte as an unsigned char value, or EOF when the cursor is at or
 * past size. */
static int string_read_char_impl(void* handle) {
    string_stream* ss = (string_stream*)handle;
    if (ss->pos >= ss->size) return EOF;
    return (unsigned char)ss->data[ss->pos++];
}

/** String-stream vtable EOF probe: non-zero once the cursor reaches size. */
static int string_eof_impl(void* handle) {
    string_stream* ss = (string_stream*)handle;
    return ss->pos >= ss->size;
}

/** String-stream vtable seek: computes the new cursor per @p whence and rejects results outside [0, size]. @return 0 on
 * success, -1 on invalid whence or out-of-range position. */
static int string_seek_impl(void* handle, long offset, int whence) {
    string_stream* ss = (string_stream*)handle;
    ssize_t new_pos = 0;

    switch (whence) {
        case SEEK_SET:
            new_pos = offset;
            break;
        case SEEK_CUR:
            new_pos = (ssize_t)ss->pos + offset;
            break;
        case SEEK_END:
            new_pos = (ssize_t)ss->size + offset;
            break;
        default:
            return -1;
    }

    if (new_pos < 0 || (size_t)new_pos > ss->size) return -1;

    ss->pos = (size_t)new_pos;
    return 0;
}

/** String-stream vtable flush: no-op since string content is always immediately consistent. @return Always 0. */
static int string_flush_impl(void* handle) {
    (void)handle;
    return 0;
}

/** @brief Allocates a string stream with struct stream + string_stream in a single malloc block. Content up to
 * STRING_STREAM_SSO_CAP bytes lives in the inline buffer; larger initial_capacity requests heap memory upfront. @param
 * initial_capacity Suggested initial capacity in bytes; <= STRING_STREAM_SSO_CAP keeps data inline. @return New stream
 * handle to release with stream_destroy(), or NULL on allocation failure. */
stream_t create_string_stream(size_t initial_capacity) {
    // Single combined allocation for struct stream + string_stream struct
    stream_t s = (stream_t)malloc(sizeof(struct stream) + sizeof(string_stream));
    if (STREAM_UNLIKELY(!s)) return NULL;

    string_stream* ss = (string_stream*)(s + 1);

    if (initial_capacity <= STRING_STREAM_SSO_CAP) {
        // Use inline SSO buffer
        ss->data = ss->inline_buf;
        ss->capacity = STRING_STREAM_SSO_CAP;
    } else {
        ss->data = (char*)malloc(initial_capacity);
        if (STREAM_UNLIKELY(!ss->data)) {
            free(s);
            return NULL;
        }
        ss->capacity = initial_capacity;
    }

    ss->data[0] = '\0';
    ss->size = 0;
    ss->pos = 0;

    s->read = string_read_impl;
    s->write = string_write_impl;
    s->flush = string_flush_impl;
    s->read_char = string_read_char_impl;
    s->eof = string_eof_impl;
    s->seek = string_seek_impl;
    s->handle = ss;
    s->type = STRING_STREAM;

    return s;
}

/* -------------------------------------------------------------------------
 * Fast String Helpers
 * ---------------------------------------------------------------------- */

/** @brief Appends a NUL-terminated string at the end of a string stream (ignores the seek cursor). @param stream
 * Destination stream; must be string-backed. @param str NUL-terminated string to append; must not be NULL. @return 0 on
 * success, -1 on invalid arguments or allocation failure. */
int string_stream_write(stream_t stream, const char* str) {
    if (STREAM_UNLIKELY(!stream || stream->type != STRING_STREAM || !str)) return -1;

    size_t len = strlen(str);
    return string_stream_write_len(stream, str, len);
}

/** @brief Appends exactly @p n bytes at the end of a string stream (ignores the seek cursor); embedded NUL bytes are
 * copied verbatim. @param stream Destination stream; must be string-backed. @param str Source buffer of at least @p n
 * bytes. @param n Number of bytes to append. @return 0 on success, -1 on invalid arguments, size_t overflow, or
 * allocation failure. */
int string_stream_write_len(stream_t stream, const char* str, size_t n) {
    if (STREAM_UNLIKELY(!stream || stream->type != STRING_STREAM || !str)) return -1;

    string_stream* ss = (string_stream*)stream->handle;
    if (STREAM_UNLIKELY(n > SIZE_MAX - ss->size - 1)) return -1;

    size_t needed_cap = ss->size + n + 1;
    if (!string_stream_ensure_capacity(ss, needed_cap)) return -1;

    memcpy(ss->data + ss->size, str, n);
    ss->size += n;
    ss->data[ss->size] = '\0';

    return (int)n;
}

/** @brief Returns a read-only pointer to the string stream's NUL-terminated buffer, valid until the next mutating call
 * or stream_destroy(). @param stream Source stream; must be string-backed. @return Internal data pointer, or NULL if @p
 * stream is NULL or not string-backed. */
const char* string_stream_data(stream_t stream) {
    if (STREAM_UNLIKELY(!stream || stream->type != STRING_STREAM)) return NULL;
    return ((string_stream*)stream->handle)->data;
}

/* =========================================================================
 * Delimited Read (read_until)
 * ====================================================================== */

/** @brief Reads up to buffer_size-1 bytes into @p buffer, stopping at (and consuming, but not storing) @p delim. String
 * streams use memchr; seekable files take a bulk-fread fast path that rolls the position back over overshoot;
 * non-seekable streams use a per-byte loop. The buffer is always NUL-terminated on a non-error return. @param stream
 * Source stream. @param delim Delimiter byte to search for (as with fgetc). @param buffer Destination buffer. @param
 * buffer_size Total buffer size in bytes, including room for the NUL. @return Bytes stored (excluding NUL), 0 on
 * immediate EOF, -1 on invalid arguments or read error. */
ssize_t read_until(stream_t stream, int delim, char* buffer, size_t buffer_size) {
    if (STREAM_UNLIKELY(!stream || !buffer || buffer_size == 0)) return -1;

    /* --- SIMD-accelerated Fast Path for String Streams --- */
    if (STREAM_LIKELY(stream->type == STRING_STREAM)) {
        string_stream* ss = (string_stream*)stream->handle;
        if (STREAM_UNLIKELY(ss->pos >= ss->size)) return 0; /* immediate EOF */

        size_t avail = ss->size - ss->pos;
        size_t max_read = buffer_size - 1;
        size_t check_len = avail < max_read ? avail : max_read;

        const char* p = ss->data + ss->pos;
        const char* match = (const char*)memchr(p, delim, check_len);

        size_t copy_len = 0;
        if (match) {
            copy_len = (size_t)(match - p);
            memcpy(buffer, p, copy_len);
            ss->pos += copy_len + 1;  // Consume delimiter
        } else {
            copy_len = check_len;
            memcpy(buffer, p, copy_len);
            ss->pos += copy_len;
        }

        buffer[copy_len] = '\0';
        return (ssize_t)copy_len;
    }

    /* --- FILE_STREAM --- */
    FILE* fp = (FILE*)stream->handle;
    size_t max_bytes = buffer_size - 1;

    /*
     * Seekable fast path (Perf #18): pull the whole remaining window with
     * one fread, locate the delimiter with memchr, then roll the file
     * position back over any overshoot.  Guarded by an ftell probe so
     * non-seekable streams (pipes, ttys) fall back to the portable byte
     * loop rather than silently losing pushed-back data.
     */
    if (ftell(fp) >= 0) {
        size_t got = fread(buffer, 1, max_bytes, fp);
        if (got == 0) {
            return feof(fp) ? 0 : -1;
        }

        const char* hit = (const char*)memchr(buffer, delim, got);
        if (hit) {
            size_t consume = (size_t)(hit - buffer) + 1; /* include delimiter */
            long overshoot = (long)(got - consume);
            if (overshoot > 0 && fseek(fp, -overshoot, SEEK_CUR) != 0) {
                /* Rollback failed on what appeared seekable: the delimiter
                 * boundary is still reported correctly, but the overshoot
                 * bytes are unrecoverable here.  Treat as short read. */
                buffer[consume - 1] = '\0';
                return (ssize_t)(consume - 1);
            }
            buffer[consume - 1] = '\0';
            return (ssize_t)(consume - 1); /* exclude delimiter */
        }

        /* No delimiter in this window: whole window is the result. */
        buffer[got] = '\0';
        return (ssize_t)got;
    }

#if HAS_UNLOCKED_CHAR_IO
    flockfile(fp);
#endif

    ssize_t bytes = 0;
    while ((size_t)bytes < max_bytes) {
#if HAS_UNLOCKED_CHAR_IO
        int ch = getc_unlocked(fp);
#else
        int ch = fgetc(fp);
#endif
        if (ch == EOF || ch == delim) break;
        buffer[bytes++] = (char)ch;
    }

#if HAS_UNLOCKED_CHAR_IO
    funlockfile(fp);
#endif

    if (bytes == 0 && feof(fp)) return 0; /* immediate EOF */
    buffer[bytes] = '\0';
    return bytes;
}

/* =========================================================================
 * Stream Copy Routines
 * ====================================================================== */

/** @brief Bulk-copies everything remaining in @p src (from its cursor) to @p dst at dst's cursor with a single memcpy,
 * advancing both cursors and keeping dst NUL-terminated. Both streams must be string-backed. @param dst Destination
 * string stream. @param src Source string stream. @return Bytes copied, 0 if the source is exhausted, or (unsigned
 * long)-1 on invalid arguments, size_t overflow, or allocation failure. */
unsigned long string_stream_copy_fast(stream_t dst, stream_t src) {
    if (STREAM_UNLIKELY(!dst || !src || dst->type != STRING_STREAM || src->type != STRING_STREAM)) {
        return (unsigned long)-1;
    }

    string_stream* s = (string_stream*)src->handle;
    string_stream* d = (string_stream*)dst->handle;

    if (s->pos >= s->size) return 0;

    size_t n = s->size - s->pos;
    if (STREAM_UNLIKELY(n > SIZE_MAX - d->pos - 1)) return (unsigned long)-1;

    size_t needed_cap = d->pos + n + 1;
    if (!string_stream_ensure_capacity(d, needed_cap)) return (unsigned long)-1;

    memcpy(d->data + d->pos, s->data + s->pos, n);

    if (d->pos + n > d->size) {
        d->size = d->pos + n;
    }
    d->data[d->size] = '\0';

    d->pos += n;
    s->pos += n;
    return (unsigned long)n;
}

/** @brief Copies reader to writer until EOF via a 16 KB chunk loop, flushing the writer at the end. String-to-string
 * pairs bypass the loop (string_stream_copy_fast), and copying a seekable file into a string stream pre-sizes the
 * destination to avoid regrowth. @param writer Destination stream. @param reader Source stream. @return Total bytes
 * copied, or (unsigned long)-1 on invalid arguments or I/O error. */
unsigned long io_copy(stream_t writer, stream_t reader) {
    if (STREAM_UNLIKELY(!writer || !reader)) return (unsigned long)-1;

    // Direct String-to-String bypass
    if (writer->type == STRING_STREAM && reader->type == STRING_STREAM) {
        return string_stream_copy_fast(writer, reader);
    }

    // Pre-allocate capacity if copying from FILE to STRING_STREAM
    if (writer->type == STRING_STREAM && reader->type == FILE_STREAM) {
        FILE* fp = (FILE*)reader->handle;
        long curr = ftell(fp);
        if (curr >= 0 && fseek(fp, 0, SEEK_END) == 0) {
            long end = ftell(fp);
            fseek(fp, curr, SEEK_SET);
            if (end > curr) {
                string_stream_ensure_capacity((string_stream*)writer->handle, (size_t)(end - curr) + 1);
            }
        }
    }

    char buf[16384];
    ssize_t nread = 0;
    unsigned long total = 0;

    while ((nread = reader->read(reader->handle, buf, sizeof(buf))) > 0) {
        ssize_t w = writer->write(writer->handle, buf, (size_t)nread);
        if (w < 0) return (unsigned long)-1;
        total += (unsigned long)w;
    }

    if (nread < 0) return (unsigned long)-1;

    writer->flush(writer->handle);
    return total;
}

/** @brief Copies at most @p n bytes from reader to writer in chunks of up to 16 KB, stopping early on EOF, then flushes
 * the writer. @param writer Destination stream. @param reader Source stream. @param n Maximum number of bytes to copy.
 * @return Bytes actually copied (may be < @p n on early EOF), or (unsigned long)-1 on invalid arguments or I/O error.
 */
unsigned long io_copy_n(stream_t writer, stream_t reader, size_t n) {
    if (STREAM_UNLIKELY(!writer || !reader)) return (unsigned long)-1;

    char buf[16384];
    ssize_t nread = 0;
    unsigned long total = 0;

    while (n > 0) {
        size_t want = n < sizeof(buf) ? n : sizeof(buf);
        nread = reader->read(reader->handle, buf, want);
        if (nread <= 0) break;

        ssize_t w = writer->write(writer->handle, buf, (size_t)nread);
        if (w < 0) return (unsigned long)-1;

        total += (unsigned long)w;
        n -= (size_t)nread;
    }

    if (nread < 0) return (unsigned long)-1;

    writer->flush(writer->handle);
    return total;
}

/* =========================================================================
 * Stream Deallocation
 * ====================================================================== */

/** @brief Releases the wrapper's resources: for string streams the heap buffer (when not SSO-inline) and the combined
 * block are freed. The wrapped FILE* is never closed — ownership stays with the caller (see create_file_stream). @param
 * stream Stream to destroy; NULL is a no-op. */
void stream_destroy(stream_t stream) {
    if (!stream) return;

    if (stream->type == FILE_STREAM) {
        /*
         * FIX (Bug #23): destroy() used to fclose() the wrapped FILE*
         * (except the std streams), contradicting the documented
         * ownership contract — create_file_stream() explicitly does NOT
         * take ownership, and callers may still need the stream or may
         * close it themselves (double-close hazard).  Ownership stays
         * with the caller, exactly as the header documents.
         */
        free(stream);
    } else if (stream->type == STRING_STREAM) {
        string_stream* ss = (string_stream*)stream->handle;
        if (ss && ss->data && ss->data != ss->inline_buf) {
            free(ss->data);
        }
        // Free single contiguous block allocation containing both stream and string_stream
        free(stream);
    }
}
