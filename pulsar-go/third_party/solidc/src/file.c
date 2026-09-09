/* Ensure Darwin extensions (sendfile) are visible before any POSIX headers.
 * _DARWIN_C_SOURCE must be defined before the first system header.
 * CMake defines it via -D_DARWIN_C_SOURCE, but defining it here makes the
 * file self-contained for standalone builds. */
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
    #define _DARWIN_C_SOURCE 1
#endif

#include "../include/file.h"

#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
    #include <sys/stat.h> /* fstat, S_ISREG for the file_readall fast path */
    #ifdef __linux__
        #include <linux/version.h>
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
            #define HAVE_COPY_FILE_RANGE 1
        #endif
    #endif
#endif

#ifdef _WIN32
    #include <io.h>
#else
    #include <pwd.h>
    #include <sys/types.h>
#endif

/** Human-readable size formatting precision threshold. */
#define HUMAN_SIZE_EPSILON 1e-4

/** Buffer size for file copy operations. */
#define COPY_BUFSIZE 65536

/** Maximum safe file size for readall operations (1GB). */
#define MAX_READALL_SIZE (1ULL << 30)

/** Extracts the platform-native handle (fd on POSIX, HANDLE on Windows) from a FILE* stream. @param stream The FILE*
 * stream. @return Native handle or INVALID_NATIVE_HANDLE on error. */
static native_handle_t get_native_handle(FILE* stream) {
    if (!stream) {
        return INVALID_NATIVE_HANDLE;
    }

#ifdef _WIN32
    int fd = _fileno(stream);
    if (fd == -1) {
        return INVALID_NATIVE_HANDLE;
    }
    HANDLE handle = (HANDLE)(uintptr_t)_get_osfhandle(fd);
    return (handle == INVALID_HANDLE_VALUE) ? INVALID_NATIVE_HANDLE : handle;
#else
    int fd = fileno(stream);
    return (fd == -1) ? INVALID_NATIVE_HANDLE : fd;
#endif
}

/**
 * Cross-platform file information retrieval.
 * On Unix: uses lstat to detect symlinks without following them.
 * On Windows: uses GetFileAttributesEx for basic info.
 */
#ifdef _WIN32

/** Converts Windows FILETIME (100 ns intervals since 1601) to a Unix timestamp in seconds since 1970. @param ft Windows
 * FILETIME structure. @return Unix timestamp (seconds since epoch). */
static time_t filetime_to_unix(const FILETIME* ft) {
    ULARGE_INTEGER ull;
    ull.LowPart = ft->dwLowDateTime;
    ull.HighPart = ft->dwHighDateTime;
    // Convert from 100-nanosecond intervals since 1601 to seconds since 1970
    return (time_t)((ull.QuadPart / 10000000ULL) - 11644473600ULL);
}

/** Populates FileAttributes from a file path (Windows implementation via GetFileAttributesExA; executability is
 * inferred from the .exe/.bat/.cmd/.com extension). @param path Full path to the file. @param attr Output
 * FileAttributes structure to populate. @return 0 on success, -1 on error (errno is set). */
int populate_file_attrs(const char* path, FileAttributes* attr) {
    WIN32_FILE_ATTRIBUTE_DATA file_info;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &file_info)) {
        errno = ENOENT;
        return -1;
    }

    // Initialize structure
    *attr = (FileAttributes){
        .attrs = FATTR_NONE,
        .size = 0,
        .mtime = filetime_to_unix(&file_info.ftLastWriteTime),
    };

    // Calculate file size
    ULARGE_INTEGER file_size;
    file_size.LowPart = file_info.nFileSizeLow;
    file_size.HighPart = file_info.nFileSizeHigh;
    attr->size = file_size.QuadPart;

    // Determine file type
    if (file_info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        attr->attrs |= FATTR_DIR;
        attr->size = 0;  // Directories have no meaningful size on Windows
    } else {
        attr->attrs |= FATTR_FILE;
    }

    // Check for reparse points (symlinks, junctions, etc.)
    if (file_info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        attr->attrs |= FATTR_SYMLINK;
    }

    // Check for hidden files
    if (file_info.dwFileAttributes & FILE_ATTRIBUTE_HIDDEN) {
        attr->attrs |= FATTR_HIDDEN;
    }

    // On Windows, executability is determined by file extension
    const char* ext = strrchr(path, '.');
    if (ext && (strcmp(ext, ".exe") == 0 || strcmp(ext, ".bat") == 0 || strcmp(ext, ".cmd") == 0 ||
                strcmp(ext, ".com") == 0)) {
        attr->attrs |= FATTR_EXECUTABLE;
    }

    return 0;
}

#else  // Unix/Linux/macOS

/** Populates FileAttributes from a file path (POSIX implementation using lstat, so symlinks are detected without being
 * followed; hidden means a leading '.'). @param path Full path to the file. @param attr Output FileAttributes structure
 * to populate. @return 0 on success, -1 on error (errno is set). */
int populate_file_attrs(const char* path, FileAttributes* attr) {
    if (!attr) {
        errno = EINVAL;
        return -1;
    }

    struct stat st;
    if (lstat(path, &st) != 0) {
        return -1;  // errno is set by lstat
    }

    // Initialize structure
    *attr = (FileAttributes){
        .attrs = FATTR_NONE,
        .size = (uint64_t)st.st_size,
        .mtime = st.st_mtime,
    };

    // Determine file type
    if (S_ISREG(st.st_mode)) {
        attr->attrs |= FATTR_FILE;
        // Check if the file is executable by User, Group, or Other.
        if (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) {
            attr->attrs |= FATTR_EXECUTABLE;
        }
    } else if (S_ISDIR(st.st_mode)) {
        attr->attrs |= FATTR_DIR;
        attr->size = 0;  // Directory size is not meaningful
    } else if (S_ISLNK(st.st_mode)) {
        attr->attrs |= FATTR_SYMLINK;
    }

    #ifdef S_ISCHR
    if (S_ISCHR(st.st_mode)) {
        attr->attrs |= FATTR_CHARDEV;
    }
    #endif

    #ifdef S_ISBLK
    if (S_ISBLK(st.st_mode)) {
        attr->attrs |= FATTR_BLOCKDEV;
    }
    #endif

    #ifdef S_ISFIFO
    if (S_ISFIFO(st.st_mode)) {
        attr->attrs |= FATTR_FIFO;
    }
    #endif

    #ifdef S_ISSOCK
    if (S_ISSOCK(st.st_mode)) {
        attr->attrs |= FATTR_SOCKET;
    }
    #endif

    // Check if hidden (starts with '.' on Unix)
    const char* name = path;

    if (path) {
        const char* slash = strrchr(path, '/');
        if (slash && slash[1] != '\0') {
            name = slash + 1;
        }
    }

    if (name[0] == '.') {
        attr->attrs |= FATTR_HIDDEN;
    }

    return 0;
}
#endif  // _WIN32

/** @brief Opens a file and fills @p file with its stream, native handle, and attributes; on any failure the stream is
 * closed and errno explains why. @param file Pointer to file_t structure to initialize. @param filename Path to the
 * file to open. @param mode fopen-style mode string (e.g. "r", "wb+", "a"). @return FILE_SUCCESS on success,
 * appropriate error code otherwise. */
file_result_t file_open(file_t* file, const char* filename, const char* mode) {
    if (!filename || !mode) {
        errno = EINVAL;
        return FILE_ERROR_INVALID_ARGS;
    }

    // Initialize structure to safe state
    file->stream = NULL;
    file->native_handle = INVALID_NATIVE_HANDLE;

    // Open the file stream
    file->stream = fopen(filename, mode);
    if (!file->stream) {
        return FILE_ERROR_OPEN_FAILED;  // errno set by fopen
    }

    // Get native handle
    file->native_handle = get_native_handle(file->stream);
    if (file->native_handle == INVALID_NATIVE_HANDLE) {
        fclose(file->stream);
        file->stream = NULL;
        errno = EBADF;
        return FILE_ERROR_OPEN_FAILED;
    }

    // Populate file attributes.
    if (populate_file_attrs(filename, &file->attr) != 0) {
        fclose(file->stream);
        file->stream = NULL;
        errno = EBADF;
        return FILE_ERROR_OPEN_FAILED;
    }

    return FILE_SUCCESS;
}

/** @brief Closes the stream and invalidates the native handle; safe to call multiple times or on uninitialized
 * structures. @param file Pointer to the file_t structure. */
void file_close(file_t* file) {
    if (file->stream) {
        fclose(file->stream);
        file->stream = NULL;
    }
    file->native_handle = INVALID_NATIVE_HANDLE;
}

/** @brief Flushes pending writes, then truncates or extends the file to @p length bytes via the native handle. @param
 * file Pointer to the opened file_t structure (needs write permission). @param length Desired file length in bytes;
 * negative values are rejected. @return FILE_SUCCESS on success, appropriate error code otherwise. */
file_result_t file_truncate(file_t* file, int64_t length) {
    if (length < 0) {
        errno = EINVAL;
        return FILE_ERROR_INVALID_ARGS;
    }

    // Flush any pending writes before truncation
    if (fflush(file->stream) != 0) {
        return FILE_ERROR_IO_FAILED;
    }

#ifdef _WIN32
    LARGE_INTEGER li = {.QuadPart = length};
    if (!SetFilePointerEx(file->native_handle, li, NULL, FILE_BEGIN) || !SetEndOfFile(file->native_handle)) {
        errno = EIO;
        return FILE_ERROR_IO_FAILED;
    }
#else
    if (ftruncate(file->native_handle, (off_t)length) != 0) {
        return FILE_ERROR_IO_FAILED;  // errno already set
    }
#endif

    return FILE_SUCCESS;
}

/** @brief Formats @p size in human-readable units (B..EB), printing whole numbers when within HUMAN_SIZE_EPSILON of an
 * integer, else two decimals. @param size File size in bytes. @param buf Output buffer; needs at least 8 bytes (e.g.
 * "1024.00 B"). @param len Capacity of @p buf. @return FILE_SUCCESS on success, FILE_ERROR_INVALID_ARGS if the buffer
 * is NULL or too small. */
file_result_t filesize_tostring(uint64_t size, char* buf, size_t len) {
    if (!buf || len < 8) {  // Minimum for "1024.00 B"
        return FILE_ERROR_INVALID_ARGS;
    }

    if (size == 0) {
        int written = snprintf(buf, len, "0 B");
        return (written > 0 && (size_t)written < len) ? FILE_SUCCESS : FILE_ERROR_INVALID_ARGS;
    }

    static const char* const units[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB"};
    static const size_t num_units = sizeof(units) / sizeof(units[0]);

    size_t unit_index = 0;
    double value = (double)size;

    while (value >= 1024.0 && unit_index < num_units - 1) {
        value /= 1024.0;
        unit_index++;
    }

    double rounded = round(value);
    int written = -1;

    if (fabs(value - rounded) < HUMAN_SIZE_EPSILON) {
        written = snprintf(buf, len, "%.0f %s", rounded, units[unit_index]);
    } else {
        written = snprintf(buf, len, "%.2f %s", value, units[unit_index]);
    }

    return (written > 0 && (size_t)written < len) ? FILE_SUCCESS : FILE_ERROR_INVALID_ARGS;
}

/** @brief Buffered fread wrapper; returns 0 for NULL buffer or zero size/count instead of touching the stream. @param
 * file Pointer to the opened file_t structure. @param buffer Buffer to store read data. @param size Size of each
 * element. @param count Number of elements to read. @return Number of elements successfully read; use feof/ferror for
 * status. */
size_t file_read(const file_t* file, void* buffer, size_t size, size_t count) {
    if (!buffer || size == 0 || count == 0) {
        return 0;
    }
    return fread(buffer, size, count, file->stream);
}

/** @brief Buffered fwrite wrapper; does not flush the stream. Returns 0 for NULL buffer or zero size/count. @param file
 * Pointer to the opened file_t structure. @param buffer Data to write. @param size Size of each element. @param count
 * Number of elements to write. @return Number of elements successfully written; use ferror for status. */
size_t file_write(file_t* file, const void* buffer, size_t size, size_t count) {
    if (!buffer || size == 0 || count == 0) {
        return 0;
    }
    return fwrite(buffer, size, count, file->stream);
}

/** @brief Writes a null-terminated string to the file, excluding the null terminator. @param file Pointer to the opened
 * file_t structure. @param str Null-terminated string to write. @return Number of bytes written; 0 if @p str is NULL or
 * empty. */
size_t file_write_string(file_t* file, const char* str) {
    if (!str) {
        return 0;
    }
    size_t len = strlen(str);
    return (len > 0) ? fwrite(str, 1, len, file->stream) : 0;
}

/** @brief Positioned read that leaves the file pointer untouched (pread on POSIX; OVERLAPPED ReadFile on Windows, where
 * ERROR_HANDLE_EOF maps to 0). @param file Pointer to the opened file_t structure. @param buffer Buffer to store read
 * data. @param size Number of bytes to read. @param offset File offset to read from; must be >= 0. @return Bytes read
 * on success, 0 on EOF, -1 on error (errno is set). */
ssize_t file_pread(const file_t* file, void* buffer, size_t size, int64_t offset) {
    if (!buffer || size == 0 || offset < 0) {
        errno = EINVAL;
        return -1;
    }

#ifdef _WIN32
    OVERLAPPED ov = {.Offset = (DWORD)(offset & 0xFFFFFFFF), .OffsetHigh = (DWORD)(offset >> 32), .hEvent = NULL};

    DWORD bytes_read;
    if (!ReadFile(file->native_handle, buffer, (DWORD)size, &bytes_read, &ov)) {
        DWORD error = GetLastError();
        if (error == ERROR_HANDLE_EOF) {
            return 0;  // EOF
        }
        errno = EIO;
        return -1;
    }
    return (ssize_t)bytes_read;
#else
    return pread(file->native_handle, buffer, size, (off_t)offset);
#endif
}

/** @brief Positioned write that leaves the file pointer untouched (pwrite on POSIX; OVERLAPPED WriteFile on Windows).
 * @param file Pointer to the opened file_t structure. @param buffer Data to write. @param size Number of bytes to
 * write. @param offset File offset to write to; must be >= 0. @return Bytes written on success, -1 on error (errno is
 * set). */
ssize_t file_pwrite(file_t* file, const void* buffer, size_t size, int64_t offset) {
    if (!buffer || size == 0 || offset < 0) {
        errno = EINVAL;
        return -1;
    }

#ifdef _WIN32
    OVERLAPPED ov = {.Offset = (DWORD)(offset & 0xFFFFFFFF), .OffsetHigh = (DWORD)(offset >> 32), .hEvent = NULL};

    DWORD bytes_written;
    if (!WriteFile(file->native_handle, buffer, (DWORD)size, &bytes_written, &ov)) {
        errno = EIO;
        return -1;
    }
    return (ssize_t)bytes_written;
#else
    return pwrite(file->native_handle, buffer, size, (off_t)offset);
#endif
}

/** @brief Reads the whole file into a malloc'd buffer, reading from offset 0 and restoring the original position
 * afterwards. POSIX regular files take an fstat+read fast path that skips stdio's extra copy; non-regular files fall
 * back to the fseek/fread path. @param file Pointer to the opened file_t structure. @param size_out Optional pointer to
 * store the number of bytes read. @return Allocated buffer the caller must free() (a valid 1-byte buffer for empty
 * files), or NULL on error with errno set. */
void* file_readall(file_t* file, size_t* size_out) {
    if (!file || !file->stream) {
        errno = EINVAL;
        return NULL;
    }

#ifndef _WIN32
    /*
     * Fast path (Perf #10): regular files are sized with fstat(2) and read
     * directly through the descriptor.  This skips the fseek/ftell/lseek
     * dance of the legacy path AND the full extra copy stdio's fread makes
     * into its internal buffer — for large files roughly a doubling of
     * effective read bandwidth.
     *
     * Falls back to the legacy stdio path for non-regular files (pipes,
     * /proc entries whose st_size is 0 despite content), where seeking is
     * required anyway.
     */
    struct stat fst;
    if (fstat(file->native_handle, &fst) == 0 && S_ISREG(fst.st_mode) && fst.st_size > 0) {
        int64_t orig_pos = lseek(file->native_handle, 0, SEEK_CUR);
        size_t want = (size_t)fst.st_size;

        void* buffer = malloc(want);
        if (!buffer) {
            errno = ENOMEM;
            return NULL;
        }

        /* Read from offset 0 regardless of the current position, matching
         * the legacy behaviour of rewind-then-read. */
        if (lseek(file->native_handle, 0, SEEK_SET) == (off_t)-1) {
            int saved = errno;
            free(buffer);
            if (orig_pos >= 0) lseek(file->native_handle, orig_pos, SEEK_SET);
            errno = saved;
            return NULL;
        }

        size_t total = 0;
        while (total < want) {
            ssize_t r = read(file->native_handle, (char*)buffer + total, want - total);
            if (r < 0) {
                if (errno == EINTR) continue;
                int saved = errno;
                free(buffer);
                if (orig_pos >= 0) lseek(file->native_handle, orig_pos, SEEK_SET);
                errno = saved;
                return NULL;
            }
            if (r == 0) break; /* file shrank concurrently: short read */
            total += (size_t)r;
        }

        if (orig_pos >= 0) {
            lseek(file->native_handle, orig_pos, SEEK_SET);
        }

        if (total != want) {
            free(buffer);
            errno = EIO; /* concurrent truncation mid-read */
            return NULL;
        }

        file->attr.size = want;
        if (size_out) *size_out = total;
        return buffer;
    }
#endif

    /* Save the caller's current stream position so we can restore it later. */
    int64_t orig_pos = file_tell(file);

    /* Seek to the end to get the actual, up-to-date byte count. */
    if (fseek(file->stream, 0, SEEK_END) != 0) {
        return NULL;
    }

    int64_t current_size = file_tell(file);
    if (current_size < 0) {
        /* Restore position on error and bail. */
        if (orig_pos >= 0) fseek(file->stream, (long)orig_pos, SEEK_SET);
        return NULL;
    }

    /* Rewind to the beginning before reading. */
    if (fseek(file->stream, 0, SEEK_SET) != 0) {
        if (orig_pos >= 0) fseek(file->stream, (long)orig_pos, SEEK_SET);
        return NULL;
    }

    if (current_size == 0) {
        if (size_out) *size_out = 0;
        /* Return a valid non-NULL pointer for zero-sized files */
        return malloc(1);
    }

    void* buffer = malloc((size_t)current_size);
    if (!buffer) {
        errno = ENOMEM;
        if (orig_pos >= 0) fseek(file->stream, (long)orig_pos, SEEK_SET);
        return NULL;
    }

    size_t bytes_read = file_read(file, buffer, 1, (size_t)current_size);

    /* Restore the original stream position (best-effort). */
    if (orig_pos >= 0) {
        fseek(file->stream, (long)orig_pos, SEEK_SET);
    }

    if (bytes_read != (size_t)current_size) {
        free(buffer);
        errno = ferror(file->stream) ? EIO : EINVAL;
        return NULL;
    }

    // Update attrs.size with most recent size after reading, since file could have changed since open
    file->attr.size = (size_t)current_size;

    if (size_out) {
        *size_out = bytes_read;
    }
    return buffer;
}

/** @brief Attempts a non-blocking exclusive advisory lock on the whole file (F_SETLK on POSIX, LockFileEx on Windows).
 * @param file Pointer to the opened file_t structure. @return FILE_SUCCESS if locked, FILE_ERROR_LOCK_FAILED if already
 * locked elsewhere, other error codes for system failures. */
file_result_t file_lock(const file_t* file) {
#ifdef _WIN32
    OVERLAPPED overlapped = {0};
    if (LockFileEx(file->native_handle, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, MAXDWORD, MAXDWORD,
                   &overlapped)) {
        return FILE_SUCCESS;
    }

    DWORD error = GetLastError();
    if (error == ERROR_LOCK_VIOLATION) {
        errno = EACCES;
        return FILE_ERROR_LOCK_FAILED;
    }
    errno = EIO;
    return FILE_ERROR_SYSTEM_ERROR;
#else
    struct flock fl = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0};

    if (fcntl(file->native_handle, F_SETLK, &fl) == 0) {
        return FILE_SUCCESS;
    }

    if (errno == EACCES || errno == EAGAIN) {
        return FILE_ERROR_LOCK_FAILED;
    }
    return FILE_ERROR_SYSTEM_ERROR;
#endif
}

/** @brief Releases the advisory lock taken by file_lock(); POSIX unlock of an unlocked file still succeeds. @param file
 * Pointer to the opened file_t structure. @return FILE_SUCCESS on success, FILE_ERROR_SYSTEM_ERROR otherwise. */
file_result_t file_unlock(const file_t* file) {
#ifdef _WIN32
    OVERLAPPED overlapped = {0};
    if (UnlockFileEx(file->native_handle, 0, MAXDWORD, MAXDWORD, &overlapped)) {
        return FILE_SUCCESS;
    }
    errno = EIO;
    return FILE_ERROR_SYSTEM_ERROR;
#else
    struct flock fl = {.l_type = F_UNLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0};

    if (fcntl(file->native_handle, F_SETLK, &fl) == 0) {
        return FILE_SUCCESS;
    }
    return FILE_ERROR_SYSTEM_ERROR;
#endif
}

/** @brief Copies from src's current position to EOF, appending at dst's current position, then flushes dst. On Linux
 * regular files it uses copy_file_range(2) inside the kernel (falling back on EXDEV/EOPNOTSUPP and friends before
 * anything is copied); otherwise a 64 KB read/write loop is used. @param src Source file (must be open for reading).
 * @param dst Destination file (must be open for writing). @return FILE_SUCCESS on success, appropriate error code
 * otherwise. */
file_result_t file_copy(const file_t* src, file_t* dst) {
    /*
     * Fast path (Perf #10): on Linux, copy_file_range(2) performs the copy
     * entirely inside the kernel — no bounce through user space, no stdio
     * buffers, and (on supporting filesystems) server-side/reflink copies.
     * Measured ~2x on NVMe for large regular files.
     *
     * Semantics preserved from the portable path: copy from the source's
     * CURRENT logical position to EOF, appending at the destination's
     * current position.  Both streams are resynchronised with their
     * descriptors first so raw-fd and FILE* positions agree.
     *
     * Any early failure of copy_file_range (cross-filesystem EXDEV,
     * EOPNOTSUPP on exotic fds, non-Linux) falls back to the portable
     * read/write loop below with nothing yet copied.
     */
#ifdef HAVE_COPY_FILE_RANGE
    if (src && dst && src->stream && dst->stream) {
        /* Discard stdio buffers and align fd positions with stream state. */
        fflush(dst->stream);
        clearerr(src->stream);
        clearerr(dst->stream);
        if (fseek(src->stream, 0, SEEK_CUR) != 0) {
            return FILE_ERROR_IO_FAILED;
        }

        struct stat sst;
        if (fstat(src->native_handle, &sst) != 0) {
            return FILE_ERROR_IO_FAILED;
        }
        off_t cur = lseek(src->native_handle, 0, SEEK_CUR);
        if (cur == (off_t)-1) {
            return FILE_ERROR_IO_FAILED;
        }

        /* Only take the fast path when "current position to EOF" is
         * well-defined (regular file) and there is something to do. */
        if (!S_ISREG(sst.st_mode)) {
            goto fallback;
        }
        off_t remaining = (off_t)sst.st_size - cur;
        if (remaining <= 0) {
            return FILE_SUCCESS;
        }

        /* Destination fd position is authoritative once its buffer is
         * flushed; make sure the FILE* agrees afterwards. */
        off_t dpos = lseek(dst->native_handle, 0, SEEK_CUR);
        if (dpos == (off_t)-1) {
            goto fallback;
        }

        off_t sent = 0;
        while (sent < remaining) {
            size_t chunk = (remaining - sent > (off_t)COPY_BUFSIZE) ? COPY_BUFSIZE : (size_t)(remaining - sent);
            ssize_t n = copy_file_range(src->native_handle, NULL, dst->native_handle, NULL, chunk, 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                if (sent == 0 &&
                    (errno == EXDEV || errno == EOPNOTSUPP || errno == EINVAL || errno == ENOSYS || errno == EBADF)) {
                    goto fallback; /* kernel/fs cannot help; nothing copied */
                }
                return FILE_ERROR_IO_FAILED;
            }
            if (n == 0) break; /* EOF earlier than st_size claimed */
            sent += n;
        }

        /* Realign the destination stream with what the kernel wrote. */
        if (fseek(dst->stream, dpos + sent, SEEK_SET) != 0) {
            return FILE_ERROR_IO_FAILED;
        }
        if (fflush(dst->stream) != 0) {
            return FILE_ERROR_IO_FAILED;
        }
        return FILE_SUCCESS;

    fallback:;
    }
#endif

    char buffer[COPY_BUFSIZE];
    size_t bytes_read = 0;

    // Clear any previous errors
    clearerr(src->stream);
    clearerr(dst->stream);

    while ((bytes_read = file_read(src, buffer, 1, COPY_BUFSIZE)) > 0) {
        if (file_write(dst, buffer, 1, bytes_read) != bytes_read) {
            return FILE_ERROR_IO_FAILED;
        }
    }

    // Check for read error
    if (ferror(src->stream)) {
        return FILE_ERROR_IO_FAILED;
    }

    // Flush destination
    if (fflush(dst->stream) != 0) {
        return FILE_ERROR_IO_FAILED;
    }

    return FILE_SUCCESS;
}

/** @brief Memory-maps @p length bytes from the start of the file (mmap MAP_SHARED on POSIX; CreateFileMapping +
 * MapViewOfFile on Windows). @param file Pointer to the opened file_t structure. @param length Number of bytes to map;
 * must be > 0. @param read_access Request read access to the mapping. @param write_access Request write access to the
 * mapping (at least one access flag must be set). @return Pointer to mapped memory on success, NULL on failure (errno
 * is set); release with file_munmap(). */
void* file_mmap(const file_t* file, size_t length, bool read_access, bool write_access) {
    if (length == 0 || (!read_access && !write_access)) {
        errno = EINVAL;
        return NULL;
    }

#ifdef _WIN32
    DWORD protect = write_access ? PAGE_READWRITE : PAGE_READONLY;
    DWORD access = write_access ? FILE_MAP_WRITE : FILE_MAP_READ;

    HANDLE mapping = CreateFileMapping(file->native_handle, NULL, protect, (DWORD)(length >> 32), (DWORD)length, NULL);
    if (!mapping) {
        errno = EIO;
        return NULL;
    }

    void* addr = MapViewOfFile(mapping, access, 0, 0, length);
    CloseHandle(mapping);

    if (!addr) {
        errno = EIO;
    }
    return addr;
#else
    int prot = 0;
    if (read_access) prot |= PROT_READ;
    if (write_access) prot |= PROT_WRITE;

    void* addr = mmap(NULL, length, prot, MAP_SHARED, file->native_handle, 0);
    return (addr == MAP_FAILED) ? NULL : addr;
#endif
}

/** @brief Unmaps a region previously returned by file_mmap(). @param addr Pointer to the mapped region. @param length
 * Length of the mapping (must match file_mmap; ignored on Windows). @return FILE_SUCCESS on success, an error code
 * otherwise. */
file_result_t file_munmap(void* addr, size_t length) {
    if (!addr) {
        return FILE_ERROR_INVALID_ARGS;
    }

#ifdef _WIN32
    (void)length;  // Unused on Windows
    return UnmapViewOfFile(addr) ? FILE_SUCCESS : FILE_ERROR_SYSTEM_ERROR;
#else
    return (munmap(addr, length) == 0) ? FILE_SUCCESS : FILE_ERROR_SYSTEM_ERROR;
#endif
}

/** @brief Flushes any buffered data to the underlying file. @param file Pointer to the opened file_t structure. @return
 * FILE_SUCCESS on success, FILE_ERROR_IO_FAILED otherwise. */
file_result_t file_flush(file_t* file) { return (fflush(file->stream) == 0) ? FILE_SUCCESS : FILE_ERROR_IO_FAILED; }

/** @brief Returns the current byte offset of the native handle, bypassing stdio buffering. @param file Pointer to the
 * opened file_t structure. @return Current position, or -1 on error (errno is set). */
int64_t file_tell(const file_t* file) {
#ifdef _WIN32
    LARGE_INTEGER zero = {0};
    LARGE_INTEGER pos;
    if (SetFilePointerEx(file->native_handle, zero, &pos, FILE_CURRENT)) {
        return (int64_t)pos.QuadPart;
    }
    errno = EIO;
    return -1;
#else
    off_t pos = lseek(file->native_handle, 0, SEEK_CUR);
    return (pos == (off_t)-1) ? -1 : (int64_t)pos;
#endif
}

/** @brief Flushes pending writes, seeks the native handle relative to @p whence, and resynchronises the FILE* position
 * with the descriptor. @param file Pointer to the opened file_t structure. @param offset Offset relative to whence.
 * @param whence SEEK_SET, SEEK_CUR or SEEK_END (anything else is EINVAL). @return FILE_SUCCESS on success, appropriate
 * error code otherwise. */
file_result_t file_seek(file_t* file, int64_t offset, int whence) {
    // Flush any pending writes before seeking
    if (fflush(file->stream) != 0) {
        return FILE_ERROR_IO_FAILED;
    }

#ifdef _WIN32
    DWORD move_method;
    switch (whence) {
        case SEEK_SET:
            move_method = FILE_BEGIN;
            break;
        case SEEK_CUR:
            move_method = FILE_CURRENT;
            break;
        case SEEK_END:
            move_method = FILE_END;
            break;
        default:
            errno = EINVAL;
            return FILE_ERROR_INVALID_ARGS;
    }

    LARGE_INTEGER li = {.QuadPart = offset};
    if (SetFilePointerEx(file->native_handle, li, NULL, move_method)) {
        // Sync the FILE* stream position
        fseek(file->stream, 0, SEEK_CUR);
        return FILE_SUCCESS;
    }
    errno = EIO;
    return FILE_ERROR_IO_FAILED;
#else
    if (lseek(file->native_handle, (off_t)offset, whence) == (off_t)-1) {
        return FILE_ERROR_IO_FAILED;  // errno already set
    }

    // Sync the FILE* stream position
    if (fseek(file->stream, 0, SEEK_CUR) != 0) {
        return FILE_ERROR_IO_FAILED;
    }

    return FILE_SUCCESS;
#endif
}

/* -------------------------------------------------------------------------
 * Cross-platform sendfile
 * ---------------------------------------------------------------------- */

/* -------------------------------------------------------------------------
 * Cross-platform sendfile
 *
 * Linux:   <sys/sendfile.h>  ssize_t sendfile(int out, int in, off_t *off, size_t n)
 * macOS:   <sys/socket.h>    int sendfile(int fd, int s, off_t off, off_t *len, struct sf_hdtr *hd, int flags)
 *          file \u2192 socket only; file\u2192file must use fallback/copyfile
 * FreeBSD: <sys/socket.h> + <sys/uio.h>  int sendfile(int fd, int s, off_t off, size_t n, struct sf_hdtr *hd, off_t
 * *sbytes, int flags)
 * ---------------------------------------------------------------------- */

#if defined(__linux__)
    #include <sys/sendfile.h>
#elif defined(__FreeBSD__) || defined(__APPLE__)
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <sys/uio.h>
#endif

/* Windows socket extension APIs (TransmitFile) are provided via
 * platform.h (winsock2 → mswsock → windows → ws2tcpip) which is
 * included transitively through file.h. No additional Windows
 * headers are needed here. */

/**
 * Fallback used when the OS has no native sendfile: pread from in_fd,
 * write to out_fd in stack chunks. Correct everywhere; not zero-copy.
 */
static int64_t file_sendfile_fallback(int out_fd, int in_fd, int64_t* offset, size_t count) {
    char buf[65536];
    size_t chunk = count < sizeof(buf) ? count : sizeof(buf);
#if defined(_WIN32)
    /* Windows: seek + read (no pread); save/restore the file position. */
    int64_t saved = _lseeki64(in_fd, 0, SEEK_CUR);
    if (_lseeki64(in_fd, *offset, SEEK_SET) < 0) return -1;
    int rb = (int)read(in_fd, buf, (unsigned)chunk);
    if (rb < 0) return -1;
    _lseeki64(in_fd, saved, SEEK_SET);
#else
    ssize_t rb = pread(in_fd, buf, chunk, *offset);
    if (rb < 0) return -1;
#endif
    if (rb == 0) return 0;

    size_t sent_total = 0;
    while (sent_total < (size_t)rb) {
#ifdef _WIN32
        int w = (int)send((SOCKET)(intptr_t)out_fd, buf + sent_total, (unsigned)(rb - sent_total), 0);
#else
        ssize_t w = write(out_fd, buf + sent_total, (size_t)rb - sent_total);
#endif
        if (w < 0) {
            if (errno == EINTR) continue;
            return (sent_total > 0) ? (int64_t)sent_total : -1;
        }
        sent_total += (size_t)w;
    }
    *offset += (int64_t)sent_total;
    return (int64_t)sent_total;
}

int64_t file_sendfile(int out_fd, int in_fd, int64_t* offset, size_t count) {
    if (!offset || count == 0) {
        errno = EINVAL;
        return -1;
    }

#if defined(__linux__)
    off_t off = (off_t)*offset;
    ssize_t sent = sendfile(out_fd, in_fd, &off, count);
    if (sent < 0) return -1;
    *offset = (int64_t)off;
    return (int64_t)sent;

#elif defined(__APPLE__)
    /* macOS sendfile only supports file \u2192 socket. For file\u2192file (or any
     * non-socket dest) it fails with ENOTSOCK/EINVAL. Fall back to the
     * portable pread+write loop in that case, which also handles the
     * required socket-only restriction transparently. */
    off_t len = (off_t)count;
    int r = sendfile(in_fd, out_fd, (off_t)*offset, &len, NULL, 0);
    if (r == -1) {
        if (errno == ENOTSOCK || errno == ENOTSUP || errno == EINVAL || errno == ENOTCONN || errno == EOPNOTSUPP) {
            return file_sendfile_fallback(out_fd, in_fd, offset, count);
        }
        if (errno != EAGAIN) return -1;
        /* EAGAIN: partial send happened; len reports how much. */
    }
    *offset += (int64_t)len;
    return (int64_t)len;

#elif defined(__FreeBSD__)
    off_t len = (off_t)count;
    int r = sendfile(in_fd, out_fd, (off_t)*offset, (size_t)count, NULL, &len, 0);
    if (r == -1 && errno != EAGAIN) return -1;
    *offset += (int64_t)len;
    return (int64_t)len;

#elif defined(_WIN32)
    /* TransmitFile sends from the file's CURRENT position, so seek first.
     * out_fd must be a SOCKET (cast by the caller from socket_fd()). */
    LARGE_INTEGER li;
    li.QuadPart = *offset;
    if (SetFilePointer((HANDLE)(intptr_t)in_fd, li.LowPart, &li.HighPart, FILE_BEGIN) == INVALID_SET_FILE_POINTER &&
        GetLastError() != NO_ERROR) {
        return -1;
    }
    if (count > 0xFFFFFFFEu) count = 0xFFFFFFFEu; /* TransmitFile documented max */
    if (!TransmitFile((SOCKET)(intptr_t)out_fd, (HANDLE)(intptr_t)in_fd, (DWORD)count, 0, NULL, NULL,
                      TF_USE_DEFAULT_WORKER)) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            errno = EAGAIN;
            return -1;
        }
        errno = EIO;
        return -1;
    }
    *offset += (int64_t)count;
    return (int64_t)count;

#else
    return file_sendfile_fallback(out_fd, in_fd, offset, count);
#endif
}
