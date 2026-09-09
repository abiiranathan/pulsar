/**
 * @file file.h
 * @brief Cross-platform file handling API with synchronous and asynchronous I/O support.
 */
#ifndef SOLIDC_FILE_H
#define SOLIDC_FILE_H

#if !defined(_POSIX_C_SOURCE) && !defined(_WIN32) && !defined(__APPLE__)
    #define _POSIX_C_SOURCE   200809L  // For fstat, fileno, pwrite, pread, fcntl, etc.
    #define _FILE_OFFSET_BITS 64       // Ensure 64-bit off_t on 32-bit POSIX systems
#endif

#include "platform.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Platform detection and feature setup
#ifdef _WIN32
    #include <io.h>

    // ssize_t and Windows headers (winsock2 → mswsock → windows → ws2tcpip)
    // are provided by platform.h in the correct order.

    // Define ssize_t for Windows if not already defined
    #if defined(_MSC_VER) && !defined(_SSIZE_T_DEFINED)
typedef intptr_t ssize_t;
        #define _SSIZE_T_DEFINED
    #endif

// Windows-specific file handle type
typedef HANDLE native_handle_t;
    #define INVALID_NATIVE_HANDLE INVALID_HANDLE_VALUE

#else  // POSIX systems

    #include <fcntl.h>
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <unistd.h>

// POSIX file handle type
typedef int native_handle_t;

enum { INVALID_NATIVE_HANDLE = (-1) };
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** File attribute flags bitmask */
typedef enum FileAttrFlags {
    FATTR_NONE = 0,            /**< No attributes set */
    FATTR_FILE = 1 << 0,       /**< Regular file */
    FATTR_DIR = 1 << 1,        /**< Directory */
    FATTR_SYMLINK = 1 << 2,    /**< Symbolic link */
    FATTR_CHARDEV = 1 << 3,    /**< Character device */
    FATTR_BLOCKDEV = 1 << 4,   /**< Block device */
    FATTR_FIFO = 1 << 5,       /**< Named pipe (FIFO) */
    FATTR_SOCKET = 1 << 6,     /**< Socket */
    FATTR_HIDDEN = 1 << 7,     /**< Hidden file (starts with '.') */
    FATTR_EXECUTABLE = 1 << 8, /**< This is an executable file */
} FileAttrFlags;

/** Represents file attributes for directory traversal */
typedef struct FileAttributes {
    /** Bitmask of FileAttrFlags */
    uint32_t attrs;

    /** File size in bytes (0 for directories and special files) */
    size_t size;

    /** Last modification time (Unix timestamp) */
    time_t mtime;
} FileAttributes;

/**
 * Checks if a file has a specific attribute flag.
 * @param attr File attributes structure.
 * @param flag The flag to check (from FileAttrFlags).
 * @return true if the flag is set, false otherwise.
 */
static inline bool fattr_has(const FileAttributes* attr, FileAttrFlags flag) { return (attr->attrs & flag) != 0; }

/**
 * Checks if the file is a regular file.
 * @param attr File attributes structure.
 * @return true if file is a regular file, false otherwise.
 */
static inline bool fattr_is_file(const FileAttributes* attr) { return (attr->attrs & FATTR_FILE) != 0; }

/**
 * Checks if the file is a directory.
 * @param attr File attributes structure.
 * @return true if file is a directory, false otherwise.
 */
static inline bool fattr_is_dir(const FileAttributes* attr) { return (attr->attrs & FATTR_DIR) != 0; }

/**
 * Checks if the file is a symbolic link.
 * @param attr File attributes structure.
 * @return true if file is a symbolic link, false otherwise.
 */
static inline bool fattr_is_symlink(const FileAttributes* attr) { return (attr->attrs & FATTR_SYMLINK) != 0; }

/**
 * Checks if the file is an I/O device (character or block device).
 * @param attr File attributes structure.
 * @return true if file is a device, false otherwise.
 */
static inline bool fattr_is_device(const FileAttributes* attr) {
    return (attr->attrs & (FATTR_CHARDEV | FATTR_BLOCKDEV)) != 0;
}

/**
 * Populates FileAttributes structure from a file path (POSIX implementation).
 * @param path Full path to the file.
 * @param name Basename of the file.
 * @param attr Output FileAttributes structure to populate.
 * @return 0 on success, -1 on error (errno is set).
 */
int populate_file_attrs(const char* path, FileAttributes* attr);

/**
 * Cross-platform file structure.
 * Encapsulates both high-level (FILE*) and low-level (native handle) operations.
 * Optimized to minimize memory footprint while maintaining functionality.
 */
typedef struct {
    FILE* stream;                  /**< Standard C file stream for buffered I/O. */
    FileAttributes attr;           // File attributes
    native_handle_t native_handle; /**< Platform-native file handle for direct operations. */
} file_t;

/** File operation result codes. */
typedef enum {
    FILE_SUCCESS = 0,         /**< Operation completed successfully. */
    FILE_ERROR_INVALID_ARGS,  /**< Invalid arguments provided. */
    FILE_ERROR_OPEN_FAILED,   /**< File open operation failed. */
    FILE_ERROR_IO_FAILED,     /**< I/O operation failed. */
    FILE_ERROR_LOCK_FAILED,   /**< File locking operation failed. */
    FILE_ERROR_MEMORY_FAILED, /**< Memory allocation failed. */
    FILE_ERROR_SYSTEM_ERROR   /**< System-specific error occurred. */
} file_result_t;

/**
 * Opens a file and populates the file_t structure.
 *
 * @param file Pointer to file_t structure to initialize.
 * @param filename Path to the file to open.
 * @param mode Mode string (e.g., "r", "wb+", "a"). See fopen documentation.
 * @return FILE_SUCCESS on success, appropriate error code otherwise.
 * @note Sets errno on failure. The file structure is zeroed on failure.
 */
file_result_t file_open(file_t* file, const char* filename, const char* mode);

/**
 * Closes the file and releases all associated resources.
 * Safe to call multiple times or on uninitialized structures.
 *
 * @param file Pointer to the file_t structure.
 */
void file_close(file_t* file);

/**
 * Truncates or extends the file to the specified length.
 * File must be opened with write permissions.
 *
 * @param file Pointer to the opened file_t structure.
 * @param length Desired file length in bytes.
 * @return FILE_SUCCESS on success, appropriate error code otherwise.
 */
file_result_t file_truncate(file_t* file, int64_t length);

/**
 * Converts a file size to a human-readable string representation.
 *
 * @param size File size in bytes.
 * @param buf Buffer to store the formatted string.
 * @param len Size of the buffer.
 * @return FILE_SUCCESS on success, FILE_ERROR_INVALID_ARGS if buffer too small.
 */
file_result_t filesize_tostring(uint64_t size, char* buf, size_t len);

/**
 * Reads data from the file using buffered I/O.
 *
 * @param file Pointer to the opened file_t structure.
 * @param buffer Buffer to store read data.
 * @param size Size of each element.
 * @param count Number of elements to read.
 * @return Number of elements successfully read. Use feof/ferror for status.
 */
size_t file_read(const file_t* file, void* buffer, size_t size, size_t count);

/**
 * Writes data to the file using buffered I/O.
 * Does not automatically flush the stream.
 *
 * @param file Pointer to the opened file_t structure.
 * @param buffer Data to write.
 * @param size Size of each element.
 * @param count Number of elements to write.
 * @return Number of elements successfully written. Use ferror for status.
 */
size_t file_write(file_t* file, const void* buffer, size_t size, size_t count);

/**
 * Writes a null-terminated string to the file (excluding null terminator).
 *
 * @param file Pointer to the opened file_t structure.
 * @param str Null-terminated string to write.
 * @return Number of bytes written on success, 0 if str is NULL or empty.
 */
size_t file_write_string(file_t* file, const char* str);

/**
 * Performs positioned read without affecting the file pointer.
 * This is atomic on POSIX systems and simulated on Windows.
 *
 * @param file Pointer to the opened file_t structure.
 * @param buffer Buffer to store read data.
 * @param size Number of bytes to read.
 * @param offset File offset to read from.
 * @return Number of bytes read on success, -1 on error (errno is set).
 */
ssize_t file_pread(const file_t* file, void* buffer, size_t size, int64_t offset);

/**
 * Performs positioned write without affecting the file pointer.
 * This is atomic on POSIX systems and simulated on Windows.
 *
 * @param file Pointer to the opened file_t structure.
 * @param buffer Data to write.
 * @param size Number of bytes to write.
 * @param offset File offset to write to.
 * @return Number of bytes written on success, -1 on error (errno is set).
 */
ssize_t file_pwrite(file_t* file, const void* buffer, size_t size, int64_t offset);

/**
 * Reads the entire file content into a newly allocated buffer.
 * The file position is reset to the beginning before reading.
 *
 * @param file Pointer to the opened file_t structure.
 * @param size_out Optional pointer to store the file size read.
 * @return Allocated buffer containing file content, or NULL on error.
 * @note Caller must free() the returned buffer. Sets errno on failure.
 */
void* file_readall(file_t* file, size_t* size_out);

/**
 * Attempts to acquire an exclusive advisory lock on the entire file.
 * The lock is non-blocking and will fail immediately if unavailable.
 *
 * @param file Pointer to the opened file_t structure.
 * @return FILE_SUCCESS if locked, FILE_ERROR_LOCK_FAILED if already locked,
 *         other error codes for system failures.
 */
file_result_t file_lock(const file_t* file);

/**
 * Releases an advisory lock on the file.
 * Safe to call on files that are not locked.
 *
 * @param file Pointer to the opened file_t structure.
 * @return FILE_SUCCESS on success, appropriate error code otherwise.
 */
file_result_t file_unlock(const file_t* file);

/**
 * Copies content from source file to destination file.
 * Reads from current position of source until EOF.
 * Flushes destination after copying.
 *
 * @param src Source file (must be open for reading).
 * @param dst Destination file (must be open for writing).
 * @return FILE_SUCCESS on success, appropriate error code otherwise.
 */
file_result_t file_copy(const file_t* src, file_t* dst);

/**
 * Memory maps a portion of the file starting from the beginning.
 *
 * @param file Pointer to the opened file_t structure.
 * @param length Number of bytes to map.
 * @param read_access Request read access to the mapping.
 * @param write_access Request write access to the mapping.
 * @return Pointer to mapped memory on success, NULL on failure (errno is set).
 * @note Use file_munmap() to release the mapping.
 */
void* file_mmap(const file_t* file, size_t length, bool read_access, bool write_access);

/**
 * Unmaps a previously memory-mapped region.
 *
 * @param addr Pointer to the mapped region (from file_mmap).
 * @param length Length of the mapping (must match file_mmap parameter).
 * @return FILE_SUCCESS on success, FILE_ERROR_INVALID_ARGS on failure.
 */
file_result_t file_munmap(void* addr, size_t length);

/**
 * Flushes any buffered data to the underlying file.
 *
 * @param file Pointer to the opened file_t structure.
 * @return FILE_SUCCESS on success, FILE_ERROR_IO_FAILED otherwise.
 */
file_result_t file_flush(file_t* file);

/**
 * Gets the current file position.
 *
 * @param file Pointer to the opened file_t structure.
 * @return Current file position, or -1 on error (errno is set).
 */
int64_t file_tell(const file_t* file);

/**
 * Sets the file position.
 *
 * @param file Pointer to the opened file_t structure.
 * @param offset Offset relative to whence.
 * @param whence Position reference (SEEK_SET, SEEK_CUR, SEEK_END).
 * @return FILE_SUCCESS on success, FILE_ERROR_IO_FAILED otherwise.
 */
file_result_t file_seek(file_t* file, int64_t offset, int whence);

/**
 * @brief Zero-copy file-to-descriptor transfer (cross-platform sendfile).
 *
 * Copies up to @p count bytes from @p in_fd starting at @p *offset directly
 * to @p out_fd without routing through user space, where the OS supports it:
 *
 *   Linux        sendfile(2)
 *   macOS        sendfile (header into socket; Apple variant)
 *   FreeBSD      sendfile (with NULL header/trailer)
 *   Windows      TransmitFile (out must be a SOCKET)
 *   Fallback     pread + write loop (portable, always correct)
 *
 * @param[in,out] out_fd Destination descriptor. On POSIX any writable
 *                descriptor (typically a socket fd from socket_fd()); on
 *                Windows this must be a SOCKET handle cast to int.
 * @param[in] in_fd Source regular-file descriptor.
 * @param[in,out] offset Start offset into in_fd; advanced by the number of
 *                bytes actually sent. Never touches in_fd's file position.
 * @param[in] count Maximum bytes to send.
 * @return Number of bytes sent (> 0), 0 if the source is exhausted
 *         (offset at EOF), or -1 on error (errno set).
 *
 * @note May send fewer bytes than requested — non-blocking sockets and
 *       kernel limits both cause partial sends. Loop until it returns 0 or
 *       your file offset reaches EOF. EAGAIN from a non-blocking socket is
 *       reported as -1 with errno == EAGAIN; pair with a poller write
 *       event and resume from the updated *offset.
 *
 * @code
 *   int64_t off = 0;
 *   int64_t sent;
 *   while ((sent = file_sendfile(sock_fd, file_fd, &off, remaining)) > 0)
 *       remaining -= (size_t)sent;
 * @endcode
 */
int64_t file_sendfile(int out_fd, int in_fd, int64_t* offset, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* SOLIDC_FILE_H */
