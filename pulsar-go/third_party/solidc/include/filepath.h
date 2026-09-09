/**
 * @file filepath.h
 * @brief Cross-platform file path manipulation and directory traversal utilities.
 *
 * This module provides a unified API for file system operations across Windows
 * and POSIX platforms. All functions handle path separators appropriately for
 * the target platform.
 *
 * Thread Safety: Individual functions document their thread-safety guarantees.
 * Most functions are thread-safe unless otherwise noted.
 */

#ifndef DA20B33A_06DF_4AB0_8B0A_B8874A623312
#define DA20B33A_06DF_4AB0_8B0A_B8874A623312

#include "file.h"
#include "macros.h"
#include "platform.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef _WIN32
    #include "win32_dirent.h"
    // platform.h already included transitively via file.h / win32_dirent.h

    #ifndef _WIN32_WINNT
        #define _WIN32_WINNT 0x0400  // Required for syncapi
    #endif
    #define PATH_SEP     '\\'
    #define PATH_SEP_STR "\\"
#else
    #include <dirent.h>
    #include <pwd.h>
    #include <sys/mman.h>
    #include <sys/random.h>
    #include <sys/stat.h>
    #include <unistd.h>

    /** Platform-specific directory separator character. */
    #define PATH_SEP     '/'

    /** Platform-specific directory separator string. */
    #define PATH_SEP_STR "/"

    #ifndef MAX_PATH
        #define MAX_PATH 1024
    #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opaque directory handle for iterating directory contents.
 *
 * @note Not safe for concurrent use. Each thread should use its own handle.
 * @note Must be closed with dir_close() to prevent resource leaks.
 */
typedef struct {
    char* path; /**< Directory path being traversed. */
#ifdef _WIN32
    HANDLE handle;              /**< Windows directory search handle. */
    WIN32_FIND_DATAW find_data; /**< Current directory entry data. */
    char name_buf[MAX_PATH];    /**< Thread-safe name buffer. */
#else
    DIR* dir; /**< POSIX directory stream. */
#endif
} Directory;

/**
 * Opens a directory for reading.
 *
 * @param path Path to the directory to open. Must not be NULL or empty.
 * @return Directory handle on success, NULL on failure (sets errno).
 * @note Caller must call dir_close() to release resources.
 * @note Thread-safe: Each call returns an independent handle.
 */
WARN_UNUSED_RESULT Directory* dir_open(const char* path);

/**
 * Closes a directory handle and releases all associated resources.
 *
 * @param dir Directory handle to close. Safe to pass NULL.
 * @note Thread-safe with respect to other directories.
 */
void dir_close(Directory* dir);

/**
 * Reads the next entry in the directory.
 *
 * @param dir Directory handle returned by dir_open(). Must not be NULL.
 * @return Pointer to entry name, or NULL when no more entries or on error.
 * @note The returned pointer is valid only until the next call to dir_next()
 *       or dir_close() on the same handle.
 * @note Special entries "." and ".." are included in iteration.
 * @note Not thread-safe: Do not call on the same handle from multiple threads.
 */
WARN_UNUSED_RESULT char* dir_next(Directory* dir);

/**
 * Creates a new directory with default permissions.
 *
 * @param path Path of the directory to create. Must not be NULL.
 * @return 0 on success (or if directory already exists), -1 on error (sets errno).
 * @note On POSIX, creates with mode 0755. On Windows, uses default ACLs.
 * @note Does not create parent directories (use filepath_makedirs() for that).
 * @note Thread-safe.
 */
int dir_create(const char* path);

/**
 * Removes a directory.
 *
 * @param path Path to the directory to remove. Must not be NULL.
 * @param recursive If true, recursively removes all contents. If false, fails on non-empty directories.
 * @return 0 on success, -1 on error (sets errno).
 * @note Recursive removal uses depth-first post-order traversal.
 * @note Not safe for concurrent modification of the same directory tree.
 */
int dir_remove(const char* path, bool recursive);

/**
 * Renames or moves a directory.
 *
 * @param oldpath Current path of the directory. Must not be NULL.
 * @param newpath New path for the directory. Must not be NULL.
 * @return 0 on success, -1 on error (sets errno).
 * @note Behavior is platform-specific when newpath exists.
 * @note May fail if oldpath and newpath are on different filesystems.
 * @note Thread-safe.
 */
int dir_rename(const char* oldpath, const char* newpath);

/**
 * Changes the current working directory of the process.
 *
 * @param path Path to the new working directory. Must not be NULL.
 * @return 0 on success, -1 on error (sets errno).
 * @note Affects the entire process, not thread-local.
 * @note Not safe for concurrent use in multi-threaded programs.
 */
int dir_chdir(const char* path);

/**
 * Lists all entries in a directory.
 *
 * @param path Path to the directory. Must not be NULL.
 * @param count Pointer to store the number of entries. Must not be NULL.
 * @return Array of dynamically allocated entry names, or NULL on error (sets errno).
 * @note Caller must free each entry string and the array itself.
 * @note Includes "." and ".." entries.
 * @note Thread-safe.
 */
WARN_UNUSED_RESULT char** dir_list(const char* path, size_t* count);

/**
 * Iterates directory entries with a callback function.
 *
 * @param path Path to the directory. Must not be NULL.
 * @param callback Function called for each entry (excluding "." and ".."). Must not be NULL.
 * @note Callback receives the entry name. The pointer is valid only during the callback.
 * @note Thread-safe if callback is thread-safe.
 */
void dir_list_with_callback(const char* path, void (*callback)(const char* name));

/**
 * Checks if a path refers to a directory.
 *
 * @param path Path to check. Must not be NULL.
 * @return true if path exists and is a directory, false otherwise.
 * @note Follows symbolic links.
 * @note Thread-safe.
 */
bool is_dir(const char* path);

/**
 * Checks if a path refers to a regular file.
 *
 * @param path Path to check. Must not be NULL.
 * @return true if path exists and is a regular file, false otherwise.
 * @note Follows symbolic links.
 * @note Thread-safe.
 */
bool is_file(const char* path);

/**
 * Checks if a path is a symbolic link.
 *
 * @param path Path to check. Must not be NULL.
 * @return true if path is a symbolic link (POSIX only), false otherwise or on Windows.
 * @note Does not follow symbolic links (uses lstat on POSIX).
 * @note Always returns false on Windows.
 * @note Thread-safe.
 */
bool is_symlink(const char* path);

/**
 * Creates a directory and all necessary parent directories.
 *
 * @param path Path to create. Must not be NULL.
 * @return true on success (or if path already exists), false on error.
 * @note Similar to mkdir -p on Unix.
 * @note Thread-safe, but race conditions may occur with concurrent creation.
 */
bool filepath_makedirs(const char* path);

/**
 * Returns the path to the system's temporary directory.
 *
 * @return Dynamically allocated path string, or NULL on error.
 * @note On Windows, checks TEMP, then TMP environment variables, falls back to C:\Windows\Temp.
 * @note On POSIX, checks TMPDIR environment variable, falls back to /tmp.
 * @note Caller must free the returned string.
 * @note Thread-safe.
 */
WARN_UNUSED_RESULT char* get_tempdir(void);

/**
 * Creates a temporary file with a unique name.
 *
 * @return Dynamically allocated path to the created file, or NULL on error (sets errno).
 * @note File is created with restrictive permissions (0600 on POSIX).
 * @note Caller is responsible for deleting the file and freeing the path.
 * @note Thread-safe.
 */
WARN_UNUSED_RESULT char* make_tempfile(void);

/**
 * Creates a temporary directory with a unique name.
 *
 * @return Dynamically allocated path to the created directory, or NULL on error (sets errno).
 * @note Directory is created with default permissions.
 * @note Caller is responsible for removing the directory and freeing the path.
 * @note Thread-safe.
 */
WARN_UNUSED_RESULT char* make_tempdir(void);

/**
 * Control options for directory traversal callbacks.
 */
typedef enum WalkDirOption {
    DirContinue, /**< Continue walking the directory recursively. */
    DirStop,     /**< Stop traversal immediately and return from dir_walk. */
    DirSkip,     /**< Skip the current entry and its children (if directory). */
    DirError,    /**< An error occurred; stop traversal and return error. */
} WalkDirOption;

/**
 * Callback function type for directory walking.
 *
 * @param attr File attributes of the current entry. Never NULL.
 * @param path Full path to the entry. Valid only during callback invocation.
 * @param name Basename of the entry. Valid only during callback invocation.
 * @param data User-provided context pointer passed to dir_walk.
 * @return WalkDirOption to control traversal behavior.
 * @note Callback must not call dir_walk on the same path to avoid infinite recursion.
 */
typedef WalkDirOption (*WalkDirCallback)(const FileAttributes* attr, const char* path, const char* name, void* data);

/**
 * Walks a directory tree in breadth-first order.
 *
 * @param path Root directory to walk. Must not be NULL.
 * @param callback Function called for each entry. Must not be NULL.
 * @param data User context pointer passed to callback. May be NULL.
 * @return 0 on success, -1 on error (sets errno).
 * @note Entries "." and ".." are automatically skipped.
 * @note Callback is invoked before recursing into subdirectories.
 * @note Not safe for concurrent modification of the traversed tree.
 */
int dir_walk(const char* path, WalkDirCallback callback, void* data);

/**
 * Lazy file attributes for dir_walkx.
 *
 * On Linux, d_type from getdents64 is used to determine file type
 * without stat. Size/mtime are fetched lazily via fstatat only when
 * actually needed by the callback. This can save 90% of stat calls
 * when the callback only checks is_dir/is_file.
 *
 * Valid only during the callback invocation. Do not store the pointer.
 */
typedef struct LazyFileAttributes {
    int dirfd;             /**< Directory fd for lazy stat (internal) */
    const char* name;      /**< Entry name (internal) */
    unsigned char d_type;  /**< d_type from dirent (DT_* constants) */
    FileAttributes cached; /**< Cached full attributes */
    bool has_stat;         /**< Whether cached contains valid stat data */
    bool is_dir_cached;    /**< Whether is_dir is cached */
    bool is_dir_value;     /**< Cached is_dir result */
} LazyFileAttributes;

/**
 * Gets file attributes, performing lazy stat if needed.
 * @param lazy Lazy attributes handle. Must not be NULL.
 * @return Pointer to FileAttributes, or NULL on error.
 * @note Result is valid only during callback invocation.
 */
const FileAttributes* lazy_get_attrs(LazyFileAttributes* lazy);

/**
 * Fast check if entry is a directory without triggering stat if d_type is known.
 * @param lazy Lazy attributes handle. Must not be NULL.
 * @return true if directory, false otherwise.
 */
bool lazy_is_dir(LazyFileAttributes* lazy);

/**
 * Fast check if entry is a regular file without triggering stat if d_type is known.
 * @param lazy Lazy attributes handle. Must not be NULL.
 * @return true if regular file, false otherwise.
 */
bool lazy_is_file(LazyFileAttributes* lazy);

/**
 * Callback for lazy directory walking.
 */
typedef WalkDirOption (*WalkDirCallbackX)(LazyFileAttributes* lazy, const char* path, const char* name, void* data);

/**
 * Walks a directory tree with lazy attribute fetching (Linux optimized).
 *
 * Similar to dir_walk but uses lazy evaluation: FileAttributes are only
 * fetched via fstatat when the callback actually needs them (e.g., size,
 * mtime). If the callback only checks is_dir/is_file, no stat is performed
 * at all when d_type is available (which it is on 99% of modern Linux
 * filesystems: ext4, xfs, btrfs, tmpfs).
 *
 * This can be 2-5x faster than dir_walk when the callback does not need
 * full stat data, and 10-20% faster even when it does (due to fd-based
 * traversal and larger getdents buffer).
 *
 * Falls back to eager stat on kernels <2.6 or when d_type is DT_UNKNOWN.
 *
 * @param path Root directory to walk. Must not be NULL.
 * @param callback Function called for each entry. Must not be NULL.
 * @param data User context pointer passed to callback. May be NULL.
 * @return 0 on success, -1 on error (sets errno).
 */
int dir_walkx(const char* path, WalkDirCallbackX callback, void* data);

/**
 * Walks a directory tree in depth-first post-order.
 *
 * @param path Root directory to walk. Must not be NULL.
 * @param callback Function called for each entry. Must not be NULL.
 * @param data User context pointer passed to callback. May be NULL.
 * @return 0 on success, -1 on error (sets errno).
 * @note Callback is invoked AFTER recursing into subdirectories.
 * @note Suitable for operations like recursive deletion.
 * @note Not safe for concurrent modification of the traversed tree.
 */
int dir_walk_depth_first(const char* path, WalkDirCallback callback, void* data);

/**
 * Calculates the total size of all files in a directory tree.
 *
 * @param path Root directory to measure. Must not be NULL.
 * @return Total size in bytes on success, -1 on error (sets errno).
 * @note Walks the entire tree recursively; may be slow for large directories.
 * @note Only counts regular files, not directory metadata.
 * @note Thread-safe, but result may be stale in actively modified directories.
 */
ssize_t dir_size(const char* path);

/**
 * Checks if a path exists in the filesystem.
 *
 * @param path Path to check. Must not be NULL.
 * @return true if path exists (file, directory, or other), false otherwise.
 * @note Follows symbolic links.
 * @note Thread-safe.
 */
bool path_exists(const char* path);

/**
 * Returns the current working directory path.
 *
 * @return Dynamically allocated path string, or NULL on error (sets errno).
 * @note Caller must free the returned string.
 * @note Thread-safe.
 */
WARN_UNUSED_RESULT char* get_cwd(void);

/**
 * Extracts the basename (filename with extension) from a path.
 *
 * @param path Full path to parse. Must not be NULL.
 * @param basename Buffer to store the result. Must not be NULL.
 * @param size Size of the basename buffer.
 * @note Handles both forward and backslashes as separators.
 * @note If path ends with a separator, returns empty string.
 * @note Thread-safe.
 */
void filepath_basename(const char* path, char* basename, size_t size);

/**
 * Extracts the directory portion of a path.
 *
 * @param path Full path to parse. Must not be NULL.
 * @param dirname Buffer to store the result. Must not be NULL.
 * @param size Size of the dirname buffer.
 * @note Returns empty string if path has no directory component.
 * @note Does not include trailing separator.
 * @note Thread-safe.
 */
void filepath_dirname(const char* path, char* dirname, size_t size);

/**
 * Extracts the file extension including the leading dot.
 *
 * @param path Full path to parse. Must not be NULL.
 * @param ext Buffer to store the result. Must not be NULL.
 * @param size Size of the ext buffer.
 * @note Returns empty string if no extension exists.
 * @note Extension includes the dot (e.g., ".txt").
 * @note Thread-safe.
 */
void filepath_extension(const char* path, char* ext, size_t size);

/**
 * Extracts the filename without extension.
 *
 * @param path Full path to parse. Must not be NULL.
 * @param name Buffer to store the result. Must not be NULL.
 * @param size Size of the name buffer.
 * @note Returns the basename with the extension removed.
 * @note Thread-safe.
 */
void filepath_nameonly(const char* path, char* name, size_t size);

/**
 * Converts a path to an absolute path.
 *
 * @param path Path to convert (may be relative or absolute). Must not be NULL.
 * @return Dynamically allocated absolute path, or NULL on error (sets errno).
 * @note Resolves ".", "..", and symbolic links (on POSIX).
 * @note Caller must free the returned string.
 * @note Thread-safe.
 */
WARN_UNUSED_RESULT char* filepath_absolute(const char* path);

/**
 * Deletes a file or empty directory.
 *
 * @param path Path to remove. Must not be NULL.
 * @return 0 on success, -1 on error (sets errno).
 * @note Fails on non-empty directories (use dir_remove with recursive=true).
 * @note Thread-safe.
 */
int filepath_remove(const char* path);

/**
 * Renames or moves a file or directory.
 *
 * @param oldpath Current path. Must not be NULL.
 * @param newpath New path. Must not be NULL.
 * @return 0 on success, -1 on error (sets errno).
 * @note May fail if paths are on different filesystems.
 * @note Behavior when newpath exists is platform-specific.
 * @note Thread-safe.
 */
int filepath_rename(const char* oldpath, const char* newpath);

/**
 * Returns the user's home directory path.
 *
 * @return Pointer to home directory string, or NULL if not found.
 * @note On Windows, returns USERPROFILE environment variable.
 * @note On POSIX, returns HOME environment variable.
 * @note The returned pointer must NOT be freed (points to environment).
 * @note Thread-safe if environment is not being modified.
 */
const char* user_home_dir(void);

/**
 * Expands tilde (~) in a path to the user's home directory.
 *
 * @param path Path potentially starting with ~. Must not be NULL.
 * @return Dynamically allocated expanded path, or NULL on error.
 * @note Only expands leading ~, not embedded tildes.
 * @note Returns copy of path unchanged if it doesn't start with ~.
 * @note Caller must free the returned string.
 * @note Thread-safe.
 */
WARN_UNUSED_RESULT char* filepath_expanduser(const char* path);

/**
 * Expands tilde (~) in a path to the user's home directory into a buffer.
 *
 * @param path Path potentially starting with ~. Must not be NULL.
 * @param expanded Buffer to store the expanded path. Must not be NULL.
 * @param len Size of the expanded buffer.
 * @return true on success, false if buffer too small or home directory not found.
 * @note Thread-safe.
 */
bool filepath_expanduser_buf(const char* path, char* expanded, size_t len);

/**
 * Joins two path components with the platform-specific separator.
 *
 * @param path1 First path component. Must not be NULL.
 * @param path2 Second path component. Must not be NULL.
 * @return Dynamically allocated joined path, or NULL on error (sets errno).
 * @note Uses backslash on Windows, forward slash on POSIX.
 * @note Caller must free the returned string.
 * @note Thread-safe.
 */
WARN_UNUSED_RESULT char* filepath_join(const char* path1, const char* path2);

/**
 * Joins two path components into a provided buffer.
 *
 * @param path1 First path component. Must not be NULL.
 * @param path2 Second path component. Must not be NULL.
 * @param abspath Buffer to store the result. Must not be NULL.
 * @param len Size of the abspath buffer.
 * @return true on success, false if buffer too small.
 * @note Thread-safe.
 */
bool filepath_join_buf(const char* path1, const char* path2, char* abspath, size_t len);

/**
 * Splits a file path into directory and basename components.
 *
 * @param path Path to split. Must not be NULL.
 * @param dir Buffer to store the directory portion. Must not be NULL.
 * @param name Buffer to store the basename. Must not be NULL.
 * @param dir_size Size of the dir buffer.
 * @param name_size Size of the name buffer.
 * @note If path has no directory, dir is set to empty string.
 * @note Thread-safe.
 */
void filepath_split(const char* path, char* dir, char* name, size_t dir_size, size_t name_size);

#ifdef __cplusplus
}
#endif

#endif /* DA20B33A_06DF_4AB0_8B0A_B8874A623312 */
