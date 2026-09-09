/**
 * @file filepath.c
 * @brief Portable (platform-neutral) filepath and directory operations.
 *
 * This translation unit hosts every function whose logic does not depend on
 * OS APIs. Anything touching syscalls or Win32 lives in the per-platform
 * backends:
 *
 *   - src/filepath/filepath_posix.c  (Linux/macOS/BSD, incl. Linux fast path)
 *   - src/filepath/filepath_win32.c  (Win32)
 *
 * The contract between the two sides is defined in filepath_internal.h.
 */

#include "filepath_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
    #include <direct.h>
#endif

// Generate a random string for temporary file/directory names.
// len must be < 64 bytes.
/*
 * Thread-safety notes: entropy is provided by fp_random_bytes() which is
 * implemented per platform. On Linux it is getrandom(2), which is
 * thread-safe and requires no shared state, so no locking is done at all —
 * the earlier version held a mutex across the syscall (pure contention) and
 * initialised it with a check-then-act pattern that could double-initialise
 * under concurrency (Bug #9). Other platforms keep their own locking inside
 * the backend.
 */
/** @brief Generates a random NUL-terminated name of len characters drawn from [A-Za-z0-9] via fp_random_bytes(); len
 * must be < 64. On entropy failure str is set to an empty string. Thread-safe (no shared state). */
void fp_random_name(char* str, size_t len) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const size_t charset_size = sizeof(charset) - 1;  // Exclude null terminator

    unsigned char buffer[64];  // Buffer for random bytes (sufficient for typical len)

    // Ensure we don't write beyond requested length
    size_t bytes_needed = len < 64 ? len : 64;

    if (!fp_random_bytes(buffer, bytes_needed)) {
        str[0] = '\0';  // Fallback to empty string on error
        return;
    }

    // Convert random bytes to characters from charset
    for (size_t i = 0; i < len; i++) {
        str[i] = charset[buffer[i % bytes_needed] % charset_size];
    }
    str[len] = '\0';
}

/** @brief dir_size() traversal callback: accumulates the size of each regular file into the ssize_t pointed to by data;
 * stops on NULL attr/data. */
static inline WalkDirOption dir_size_callback(const FileAttributes* attr, const char* path, const char* name,
                                              void* data) {
    (void)path;
    (void)name;

    if (!attr || !data) {
        return DirStop;
    }

    if (fattr_is_file(attr)) {
        ssize_t* size = (ssize_t*)data;
        *size += attr->size;
    }
    return DirContinue;
}

// Get directory size
/** @brief Computes the total size in bytes of all regular files in the tree rooted at path, via dir_walk(). @return
 * Total size on success, -1 on error (errno set). */
ssize_t dir_size(const char* path) {
    if (!path || *path == '\0') {
        errno = EINVAL;
        return -1;
    }

    ssize_t size = 0;
    if (dir_walk(path, dir_size_callback, &size) != 0) {
        return -1;
    }
    return size;
}

// Create directories recursively
/** @brief Creates path and every missing parent component (mkdir -p semantics), accepting both '/' and '\\' separators.
 * @return true on success or if path already exists, false on error (errno set). */
bool filepath_makedirs(const char* path) {
    if (!path || *path == '\0') {
        errno = EINVAL;
        return false;
    }

    char* temp_path = strdup(path);
    if (!temp_path) {
        errno = ENOMEM;
        return false;
    }

    char* p = temp_path;
    while (*p != '\0') {
        while (*p == '/' || *p == '\\') {
            p++;
        }
        while (*p != '\0' && *p != '/' && *p != '\\') {
            p++;
        }

        char old = *p;
        *p = '\0';

        if (*temp_path != '\0') {
            if (dir_create(temp_path) != 0) {
                free(temp_path);
                return false;
            }
        }

        *p = old;
        if (*p != '\0') {
            p++;
        }
    }

    free(temp_path);
    return true;
}

// Make a temporary file
/** @brief Builds "<tempdir>/<random prefix>XXXXXX" and creates the file via fp_create_tempfile() (mode 0600 on POSIX).
 * @return Heap-allocated path of the created file, or NULL on error (errno set); caller frees the path and deletes the
 * file. */
char* make_tempfile(void) {
    char* tmpdir = get_tempdir();
    if (!tmpdir) {
        return NULL;
    }

    char pattern[FP_TEMP_PREFIX_LEN + 7] = {0};
    fp_random_name(pattern, FP_TEMP_PREFIX_LEN);
    fp_strlcpy(pattern + FP_TEMP_PREFIX_LEN, "XXXXXX", 7);

    char* tmpfile = filepath_join(tmpdir, pattern);
    free(tmpdir);
    if (!tmpfile) {
        errno = ENOMEM;
        return NULL;
    }

    return fp_create_tempfile(tmpfile);
}

// Make a temporary directory
/** @brief Builds "<tempdir>/<random prefix>XXXXXX" and creates the directory via fp_create_tempdir(). @return
 * Heap-allocated path of the created directory, or NULL on error (errno set); caller frees the path and removes the
 * directory. */
char* make_tempdir(void) {
    char* tmpdir = get_tempdir();
    if (!tmpdir) {
        return NULL;
    }

    char pattern[FP_TEMP_PREFIX_LEN + 7] = {0};
    fp_random_name(pattern, FP_TEMP_PREFIX_LEN);
    fp_strlcpy(pattern + FP_TEMP_PREFIX_LEN, "XXXXXX", 7);

    char* tmp = filepath_join(tmpdir, pattern);
    free(tmpdir);
    if (!tmp) {
        errno = ENOMEM;
        return NULL;
    }

    return fp_create_tempdir(tmp);
}

// Remove a directory, with optional recursive deletion
// When recursive is true, deletes all files, subdirectories, and symbolic links (POSIX)
// within path, including empty subdirectories. Does not affect parent directories,
// as the walk skips "." and "..".
/** @brief Removes a directory. When recursive, contents are deleted depth-first (post-order, "." and ".." skipped)
 * before removing the root itself. @return 0 on success, -1 on error (errno set). */
int dir_remove(const char* path, bool recursive) {
    if (!path || *path == '\0') {
        errno = EINVAL;
        return -1;
    }

    if (recursive) {
        if (dir_walk_depth_first(path, fp_dir_remove_entry, NULL) != 0) {
            return -1;
        };
        // fallthrough and remove root directory.
    }
    return fp_remove_single_directory(path);
}

// Rename a directory
/** @brief Renames or moves a directory via rename(2). @return 0 on success, -1 on error (errno set). */
int dir_rename(const char* oldpath, const char* newpath) {
    if (!oldpath || !newpath || *oldpath == '\0' || *newpath == '\0') {
        errno = EINVAL;
        return -1;
    }
    return rename(oldpath, newpath);
}

// Change the current working directory
/** @brief Changes the process-wide current working directory via chdir(2). @return 0 on success, -1 on error (errno
 * set). */
int dir_chdir(const char* path) {
    if (!path || *path == '\0') {
        errno = EINVAL;
        return -1;
    }
#ifdef _WIN32
    return _chdir(path);
#else
    return chdir(path);
#endif
}

// List files in a directory with unified error handling
/** @brief Lists every entry of a directory, including "." and "..". @return Heap array of *count allocated name
 * strings, or NULL on error (errno set); caller frees each name and the array. */
char** dir_list(const char* path, size_t* count) {
    if (!path || !count || *path == '\0') {
        errno = EINVAL;
        return NULL;
    }

    Directory* dir = NULL;
    char** list = NULL;
    size_t size = 0;
    size_t capacity = 10;
    char* name = NULL;

    dir = dir_open(path);
    if (!dir) return NULL;

    list = (char**)calloc(capacity, sizeof(char*));
    if (!list) {
        goto error;
    }

    while ((name = dir_next(dir)) != NULL) {
        if (size >= capacity) {
            capacity *= 2;
            char** tmp = (char**)realloc(list, capacity * sizeof(char*));
            if (!tmp) {
                goto error;
            }
            list = tmp;
        }

        list[size] = strdup(name);
        if (!list[size]) {
            goto error;
        }
        size++;
    }

    dir_close(dir);
    *count = size;
    return list;

error:
    if (list) {
        // Free all successfully duplicated names
        for (size_t i = 0; i < size; i++) {
            free(list[i]);
        }
        free(list);
    }

    if (dir) dir_close(dir);

    return NULL;
}

// List files with callback
/** @brief Invokes callback for each entry of path except "." and ".."; silently returns if arguments are invalid or the
 * directory cannot be opened. */
void dir_list_with_callback(const char* path, void (*callback)(const char* name)) {
    if (!path || !callback || *path == '\0') return;

    Directory* dir = dir_open(path);
    if (!dir) {
        return;
    }

    char* name = NULL;
    while ((name = dir_next(dir)) != NULL) {
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }
        callback(name);
    }

    dir_close(dir);
}

// Fast checks that avoid stat when d_type is known (Linux); otherwise they
// fall back to lazy stat via lazy_get_attrs().
/** @brief Directory check for lazy walks: uses cached d_type when known (Linux), else one cached stat via
 * lazy_get_attrs(). @return true if the entry is a directory (result memoised in lazy). */
bool lazy_is_dir(LazyFileAttributes* lazy) {
    if (!lazy) return false;
    if (lazy->is_dir_cached) return lazy->is_dir_value;
#ifdef __linux__
    if (lazy->d_type != DT_UNKNOWN) {
        bool is_dir = (lazy->d_type == DT_DIR);
        lazy->is_dir_cached = true;
        lazy->is_dir_value = is_dir;
        return is_dir;
    }
#endif
    const FileAttributes* attr = lazy_get_attrs(lazy);
    if (!attr) return false;
    bool is_dir = fattr_is_dir(attr);
    lazy->is_dir_cached = true;
    lazy->is_dir_value = is_dir;
    return is_dir;
}

/** @brief Regular-file check for lazy walks: trusts d_type when known (Linux), falling back to a stat via
 * lazy_get_attrs(). @return true if the entry is a regular file. */
bool lazy_is_file(LazyFileAttributes* lazy) {
    if (!lazy) return false;
#ifdef __linux__
    if (lazy->d_type != DT_UNKNOWN) {
        return lazy->d_type == DT_REG;
    }
#endif
    const FileAttributes* attr = lazy_get_attrs(lazy);
    if (!attr) return false;
    return fattr_is_file(attr);
}

/** @brief Recursively walks a directory tree breadth-first, invoking callback for each entry before recursing into
 * subdirectories. @param path Starting directory path. @param callback Function to call for each directory entry.
 * @param data User-provided data passed to callback. @return 0 on success, -1 on error (errno is set). */
int dir_walk(const char* path, WalkDirCallback callback, void* data) { return fp_dir_walk_impl(path, callback, data); }

/** @brief Recursively walks a directory tree depth-first (post-order): entries are processed after their children,
 * which suits operations like recursive deletion where a directory must be emptied before removal. @param path Starting
 * directory path. @param callback Function to call for each directory entry. @param data User-provided data passed to
 * callback. @return 0 on success, -1 on error (errno is set). */
int dir_walk_depth_first(const char* path, WalkDirCallback callback, void* data) {
    if (!path || !callback || *path == '\0') {
        errno = EINVAL;
        return -1;
    }
    return fp_dir_walk_depth_first_impl(path, callback, data);
}

/** @brief Walks a directory tree with lazy attribute fetching, dispatching to fp_dir_walkx_impl() (Linux
 * getdents64/fstatat fast path; full stat only when the callback needs size/mtime). @return 0 on success, -1 on error
 * (errno set). */
int dir_walkx(const char* path, WalkDirCallbackX callback, void* data) {
    if (!path || !callback || *path == '\0') {
        errno = EINVAL;
        return -1;
    }
    return fp_dir_walkx_impl(path, callback, data);
}

// Rename a file
/** @brief Renames or moves a file (or directory) via rename(2). @return 0 on success, -1 on error (errno set). */
int filepath_rename(const char* oldpath, const char* newpath) {
    if (!oldpath || !newpath || *oldpath == '\0' || *newpath == '\0') {
        errno = EINVAL;
        return -1;
    }
    return rename(oldpath, newpath);
}

// Expand user home directory
/** @brief Expands a leading '~' to the user's home directory: bare "~" or "~/"/"~\\" collapse to home itself,
 * "~<suffix>" becomes "<home>/<suffix>", and paths not starting with '~' are returned unchanged as a copy. @return
 * Heap-allocated expanded path, or NULL on error (EINVAL/ENOENT/ENOMEM). */
char* filepath_expanduser(const char* path) {
    if (!path) {
        errno = EINVAL;
        return NULL;
    }

    if (path[0] != '~') {
        return strdup(path);
    }

    const char* home = user_home_dir();
    if (!home) {
        errno = ENOENT;
        return NULL;
    }

    size_t pathLen = strlen(path);
    bool isHome = pathLen == 1 || (pathLen == 2 && (path[1] == '/' || path[1] == '\\'));
    if (isHome) {
        return strdup(home);
    }

    size_t len = strlen(home) + pathLen + 1;
    char* expanded = (char*)malloc(len);
    if (!expanded) {
        errno = ENOMEM;
        return NULL;
    }

    const char* suffix = path + 1;
    // Skip leading separator after ~
    if (*suffix == '/' || *suffix == '\\') {
        suffix++;
    }
    snprintf(expanded, len, "%s%c%s", home, PATH_SEP, suffix);
    return expanded;
}

// Expand user home directory into buffer
/** @brief Buffer variant of filepath_expanduser(): writes the expanded (or verbatim) path into expanded, always
 * NUL-terminated. @return true on success; false if arguments are invalid, HOME is unset, or the result does not fit
 * (errno EINVAL/ENOENT/ENAMETOOLONG). */
bool filepath_expanduser_buf(const char* path, char* expanded, size_t len) {
    if (!path || !expanded || len == 0) {
        if (expanded) expanded[0] = '\0';
        errno = EINVAL;
        return false;
    }

    if (path[0] != '~') {
        return fp_strlcpy(expanded, path, len) < len;
    }

    const char* home = user_home_dir();
    if (!home) {
        errno = ENOENT;
        return false;
    }

    size_t pathLen = strlen(path);
    bool isHome = pathLen == 1 || (pathLen == 2 && (path[1] == '/' || path[1] == '\\'));
    if (isHome) {
        return fp_strlcpy(expanded, home, len) < len;
    }

    size_t homeLen = strlen(home);
    if (homeLen + pathLen + 1 > len) {
        errno = ENAMETOOLONG;
        return false;
    }

#ifdef _WIN32
    snprintf(expanded, len, "%s%s%s", home, path[1] == '\\' ? "\\" : "/", path + 1);
#else
    snprintf(expanded, len, "%s/%s", home, path + 1);
#endif
    return true;
}
