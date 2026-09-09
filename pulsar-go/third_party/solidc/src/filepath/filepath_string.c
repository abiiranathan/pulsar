/**
 * @file filepath_string.c
 * @brief Pure string manipulation for file paths: separators, basename,
 *        dirname, extension, joining and splitting.
 *
 * Everything in this file is platform-independent: both '/' and '\\' are
 * accepted as separators on every platform so that foreign paths can be
 * reasoned about anywhere.
 */

#include "filepath_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/** @brief Bounds-safe string copy used across the filepath module: copies src into dst, always NUL-terminates, and
 * never writes more than size bytes. @return Number of characters copied (strnlen(src, size - 1)); 0 for NULL args or
 * size == 0. */
size_t fp_strlcpy(char* dst, const char* src, size_t size) {
    if (!dst || !src || size == 0) {
        return 0;
    }
    size_t n = strnlen(src, size - 1);
    memcpy(dst, src, n);
    dst[n] = '\0';
    return n;
}

/** Finds the last path separator ('/' or '\\') in a path, or NULL. */
static const char* last_separator(const char* path) {
    const char* sep = strrchr(path, '/');
    if (!sep) {
        sep = strrchr(path, '\\');
    }
    return sep;
}

// Get basename of path
/** @brief Copies the basename of path (everything after the final '/' or '\\') into basename; empty string if path ends
 * with a separator or arguments are invalid. Accepts both separators on every platform. */
void filepath_basename(const char* path, char* basename, size_t size) {
    if (!path || !basename || size == 0) {
        if (basename) basename[0] = '\0';
        return;
    }

    const char* base = last_separator(path);
    base = base ? base + 1 : path;
    fp_strlcpy(basename, base, size);
}

// Get dirname of path
/** @brief Copies the directory portion of path (everything before the final separator, without a trailing separator)
 * into dirname; empty string if path has no separator. */
void filepath_dirname(const char* path, char* dirname, size_t size) {
    if (!path || !dirname || size == 0) {
        if (dirname) dirname[0] = '\0';
        return;
    }

    const char* base = last_separator(path);
    if (!base) {
        dirname[0] = '\0';
    } else {
        size_t len = (size_t)(base - path);
        fp_strlcpy(dirname, path, len + 1 < size ? len + 1 : size);
    }
}

/*
 * Returns the extension of the BASENAME, including the dot, or "" if the
 * basename has none.  Two subtleties handled here:
 *   - The search must start AFTER the last separator, otherwise
 *     "/path/to.dir/file" would report ".dir/file".
 *   - A leading dot in the basename marks a hidden file ("~/.bashrc"),
 *     not an extension, so ".bashrc" yields "".
 * Multi-part names behave as expected: "archive.tar.gz" -> ".gz".
 */
/** @brief Copies the extension of the basename, including the dot, into ext (empty string if there is none). The search
 * starts after the last separator, and a leading dot on a hidden file (".bashrc") is not treated as an extension. */
void filepath_extension(const char* path, char* ext, size_t size) {
    if (!path || !ext || size == 0) {
        if (ext) ext[0] = '\0';
        return;
    }

    const char* base = last_separator(path);
    base = base ? base + 1 : path;

    const char* dot = strrchr(base, '.');
    if (!dot || dot == base) {
        ext[0] = '\0';
        return;
    }
    fp_strlcpy(ext, dot, size);
}

#define BASENAME_MAX 512

// Get filename without extension
/** @brief Copies the basename of path with its extension removed into name (truncated to fit size if necessary). */
void filepath_nameonly(const char* path, char* name, size_t size) {
    if (!path || !name || size == 0) {
        if (name) name[0] = '\0';
        return;
    }

    char base[BASENAME_MAX] = {0};
    filepath_basename(path, base, BASENAME_MAX);
    char* dot = strrchr(base, '.');

    size_t base_len = strnlen(base, BASENAME_MAX);
    size_t source_len = dot ? (size_t)(dot - base) : base_len;

    // Don't exceed destination size
    size_t to_copy = source_len < size - 1 ? source_len : size - 1;
    memcpy(name, base, to_copy);
    name[to_copy] = '\0';
}

// Join paths
/** @brief Joins path1 and path2 with the platform separator ('\\' when path1 already uses backslashes on Windows, '/'
 * elsewhere). @return Heap-allocated joined path, or NULL on NULL args or allocation failure (errno set). */
char* filepath_join(const char* path1, const char* path2) {
    if (!path1 || !path2) {
        errno = EINVAL;
        return NULL;
    }

    size_t len = strlen(path1) + strlen(path2) + 2;
    char* joined = (char*)malloc(len);
    if (!joined) {
        errno = ENOMEM;
        return NULL;
    }

#ifdef _WIN32
    snprintf(joined, len, "%s%s%s", path1, strchr(path1, '\\') ? "\\" : "/", path2);
#else
    snprintf(joined, len, "%s/%s", path1, path2);
#endif
    return joined;
}

/** @brief Buffer variant of filepath_join(): writes the joined path into abspath, NUL-terminated. @return true on
 * success; false on invalid args or truncation (errno EINVAL/ENAMETOOLONG). */
bool filepath_join_buf(const char* path1, const char* path2, char* abspath, size_t len) {
    if (!path1 || !path2 || !abspath || len == 0) {
        if (abspath && len > 0) abspath[0] = '\0';
        errno = EINVAL;
        return false;
    }

#ifdef _WIN32
    // On Windows, decide which separator to use based on what path1 already uses
    const char* sep = strchr(path1, '\\') ? "\\" : "/";
    int result = snprintf(abspath, len, "%s%s%s", path1, sep, path2);
#else
    int result = snprintf(abspath, len, "%s/%s", path1, path2);
#endif

    // Check for encoding error or truncation
    if (result < 0 || (size_t)result >= len) {
        // Ensure null-termination if truncated (snprintf does this, but good practice to be sure)
        abspath[len - 1] = '\0';
        errno = ENAMETOOLONG;
        return false;
    }

    return true;
}

// Split path into directory and filename
/** @brief Splits path at the last separator: dir gets the portion before it (no trailing separator) and name the
 * portion after; if there is no separator, dir is empty and name receives the whole path. */
void filepath_split(const char* path, char* dir, char* name, size_t dir_size, size_t name_size) {
    if (!path || !dir || !name || dir_size == 0 || name_size == 0) {
        if (dir) dir[0] = '\0';
        if (name) name[0] = '\0';
        return;
    }

    const char* p = last_separator(path);

    if (!p) {
        dir[0] = '\0';
        fp_strlcpy(name, path, name_size);
    } else {
        size_t len = (size_t)(p - path);
        fp_strlcpy(dir, path, len + 1 < dir_size ? len + 1 : dir_size);
        fp_strlcpy(name, p + 1, name_size);
    }
}
