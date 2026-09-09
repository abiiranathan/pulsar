/**
 * @file filepath_posix.c
 * @brief POSIX (Linux/macOS/BSD) implementation of the filepath backends.
 *
 * Contains all POSIX-specific filesystem primitives: opendir/readdir based
 * directory access, stat-based attribute mapping, and — on Linux — an
 * optimized getdents64 + openat + fstatat fast path for directory walks.
 */

#include "filepath_internal.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../../include/lock.h"

#ifdef __linux__
    #include <sys/syscall.h>
    #include <sys/utsname.h>

    // Linux getdents64 structures
    #ifndef SYS_getdents64
        #define SYS_getdents64 217
    #endif

struct linux_dirent64 {
    ino64_t d_ino;
    off64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

// Kernel version check for fast path
/** @brief Compares the running kernel version against want_major.want_minor, caching the result after the first uname()
 * call. Used to gate Linux fast-path traversal features. @return 1 if the running kernel is at least the requested
 * version, 0 otherwise (including uname failure). */
static int kernel_version_ge(int want_major, int want_minor) {
    static int cached_result = -1;
    struct utsname u;
    int major = 0, minor = 0;

    if (cached_result != -1) {
        return cached_result;
    }

    if (uname(&u) != 0) {
        cached_result = 0;
        return 0;
    }

    sscanf(u.release, "%d.%d", &major, &minor);

    if (major > want_major) {
        cached_result = 1;
    } else if (major == want_major && minor >= want_minor) {
        cached_result = 1;
    } else {
        cached_result = 0;
    }
    return cached_result;
}

/** @brief True when getdents64 + openat + fstatat are available (kernel >= 2.6), enabling the fast directory-walk path.
 */
static inline int has_fast_dirent(void) {
    // getdents64 + openat + fstatat available since 2.6.16, d_type reliable since 2.6
    // statx available since 4.11
    return kernel_version_ge(2, 6);
}

/** @brief True when statx is available (kernel >= 4.11); reserved for future attribute queries. */
static inline int has_statx(void) { return kernel_version_ge(4, 11); }
#endif /* __linux__ */

/* ---------------------------------------------------------------------------
 * Entropy
 * ------------------------------------------------------------------------- */

/** @brief Fills buf with n cryptographically random bytes. On Linux uses getrandom(2) (thread-safe, no locking);
 * elsewhere opens /dev/urandom per call under a once-initialised lock. @return true on success, false if fewer than n
 * bytes could be read. */
bool fp_random_bytes(unsigned char* buf, size_t n) {
#ifdef __linux__
    /* Kernel-provided, thread-safe, no descriptor churn. */
    ssize_t bytes_read = getrandom(buf, n, 0);
    if (bytes_read != (ssize_t)n) {
        return false;
    }
#else
    /*
     * Thread-safety: /dev/urandom needs per-call open/close; guard it with a
     * lock whose initialiser uses an atomic exchange so exactly one thread
     * ever runs lock_init.
     */
    static Lock rand_lock;
    static atomic_int initialized = 0;

    if (!atomic_exchange(&initialized, 1)) {
        lock_init(&rand_lock);
    }

    lock_acquire(&rand_lock);
    ssize_t bytes_read = -1;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        bytes_read = read(fd, buf, n);
        close(fd);
    }
    if (bytes_read != (ssize_t)n) {
        lock_release(&rand_lock);
        return false;
    }
    lock_release(&rand_lock);
#endif
    return true;
}

/* ---------------------------------------------------------------------------
 * Directory handles
 * ------------------------------------------------------------------------- */

// Open a directory
/** @brief opendir() backend: allocates a Directory handle wrapping the DIR stream plus a copy of path. @return Handle
 * on success; NULL on invalid input or failure with errno preserved from opendir()/allocation. */
Directory* dir_open(const char* path) {
    if (!path || *path == '\0') {
        errno = EINVAL;
        return NULL;
    }

    Directory* dir = (Directory*)calloc(1, sizeof(Directory));
    if (!dir) {
        errno = ENOMEM;
        return NULL;
    }

    dir->path = strdup(path);
    if (!dir->path) {
        free(dir);
        errno = ENOMEM;
        return NULL;
    }

    dir->dir = opendir(path);
    if (!dir->dir) {
        int saved_errno = errno;
        free(dir->path);
        free(dir);
        errno = saved_errno;
        return NULL;
    }
    return dir;
}

// Close a directory
/** @brief closedir() backend: closes the stream and frees the handle. Safe to pass NULL. */
void dir_close(Directory* dir) {
    if (!dir) return;

    if (dir->dir) {
        closedir(dir->dir);
    }
    free(dir->path);
    free(dir);
}

// Read the next entry in the directory
/** @brief readdir() backend: advances the stream. @return Pointer to the entry name owned by the DIR stream (valid only
 * until the next call to dir_next()/dir_close()), or NULL at end of directory. */
char* dir_next(Directory* dir) {
    if (!dir) {
        errno = EINVAL;
        return NULL;
    }

    struct dirent* entry = readdir(dir->dir);
    if (entry) {
        return entry->d_name;
    }
    return NULL;
}

/* ---------------------------------------------------------------------------
 * Attribute mapping
 * ------------------------------------------------------------------------- */

/** @brief Maps lstat() results for one dirent into FileAttributes: size, mtime, hidden flag (leading '.'), and
 * S_*-derived type bits (regular + executable, dir, symlink, char/block device, FIFO, socket); directory sizes are
 * forced to 0. @return 0 on success, -1 if lstat fails. */
static int map_dirent_attrs(const struct dirent* entry, const char* path, FileAttributes* attr) {
    struct stat st;
    if (lstat(path, &st) != 0) return -1;

    attr->size = (size_t)st.st_size;
    attr->mtime = st.st_mtime;
    attr->attrs = FATTR_NONE;

    // Check for hidden file based on name
    if (entry->d_name[0] == '.') {
        attr->attrs |= FATTR_HIDDEN;
    }

    // Use standard POSIX macros on st_mode instead of non-standard DT_ constants
    if (S_ISREG(st.st_mode)) {
        attr->attrs |= FATTR_FILE;
        // Optional: Check executable bits here if needed
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
    else if (S_ISCHR(st.st_mode)) {
        attr->attrs |= FATTR_CHARDEV;
    }
#endif
#ifdef S_ISBLK
    else if (S_ISBLK(st.st_mode)) {
        attr->attrs |= FATTR_BLOCKDEV;
    }
#endif
#ifdef S_ISFIFO
    else if (S_ISFIFO(st.st_mode)) {
        attr->attrs |= FATTR_FIFO;
    }
#endif
#ifdef S_ISSOCK
    else if (S_ISSOCK(st.st_mode)) {
        attr->attrs |= FATTR_SOCKET;
    }
#endif
    return 0;
}

/** @brief Returns full FileAttributes for a lazily walked entry: on first use performs fstatat(dirfd, name,
 * AT_SYMLINK_NOFOLLOW) against the walk's directory fd and caches the result in lazy->cached; subsequent calls return
 * the cache directly. @return Pointer to the cached attributes (valid only during the callback invocation), or NULL on
 * stat failure or NULL input. */
const FileAttributes* lazy_get_attrs(LazyFileAttributes* lazy) {
    if (!lazy) {
        errno = EINVAL;
        return NULL;
    }
    if (lazy->has_stat) {
        return &lazy->cached;
    }
#ifdef __linux__
    struct stat st;
    if (fstatat(lazy->dirfd, lazy->name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        return NULL;
    }
    lazy->cached.size = (size_t)st.st_size;
    lazy->cached.mtime = st.st_mtime;
    lazy->cached.attrs = FATTR_NONE;
    if (lazy->name[0] == '.') {
        lazy->cached.attrs |= FATTR_HIDDEN;
    }
    if (S_ISREG(st.st_mode)) {
        lazy->cached.attrs |= FATTR_FILE;
        if (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) {
            lazy->cached.attrs |= FATTR_EXECUTABLE;
        }
    } else if (S_ISDIR(st.st_mode)) {
        lazy->cached.attrs |= FATTR_DIR;
        lazy->cached.size = 0;
    } else if (S_ISLNK(st.st_mode)) {
        lazy->cached.attrs |= FATTR_SYMLINK;
    }
    #ifdef S_ISCHR
    else if (S_ISCHR(st.st_mode)) {
        lazy->cached.attrs |= FATTR_CHARDEV;
    }
    #endif
    #ifdef S_ISBLK
    else if (S_ISBLK(st.st_mode)) {
        lazy->cached.attrs |= FATTR_BLOCKDEV;
    }
    #endif
    #ifdef S_ISFIFO
    else if (S_ISFIFO(st.st_mode)) {
        lazy->cached.attrs |= FATTR_FIFO;
    }
    #endif
    #ifdef S_ISSOCK
    else if (S_ISSOCK(st.st_mode)) {
        lazy->cached.attrs |= FATTR_SOCKET;
    }
    #endif
#else
    // Fallback for non-Linux POSIX: use lstat on the full fd-relative path is
    // not portable without fstatat, so callers on other platforms always pass
    // has_stat = true. Guard anyway in case of direct use.
    struct stat st;
    if (fstatat(lazy->dirfd, lazy->name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        return NULL;
    }
    lazy->cached.size = (size_t)st.st_size;
    lazy->cached.mtime = st.st_mtime;
    lazy->cached.attrs = FATTR_NONE;
    if (lazy->name[0] == '.') lazy->cached.attrs |= FATTR_HIDDEN;
    if (S_ISREG(st.st_mode)) {
        lazy->cached.attrs |= FATTR_FILE;
        if (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) lazy->cached.attrs |= FATTR_EXECUTABLE;
    } else if (S_ISDIR(st.st_mode)) {
        lazy->cached.attrs |= FATTR_DIR;
        lazy->cached.size = 0;
    } else if (S_ISLNK(st.st_mode)) {
        lazy->cached.attrs |= FATTR_SYMLINK;
    }
#endif
    lazy->has_stat = true;
    return &lazy->cached;
}

/* ---------------------------------------------------------------------------
 * Path queries and simple operations
 * ------------------------------------------------------------------------- */

// Check if path is a directory
/** @brief stat()-based directory check; follows symbolic links. @return true if path exists and is a directory. */
bool is_dir(const char* path) {
    if (!path || *path == '\0') {
        return false;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    }
    return S_ISDIR(st.st_mode);
}

// Check if path is a file
/** @brief stat()-based regular-file check; follows symbolic links. @return true if path exists and is a regular file.
 */
bool is_file(const char* path) {
    if (!path || *path == '\0') {
        return false;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    }
    return S_ISREG(st.st_mode);
}

// Check if path is a symbolic link
/** @brief lstat()-based symlink check; does not follow the final component. @return true if path itself is a symbolic
 * link. */
bool is_symlink(const char* path) {
    if (!path || *path == '\0') {
        return false;
    }

    struct stat st;
    if (lstat(path, &st) != 0) {
        return false;
    }
    return S_ISLNK(st.st_mode);
}

// Check if path exists
/** @brief Existence check for any filesystem object via stat() (follows symlinks). @return true if stat succeeds; false
 * on missing path or NULL/empty input (EINVAL). */
bool path_exists(const char* path) {
    if (!path || *path == '\0') {
        errno = EINVAL;
        return false;
    }

    struct stat st;
    return stat(path, &st) == 0;
}

// Create a directory
/** @brief mkdir(path, 0755) backend. @return 0 on success or when the directory already exists (EEXIST); -1 on other
 * errors (errno set). */
int dir_create(const char* path) {
    if (!path || *path == '\0') {
        errno = EINVAL;
        return -1;
    }

    if (mkdir(path, 0755) == -1) {
        if (errno == EEXIST) {
            return 0;
        }
        return -1;
    }
    return 0;
}

/** @brief Removes a single empty directory via rmdir(); contents are handled by callers. @return 0 on success, -1 on
 * error (errno set by rmdir). */
int fp_remove_single_directory(const char* path) {
    if (rmdir(path) == -1) {
        return -1;
    }
    return 0;
}

// Get temporary directory
/** @brief Resolves the temporary directory from $TMPDIR, falling back to /tmp when unset. @return Heap-allocated copy
 * of the directory path, or NULL on allocation failure (ENOMEM). */
char* get_tempdir(void) {
    const char* temp = GETENV("TMPDIR");
    if (!temp) {
        temp = "/tmp";
    }
    char* result = strdup(temp);
    if (!result) {
        errno = ENOMEM;
        return NULL;
    }
    return result;
}

/** @brief Turns candidate (a path ending in "XXXXXX") into a unique file via mkstemp() and closes the descriptor. Takes
 * ownership of candidate. @return candidate holding the final path on success; NULL (with candidate freed) on failure.
 */
char* fp_create_tempfile(char* candidate) {
    int fd = mkstemp(candidate);
    if (fd == -1) {
        free(candidate);
        return NULL;
    }
    close(fd);
    return candidate;
}

/** @brief Turns candidate (a path ending in "XXXXXX") into a unique directory via mkdtemp(). Takes ownership of
 * candidate. @return candidate holding the final path on success; NULL (with candidate freed) on failure. */
char* fp_create_tempdir(char* candidate) {
    if (mkdtemp(candidate) == NULL) {
        free(candidate);
        return NULL;
    }
    return candidate;
}

// Get absolute path
/** @brief realpath() backend: resolves path to a canonical absolute path, following symlinks and resolving "." / ".."
 * components. @return Heap-allocated absolute path, or NULL on error (errno set). */
char* filepath_absolute(const char* path) {
    if (!path || *path == '\0') {
        errno = EINVAL;
        return NULL;
    }

    char* abs = realpath(path, NULL);
    if (!abs) {
        return NULL;
    }
    return abs;
}

// Get current working directory
/** @brief getcwd(NULL, 0) backend: allocates a buffer of the exact size. @return Heap-allocated current working
 * directory, or NULL on error (ENOMEM). */
char* get_cwd(void) {
    char* cwd = getcwd(NULL, 0);
    if (!cwd) {
        errno = ENOMEM;
        return NULL;
    }
    return cwd;
}

// Remove a file
/** @brief unlink() backend: deletes a file (not directories). @return 0 on success, -1 on error (errno set). */
int filepath_remove(const char* path) {
    if (!path || *path == '\0') {
        errno = EINVAL;
        return -1;
    }

    return unlink(path);
}

// Get user home directory
// Get user home directory
/** @brief Returns $HOME as the user's home directory. @return Pointer into the environment (must not be freed or
 * modified), or NULL if HOME is unset. */
const char* user_home_dir(void) { return GETENV("HOME"); }

/** @brief Deletion callback for fp_dir_walk_depth_first_impl(): rmdir()s empty directories and unlink()s files during
 * post-order traversal, returning DirError on failure with errno already set by the syscall. */
WalkDirOption fp_dir_remove_entry(const FileAttributes* attr, const char* path, const char* name, void* data) {
    (void)data;
    (void)name;

    if (!attr || !path) {
        errno = EINVAL;
        return DirError;
    }

    if (fattr_is_dir(attr)) {
        if (rmdir(path) != 0) {
            return DirError;  // errno already set by rmdir
        }
    } else {
        if (unlink(path) != 0) {
            return DirError;  // errno already set by unlink
        }
    }
    return DirContinue;
}

/* ---------------------------------------------------------------------------
 * Linux fast-path traversal (getdents64 + fstatat + openat)
 *
 * This avoids path string construction for stat and uses the kernel's
 * d_type where possible.
 * ------------------------------------------------------------------------- */

#ifdef __linux__

// Fast attribute mapping using fstatat (fd-relative, avoids full path walk)
/** @brief Fast-path attribute mapping: fstatat(dirfd, name, AT_SYMLINK_NOFOLLOW) stats the entry relative to the walk's
 * directory fd, avoiding full-path reconstruction; fills size/mtime/hidden/type bits exactly like map_dirent_attrs().
 * d_type is ignored in favour of the definitive stat mode. @return 0 on success, -1 if fstatat fails. */
static int fast_map_attrs(int dirfd, const char* name, unsigned char d_type, FileAttributes* attr) {
    struct stat st;
    // For type determination, d_type is often sufficient and avoids stat
    // But we still need size/mtime for FileAttributes, so we need stat
    // However, for directories, size is always 0, so we could avoid stat
    // if we only need is_dir. For now, use fstatat which is faster than
    // lstat with full path.
    (void)d_type;

    if (fstatat(dirfd, name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
        return -1;
    }

    attr->size = (size_t)st.st_size;
    attr->mtime = st.st_mtime;
    attr->attrs = FATTR_NONE;

    if (name[0] == '.') {
        attr->attrs |= FATTR_HIDDEN;
    }

    // Use stat result for definitive type (more reliable than d_type)
    if (S_ISREG(st.st_mode)) {
        attr->attrs |= FATTR_FILE;
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
    else if (S_ISCHR(st.st_mode)) {
        attr->attrs |= FATTR_CHARDEV;
    }
    #endif
    #ifdef S_ISBLK
    else if (S_ISBLK(st.st_mode)) {
        attr->attrs |= FATTR_BLOCKDEV;
    }
    #endif
    #ifdef S_ISFIFO
    else if (S_ISFIFO(st.st_mode)) {
        attr->attrs |= FATTR_FIFO;
    }
    #endif
    #ifdef S_ISSOCK
    else if (S_ISSOCK(st.st_mode)) {
        attr->attrs |= FATTR_SOCKET;
    }
    #endif
    return 0;
}

/** @brief True only for "." and ".."; cheaper than two strcmp() calls in the getdents64 hot loop. */
static inline bool fast_is_dot_entry(const char* name) {
    return name[0] == '.' && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

// Optimized dir_walk helper using fd-based traversal and getdents64
/** @brief Recursive breadth-first walker over a directory fd: batches entries with getdents64 into a 64 KB buffer
 * (fewer syscalls), stats via fast_map_attrs(), recurses into subdirectories with openat(), and honours DirStop
 * (success), DirSkip and DirError. Unreadable/unstatable entries are skipped; openat failures other than
 * EACCES/ENOENT/ELOOP abort. Depth is capped at FP_MAX_DIR_DEPTH (ELOOP). @return 0 on success, -1 on error. */
static int dir_walk_fast_helper(const char* path, int dirfd, WalkDirCallback callback, void* data, int depth) {
    if (depth > FP_MAX_DIR_DEPTH) {
        errno = ELOOP;
        return -1;
    }

    // Use getdents64 directly with large buffer (64KB for fewer syscalls)
    char buf[64 * 1024];
    size_t path_len = strlen(path);

    int status = 0;
    char fullpath[FILENAME_MAX];

    while (1) {
        long nread = syscall(SYS_getdents64, dirfd, buf, sizeof(buf));
        if (nread == -1) {
            return -1;
        }
        if (nread == 0) break;

        for (long bpos = 0; bpos < nread;) {
            struct linux_dirent64* d = (struct linux_dirent64*)(buf + bpos);

            if (!fast_is_dot_entry(d->d_name)) {
                size_t name_len = strlen(d->d_name);
                if (path_len + 1 + name_len + 1 > sizeof(fullpath)) {
                    status = -1;
                    break;
                }
                memcpy(fullpath, path, path_len);
                fullpath[path_len] = '/';
                memcpy(fullpath + path_len + 1, d->d_name, name_len + 1);

                FileAttributes attr;
                if (fast_map_attrs(dirfd, d->d_name, d->d_type, &attr) != 0) {
                    // Skip unreadable entries
                    bpos += d->d_reclen;
                    continue;
                }

                WalkDirOption opt = callback(&attr, fullpath, d->d_name, data);
                if (opt == DirStop) {
                    return 0;
                }
                if (opt == DirError) {
                    return -1;
                }
                if (opt == DirSkip) {
                    bpos += d->d_reclen;
                    continue;
                }

                if (fattr_is_dir(&attr)) {
                    int child_fd = openat(dirfd, d->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                    if (child_fd >= 0) {
                        if (dir_walk_fast_helper(fullpath, child_fd, callback, data, depth + 1) != 0) {
                            close(child_fd);
                            return -1;
                        }
                        close(child_fd);
                    } else if (errno != EACCES && errno != ENOENT) {
                        // Only fail on unexpected errors
                        if (errno == ELOOP) return -1;
                    }
                }
            }
            bpos += d->d_reclen;
        }
        if (status != 0) break;
    }
    return status;
}

/** @brief Post-order counterpart of dir_walk_fast_helper(): recurses into subdirectories before invoking the callback
 * (so children are deleted before their parent), and re-stats a directory after recursion since the callback may have
 * modified or removed it. Honours DirStop/DirError; depth capped at FP_MAX_DIR_DEPTH (ELOOP). @return 0 on success, -1
 * on error. */
static int dir_walk_depth_first_fast_helper(const char* path, int dirfd, WalkDirCallback callback, void* data,
                                            int depth) {
    if (depth > FP_MAX_DIR_DEPTH) {
        errno = ELOOP;
        return -1;
    }

    char buf[64 * 1024];
    size_t path_len = strlen(path);

    int status = 0;
    char fullpath[FILENAME_MAX];

    while (1) {
        long nread = syscall(SYS_getdents64, dirfd, buf, sizeof(buf));
        if (nread == -1) return -1;
        if (nread == 0) break;

        for (long bpos = 0; bpos < nread;) {
            struct linux_dirent64* d = (struct linux_dirent64*)(buf + bpos);

            if (!fast_is_dot_entry(d->d_name)) {
                size_t name_len = strlen(d->d_name);
                if (path_len + 1 + name_len + 1 > sizeof(fullpath)) {
                    status = -1;
                    break;
                }
                memcpy(fullpath, path, path_len);
                fullpath[path_len] = '/';
                memcpy(fullpath + path_len + 1, d->d_name, name_len + 1);

                FileAttributes attr;
                if (fast_map_attrs(dirfd, d->d_name, d->d_type, &attr) != 0) {
                    bpos += d->d_reclen;
                    continue;
                }

                if (fattr_is_dir(&attr)) {
                    int child_fd = openat(dirfd, d->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                    if (child_fd >= 0) {
                        if (dir_walk_depth_first_fast_helper(fullpath, child_fd, callback, data, depth + 1) != 0) {
                            close(child_fd);
                            status = -1;
                            break;
                        }
                        close(child_fd);
                        // Re-stat after recursion as directory may have been modified
                        if (fast_map_attrs(dirfd, d->d_name, d->d_type, &attr) != 0) {
                            bpos += d->d_reclen;
                            continue;
                        }
                    }
                }

                WalkDirOption opt = callback(&attr, fullpath, d->d_name, data);
                if (opt == DirStop) return 0;
                if (opt == DirError) return -1;
            }
            bpos += d->d_reclen;
        }
        if (status != 0) break;
    }
    return status;
}

/** @brief Lazy variant of the fast walker: hands each entry a zero-stat LazyFileAttributes (d_type straight from
 * getdents64, FATTR_HIDDEN pre-set) so callbacks checking only lazy_is_dir/lazy_is_file never trigger fstatat. Recurses
 * into directories via openat(); honours DirStop/DirSkip/DirError; depth capped at FP_MAX_DIR_DEPTH (ELOOP). @return 0
 * on success, -1 on getdents/open failure. */
static int dir_walkx_fast_helper(const char* path, int dirfd, WalkDirCallbackX callback, void* data, int depth) {
    if (depth > FP_MAX_DIR_DEPTH) {
        errno = ELOOP;
        return -1;
    }

    char buf[64 * 1024];
    size_t path_len = strlen(path);
    char fullpath[FILENAME_MAX];

    while (1) {
        long nread = syscall(SYS_getdents64, dirfd, buf, sizeof(buf));
        if (nread == -1) return -1;
        if (nread == 0) break;

        for (long bpos = 0; bpos < nread;) {
            struct linux_dirent64* d = (struct linux_dirent64*)(buf + bpos);

            if (!fast_is_dot_entry(d->d_name)) {
                size_t name_len = strlen(d->d_name);
                if (path_len + 1 + name_len + 1 > sizeof(fullpath)) {
                    bpos += d->d_reclen;
                    continue;
                }
                memcpy(fullpath, path, path_len);
                fullpath[path_len] = '/';
                memcpy(fullpath + path_len + 1, d->d_name, name_len + 1);

                LazyFileAttributes lazy = {
                    .dirfd = dirfd,
                    .name = d->d_name,
                    .d_type = d->d_type,
                    .has_stat = false,
                    .is_dir_cached = false,
                };
                if (d->d_name[0] == '.') {
                    lazy.cached.attrs = FATTR_HIDDEN;
                }

                WalkDirOption opt = callback(&lazy, fullpath, d->d_name, data);
                if (opt == DirStop) return 0;
                if (opt == DirError) return -1;
                if (opt == DirSkip) {
                    bpos += d->d_reclen;
                    continue;
                }

                if (lazy_is_dir(&lazy)) {
                    int child_fd = openat(dirfd, d->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                    if (child_fd >= 0) {
                        if (dir_walkx_fast_helper(fullpath, child_fd, callback, data, depth + 1) != 0) {
                            close(child_fd);
                            return -1;
                        }
                        close(child_fd);
                    }
                }
            }
            bpos += d->d_reclen;
        }
    }
    return 0;
}

#endif /* __linux__ */

/* ---------------------------------------------------------------------------
 * Generic (readdir-based) traversal and dispatchers
 * ------------------------------------------------------------------------- */

/** @brief Generic readdir()-based breadth-first walk used when the Linux fast path is unavailable or cannot open the
 * directory. Attributes come from map_dirent_attrs() with a populate_file_attrs() fallback; subdirectory recursion goes
 * through fp_dir_walk_impl(), honouring DirStop/DirSkip/DirError with depth capped at FP_MAX_DIR_DEPTH (ELOOP). @return
 * 0 on success, -1 on error. */
static int dir_walk_generic(const char* path, WalkDirCallback callback, void* data, int depth) {
    if (depth > FP_MAX_DIR_DEPTH) {
        errno = ELOOP;  // Symbolic link loop or too many levels of directories
        return -1;
    }

    Directory* dir = dir_open(path);
    if (!dir) return -1;

    char fullpath[FILENAME_MAX];
    int status = 0;

    struct dirent* entry;
    while ((entry = readdir(dir->dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        if (!filepath_join_buf(path, entry->d_name, fullpath, sizeof(fullpath))) {
            status = -1;
            break;
        }

        FileAttributes attr;
        if (map_dirent_attrs(entry, fullpath, &attr) != 0) {
            continue;
        }

        if (attr.attrs == FATTR_NONE) {
            if (populate_file_attrs(fullpath, &attr) != 0) continue;
        }

        WalkDirOption opt = callback(&attr, fullpath, entry->d_name, data);
        if (opt == DirStop) break;
        if (opt == DirError) {
            status = -1;
            break;
        }
        if (opt == DirSkip) continue;

        if (fattr_is_dir(&attr)) {
            if (fp_dir_walk_impl(fullpath, callback, data) != 0) {
                status = -1;
                break;
            }
        }
    }

    dir_close(dir);
    return status;
}

/** @brief Generic readdir()-based post-order walk: subdirectories are recursed via fp_dir_walk_depth_first_impl()
 * before the callback sees the directory, enabling safe delete-style traversals where the fast path is unavailable.
 * Honours DirStop/DirError; depth capped at FP_MAX_DIR_DEPTH (ELOOP). @return 0 on success, -1 on error. */
static int dir_walk_depth_first_generic(const char* path, WalkDirCallback callback, void* data, int depth) {
    if (depth > FP_MAX_DIR_DEPTH) {
        errno = ELOOP;
        return -1;
    }

    Directory* dir = dir_open(path);
    if (!dir) return -1;

    char fullpath[FILENAME_MAX];
    int status = 0;

    struct dirent* entry;
    while ((entry = readdir(dir->dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        filepath_join_buf(path, entry->d_name, fullpath, sizeof(fullpath));
        FileAttributes attr;
        if (map_dirent_attrs(entry, fullpath, &attr) != 0) continue;

        if (attr.attrs == FATTR_NONE) {
            populate_file_attrs(fullpath, &attr);
        }

        if (fattr_is_dir(&attr)) {
            if (fp_dir_walk_depth_first_impl(fullpath, callback, data) != 0) {
                status = -1;
                break;
            }
        }

        WalkDirOption opt = callback(&attr, fullpath, entry->d_name, data);
        if (opt == DirStop) break;
        if (opt == DirError) {
            status = -1;
            break;
        }
    }

    dir_close(dir);
    return status;
}

/** @brief Generic lazy-walk fallback for non-Linux POSIX systems or when the fast path is unavailable: eagerly stats
 * each entry and wraps the result in a fully populated LazyFileAttributes (has_stat = true), so lazy_get_attrs() never
 * needs to stat again; recursion via fp_dir_walkx_impl(). Honours DirStop/DirSkip/DirError. @return 0 on success, -1 on
 * error. */
static int dir_walkx_generic(const char* path, WalkDirCallbackX callback, void* data) {
    Directory* dir = dir_open(path);
    if (!dir) return -1;

    char fullpath[FILENAME_MAX];
    int status = 0;

    struct dirent* entry;
    while ((entry = readdir(dir->dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        if (!filepath_join_buf(path, entry->d_name, fullpath, sizeof(fullpath))) {
            status = -1;
            break;
        }
        FileAttributes attr;
        if (map_dirent_attrs(entry, fullpath, &attr) != 0) continue;
        if (attr.attrs == FATTR_NONE) {
            if (populate_file_attrs(fullpath, &attr) != 0) continue;
        }
        LazyFileAttributes lazy = {
            .dirfd = dirfd(dir->dir),
            .name = entry->d_name,
            .d_type = entry->d_type,
            .cached = attr,
            .has_stat = true,
            .is_dir_cached = true,
            .is_dir_value = fattr_is_dir(&attr),
        };
        WalkDirOption opt = callback(&lazy, fullpath, entry->d_name, data);
        if (opt == DirStop) break;
        if (opt == DirError) {
            status = -1;
            break;
        }
        if (opt == DirSkip) continue;
        if (fattr_is_dir(&attr)) {
            if (fp_dir_walkx_impl(fullpath, callback, data) != 0) {
                status = -1;
                break;
            }
        }
    }

    dir_close(dir);
    return status;
}

/** @brief Dispatcher for dir_walk(): on Linux uses the getdents64 fast path when the kernel supports it, falling back
 * to dir_walk_generic() if the kernel is too old or the directory cannot be opened. @return 0 on success, -1 on error
 * (errno set). */
int fp_dir_walk_impl(const char* path, WalkDirCallback callback, void* data) {
#ifdef __linux__
    // Fast path: use getdents64 + openat + fstatat for 2-3x speedup
    // Kernel 2.6+ supports all required syscalls; check once and cache
    if (has_fast_dirent()) {
        int dirfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dirfd >= 0) {
            int ret = dir_walk_fast_helper(path, dirfd, callback, data, 0);
            close(dirfd);
            return ret;
        }
        // Fall through to legacy path if open fails (e.g., permission)
    }
#endif
    return dir_walk_generic(path, callback, data, 0);
}

/** @brief Dispatcher for dir_walk_depth_first(): uses the post-order getdents64 fast path on Linux when available,
 * falling back to dir_walk_depth_first_generic(). @return 0 on success, -1 on error (errno set). */
int fp_dir_walk_depth_first_impl(const char* path, WalkDirCallback callback, void* data) {
#ifdef __linux__
    if (has_fast_dirent()) {
        int dirfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dirfd >= 0) {
            int ret = dir_walk_depth_first_fast_helper(path, dirfd, callback, data, 0);
            close(dirfd);
            return ret;
        }
    }
#endif
    return dir_walk_depth_first_generic(path, callback, data, 0);
}

/** @brief Dispatcher for dir_walkx(): uses the lazy getdents64 fast path on Linux when available, falling back to
 * dir_walkx_generic(). @return 0 on success, -1 on error (errno set). */
int fp_dir_walkx_impl(const char* path, WalkDirCallbackX callback, void* data) {
#ifdef __linux__
    if (has_fast_dirent()) {
        int dirfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dirfd >= 0) {
            int ret = dir_walkx_fast_helper(path, dirfd, callback, data, 0);
            close(dirfd);
            return ret;
        }
    }
#endif
    return dir_walkx_generic(path, callback, data);
}
