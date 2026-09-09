/**
 * @file filepath_internal.h
 * @brief Internal contract between the portable filepath code and the
 *        per-platform implementations (filepath_posix.c / filepath_win32.c).
 *
 * Not part of the public API. Everything declared here must be implemented
 * by exactly one of the platform translation units.
 */

#ifndef SOLIDC_FILEPATH_INTERNAL_H
#define SOLIDC_FILEPATH_INTERNAL_H

#include "../../include/env.h"
#include "../../include/file.h"
#include "../../include/filepath.h"

/** Maximum recursion depth for directory walks. */
#define FP_MAX_DIR_DEPTH 64

/** Length of the random prefix used for temporary file/directory names. */
#define FP_TEMP_PREFIX_LEN 12

/**
 * strlcpy-like bounded copy. Copies at most size-1 bytes and always
 * NUL-terminates. Returns the number of bytes copied (excluding NUL).
 */
size_t fp_strlcpy(char* dst, const char* src, size_t size);

/**
 * Fills a string with len random characters from [a-zA-Z0-9] plus a NUL.
 * On entropy failure, produces an empty string.
 */
void fp_random_name(char* str, size_t len);

/* ---------------------------------------------------------------------------
 * Platform primitives
 * ------------------------------------------------------------------------- */

/** Cryptographically-sourced random bytes. Returns false on failure. */
bool fp_random_bytes(unsigned char* buf, size_t n);

/** Removes an empty directory. Returns 0 on success, -1 with errno set. */
int fp_remove_single_directory(const char* path);

/**
 * dir_walk_depth_first callback that deletes each visited entry.
 * Files are removed before their containing directory (post-order).
 */
WalkDirOption fp_dir_remove_entry(const FileAttributes* attr, const char* path, const char* name, void* data);

/**
 * Finalizes a temporary file candidate path by actually creating it.
 * Takes ownership of candidate: returns it on success, free()s it on failure.
 */
char* fp_create_tempfile(char* candidate);

/** Same ownership contract as fp_create_tempfile(), but creates a directory. */
char* fp_create_tempdir(char* candidate);

/* ---------------------------------------------------------------------------
 * Platform traversal backends (used by the public wrappers in filepath.c)
 * ------------------------------------------------------------------------- */

int fp_dir_walk_impl(const char* path, WalkDirCallback callback, void* data);
int fp_dir_walk_depth_first_impl(const char* path, WalkDirCallback callback, void* data);
int fp_dir_walkx_impl(const char* path, WalkDirCallbackX callback, void* data);

#endif /* SOLIDC_FILEPATH_INTERNAL_H */
