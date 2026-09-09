/*
MIT License
Copyright (c) 2019 win32ports
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/**
 * @file win32_dirent.h
 * @brief Windows directory entry compatibility for POSIX dirent.h.
 */

#pragma once

#ifndef __DIRENT_H_9DE6B42C_8D0C_4D31_A8EF_8E4C30E6C46A__
    #define __DIRENT_H_9DE6B42C_8D0C_4D31_A8EF_8E4C30E6C46A__

    #ifndef _WIN32
        #pragma message("this dirent.h implementation is for Windows only!")
    #else /* _WIN32 */

        #ifdef __cplusplus
extern "C" {
        #endif /* __cplusplus */

        #include <errno.h>
        #include <stdint.h>
        #include <sys/types.h>
        #include "platform.h"

    /*
     * Constants and Macros
     */

        #ifndef NAME_MAX
            #define NAME_MAX 260
        #endif /* NAME_MAX */

        #ifndef DT_UNKNOWN
            #define DT_UNKNOWN 0
        #endif /* DT_UNKNOWN */

        #ifndef DT_FIFO
            #define DT_FIFO 1
        #endif /* DT_FIFO */

        #ifndef DT_CHR
            #define DT_CHR 2
        #endif /* DT_CHR */

        #ifndef DT_DIR
            #define DT_DIR 4
        #endif /* DT_DIR */

        #ifndef DT_BLK
            #define DT_BLK 6
        #endif /* DT_BLK */

        #ifndef DT_REG
            #define DT_REG 8
        #endif /* DT_REF */

        #ifndef DT_LNK
            #define DT_LNK 10
        #endif /* DT_LNK */

        #ifndef DT_SOCK
            #define DT_SOCK 12
        #endif /* DT_SOCK */

        #ifndef DT_WHT
            #define DT_WHT 14
        #endif /* DT_WHT */

        #ifndef _DIRENT_HAVE_D_NAMLEN
            #define _DIRENT_HAVE_D_NAMLEN 1
        #endif /* _DIRENT_HAVE_D_NAMLEN */

        #ifndef _DIRENT_HAVE_D_RECLEN
            #define _DIRENT_HAVE_D_RECLEN 1
        #endif /* _DIRENT_HAVE_D_RECLEN */

        #ifndef _DIRENT_HAVE_D_OFF
            #define _DIRENT_HAVE_D_OFF 1
        #endif /* _DIRENT_HAVE_D_OFF */

        #ifndef _DIRENT_HAVE_D_TYPE
            #define _DIRENT_HAVE_D_TYPE 1
        #endif /* _DIRENT_HAVE_D_TYPE  */

        #ifndef NTFS_MAX_PATH
            #define NTFS_MAX_PATH 32768
        #endif /* NTFS_MAX_PATH */

        #ifndef FSCTL_GET_REPARSE_POINT
            #define FSCTL_GET_REPARSE_POINT 0x900a8
        #endif /* FSCTL_GET_REPARSE_POINT */

        #ifndef FILE_NAME_NORMALIZED
            #define FILE_NAME_NORMALIZED 0
        #endif /* FILE_NAME_NORMALIZED */

/* Opaque directory stream handle */
typedef void* DIR;

/* Inode structure for Windows */
typedef struct ino_t {
    unsigned long long serial;
    unsigned char fileid[16];
} __ino_t;

/* Directory entry structure */
struct dirent {
    __ino_t d_ino;           /* File serial number */
    off_t d_off;             /* Offset to the next dirent */
    unsigned short d_reclen; /* Length of this record */
    unsigned char d_namelen; /* Length of the name */
    unsigned char d_type;    /* Type of file (DT_*) */
    char d_name[NAME_MAX];   /* Null-terminated filename */
};

/*
 * Function Prototypes
 */

/**
 * @brief Opens a directory stream corresponding to the directory name.
 *
 * @param name The path to the directory to open (UTF-8).
 * @return DIR* A pointer to the directory stream, or NULL on error (errno is set).
 */
DIR* opendir(const char* name);

/**
 * @brief Opens a directory stream using a wide-character string (Windows extension).
 *
 * @param name The path to the directory to open (wchar_t).
 * @return DIR* A pointer to the directory stream, or NULL on error.
 */
DIR* _wopendir(const wchar_t* name);

/**
 * @brief Opens a directory stream from an existing file descriptor.
 *
 * @param fd The file descriptor/handle.
 * @return DIR* A pointer to the directory stream, or NULL on error.
 */
DIR* fdopendir(intptr_t fd);

/**
 * @brief Closes a directory stream.
 *
 * @param dirp The directory stream to close.
 * @return int 0 on success, -1 on error (errno is set).
 */
int closedir(DIR* dirp);

/**
 * @brief Reads the next directory entry from the stream.
 *
 * @param dirp The directory stream.
 * @return struct dirent* Pointer to the directory entry structure, or NULL if end of stream or error.
 */
struct dirent* readdir(DIR* dirp);

/**
 * @brief Thread-safe version of readdir.
 *
 * @param dirp The directory stream.
 * @param entry The caller-allocated buffer to store the entry.
 * @param result Pointer to the resulting entry pointer (set to NULL on end of stream).
 * @return int 0 on success, or an error number.
 */
int readdir_r(DIR* dirp, struct dirent* entry, struct dirent** result);

/**
 * @brief Resets the position of the directory stream to the beginning.
 *
 * @param dirp The directory stream.
 */
void rewinddir(DIR* dirp);

/**
 * @brief Sets the position of the directory stream.
 *
 * @param dirp The directory stream.
 * @param offset The offset to seek to.
 */
void seekdir(DIR* dirp, long int offset);

/**
 * @brief Returns the current position of the directory stream.
 *
 * @param dirp The directory stream.
 * @return long int The current number of entries read (index).
 */
long int telldir(DIR* dirp);

/**
 * @brief Returns the underlying file descriptor/handle of the directory stream.
 *
 * @param dirp The directory stream.
 * @return intptr_t The handle, or -1 on error.
 */
intptr_t dirfd(DIR* dirp);

/**
 * @brief Scans a directory for matching entries.
 *
 * @param dirp The path of the directory to scan.
 * @param namelist Returns a pointer to an array of pointers to directory entries.
 * @param filter Function to filter entries (return non-zero to include).
 * @param compar Function to compare entries for sorting (passed to qsort).
 * @return int The number of entries selected, or -1 on error.
 */
int scandir(const char* dirp, struct dirent*** namelist, int (*filter)(const struct dirent*),
            int (*compar)(const struct dirent**, const struct dirent**));

/**
 * @brief Compare two directory entries alphabetically.
 * Use as the 'compar' argument for scandir.
 */
int alphasort(const void* a, const void* b);

/**
 * @brief Compare two directory entries by version (natural sort).
 * Use as the 'compar' argument for scandir.
 */
int versionsort(const void* a, const void* b);

        #ifdef __cplusplus
}
        #endif /* __cplusplus */

    #endif /* _WIN32 */

#endif /* __DIRENT_H_9DE6B42C_8D0C_4D31_A8EF_8E4C30E6C46A__ */
