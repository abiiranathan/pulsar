/**
 * @file wintypes.h
 * @brief Windows-specific type definitions and compatibility macros for cross-platform development.
 */

#ifndef FLAGS_H
#define FLAGS_H

#ifdef _WIN32
    #include <direct.h>     // _mkdir (actual declaration)
    #include <fcntl.h>      // O_* flags and _O_* flags
    #include <io.h>         // _open, _read, _write, _close, _get_osfhandle
    #include <sys/stat.h>   // _S_IF*, _S_IREAD, _S_IWRITE, _mkdir
    #include <sys/types.h>  // mode_t
    #include "platform.h"   // winsock2 \u2192 mswsock \u2192 windows \u2192 ws2tcpip (correct order)

    // Must come after windows.
    #include <wincrypt.h>  // For Cryptographic functions on windows

    // File access flags
    #define O_RDONLY     _O_RDONLY
    #define O_WRONLY     _O_WRONLY
    #define O_RDWR       _O_RDWR
    #define O_APPEND     _O_APPEND
    #define O_CREAT      _O_CREAT
    #define O_TRUNC      _O_TRUNC
    #define O_EXCL       _O_EXCL
    #define O_TEXT       _O_TEXT
    #define O_BINARY     _O_BINARY
    #define O_RAW        _O_BINARY
    #define O_TEMPORARY  _O_TEMPORARY
    #define O_NOINHERIT  _O_NOINHERIT
    #define O_SEQUENTIAL _O_SEQUENTIAL
    #define O_RANDOM     _O_RANDOM
    #define O_ACCMODE    _O_ACCMODE

    // File type flags
    #define S_IFMT  _S_IFMT
    #define S_IFDIR _S_IFDIR
    #define S_IFCHR _S_IFCHR
    #define S_IFIFO _S_IFIFO
    #define S_IFREG _S_IFREG

    // File type check macros
    #ifndef S_ISDIR
        #define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
    #endif

    #ifndef S_ISREG
        #define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
    #endif

    #ifndef S_ISCHR
        #define S_ISCHR(m) (((m) & S_IFMT) == S_IFCHR)
    #endif

    #ifndef S_ISFIFO
        #define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
    #endif

    // Permission flags
    #define S_IREAD  _S_IREAD
    #define S_IWRITE _S_IWRITE
    #define S_IEXEC  _S_IEXEC

    // Directory creation
    #define MKDIR(path) _mkdir(path)

#else  // POSIX systems

    #include <dirent.h>
    #include <fcntl.h>
    #include <sys/stat.h>
    #include <sys/types.h>
    #include <unistd.h>

    // Directory creation
    #define MKDIR(path) mkdir((path), 0755)

#endif  // _WIN32

#endif  // FLAGS_H
