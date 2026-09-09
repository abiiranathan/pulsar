#ifndef SOLIDC_PLATFORM_H
#define SOLIDC_PLATFORM_H

/**
 * @file platform.h
 * @brief Cross-platform compatibility definitions and canonical Windows header
 *        inclusion point.
 *
 * On Windows, winsock2.h MUST be included before windows.h. Including
 * windows.h first pulls in the older winsock.h and causes redefinition
 * errors for SOCKET, timeval, etc. This header centralises the correct
 * order so that every other header/source can simply include "platform.h"
 * instead of including <windows.h> directly.
 *
 * Correct Windows include order enforced here:
 *   winsock2.h → mswsock.h → windows.h → ws2tcpip.h
 *
 * All Windows-specific code should include this header rather than
 * including <windows.h> or <winsock2.h> directly.
 */

// Windows-specific type definitions
#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    // winsock2.h MUST precede windows.h — windows.h otherwise pulls in
    // winsock.h (v1) and breaks winsock2 definitions (SOCKET, etc.).
    #include <winsock2.h>
    // mswsock.h provides TransmitFile and other extension APIs; requires
    // winsock2.h first.
    #include <mswsock.h>
    #include <windows.h>
    #include <ws2tcpip.h>
    // ssize_t is not defined in Windows
    #ifndef _SSIZE_T_DEFINED
        #define _SSIZE_T_DEFINED
typedef SSIZE_T ssize_t;
    #endif

#else
    // POSIX systems have ssize_t in sys/types.h
    #include <sys/types.h>
#endif

#endif /* SOLIDC_PLATFORM_H */
