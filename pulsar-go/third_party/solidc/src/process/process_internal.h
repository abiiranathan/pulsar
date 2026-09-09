/**
 * @file process_internal.h
 * @brief Internal contract between the portable process code and the
 *        per-platform implementations (process_posix.c / process_win32.c).
 *
 * Not part of the public API; everything here must be implemented by
 * exactly one platform translation unit.
 */

#ifndef SOLIDC_PROCESS_INTERNAL_H
#define SOLIDC_PROCESS_INTERNAL_H

#include "../../include/file.h"
#include "../../include/process.h"

/**
 * Pipe handle layout. Identical on every platform: PipeFd is HANDLE on
 * Windows and int on POSIX, but the struct shape is shared.
 */
struct PipeHandle {
    PipeFd read_fd;
    PipeFd write_fd;
    bool read_closed;
    bool write_closed;
};

/**
 * Maps the platform's last-error state (GetLastError() on Windows,
 * errno on POSIX) to a ProcessError code.
 */
ProcessError process_system_error(void);

/* Platform backends (implemented in process_posix.c / process_win32.c). */
ProcessError unix_create_process(ProcessHandle** handle, const char* command, const char* const argv[],
                                 const ProcessOptions* options);
ProcessError win32_create_process(ProcessHandle** handle, const char* command, const char* const argv[],
                                  const ProcessOptions* options);

#endif /* SOLIDC_PROCESS_INTERNAL_H */
