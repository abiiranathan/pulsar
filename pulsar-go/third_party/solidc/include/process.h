/**
 * @file process.h
 * @brief A modern, cross-platform API for process management and IPC
 */

#ifndef PROCESS_H
#define PROCESS_H

#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
#endif

#include "env.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include "platform.h"
    #include "wintypes.h"

    #include <io.h>
    #include <sys/stat.h>
    #include "platform.h"
#else
    #include <fcntl.h>
    #include <signal.h>
    #include <sys/select.h>
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Error codes for process operations
 */
typedef enum {
    PROCESS_SUCCESS = 0,
    PROCESS_ERROR_INVALID_ARGUMENT = -1,
    PROCESS_ERROR_FORK_FAILED = -2,
    PROCESS_ERROR_EXEC_FAILED = -3,
    PROCESS_ERROR_PIPE_FAILED = -4,
    PROCESS_ERROR_MEMORY = -5,
    PROCESS_ERROR_WAIT_FAILED = -6,
    PROCESS_ERROR_KILL_FAILED = -7,
    PROCESS_ERROR_PERMISSION_DENIED = -8,
    PROCESS_ERROR_IO = -9,
    PROCESS_ERROR_TIMEOUT = -10,      // Operation timed out
    PROCESS_ERROR_WOULD_BLOCK = -11,  // Non-blocking operation would block
    PROCESS_ERROR_PIPE_CLOSED = -12,  // Pipe end was closed
    PROCESS_ERROR_TERMINATE_FAILED = -13,
    PROCESS_ERROR_UNKNOWN = -14
} ProcessError;

#ifdef _WIN32
typedef HANDLE PipeFd;  // Pipe handle
#else
typedef int PipeFd;  // Pipe file descriptor.
#endif

/**
 * @brief Standard IO stream types for redirection
 */
typedef enum { PROCESS_STREAM_STDIN = 0, PROCESS_STREAM_STDOUT = 1, PROCESS_STREAM_STDERR = 2 } ProcessStream;

/**
 * @brief Process handle type (platform-specific details hidden in
 * implementation)
 */
typedef struct ProcessHandle ProcessHandle;

/**
 * @brief Pipe handle type for IPC (platform-specific details hidden in
 * implementation)
 */
typedef struct PipeHandle PipeHandle;

/**
 * File redirection handle
 */
typedef struct FileRedirection FileRedirection;

/**
 * @brief Options for process creation
 */
typedef struct {
    const char* working_directory;   // NULL = inherit current
    bool inherit_environment;        // If true, child inherits parent env
    const char* const* environment;  // NULL-terminated array of "KEY=VALUE" strings
    bool detached;                   // Run process in background (no wait by default)

    // Stream redirection options
    struct {
        PipeHandle* stdin_pipe;   // NULL = inherit
        PipeHandle* stdout_pipe;  // NULL = inherit
        PipeHandle* stderr_pipe;  // NULL = inherit
        bool merge_stderr;        // Redirect stderr to stdout
    } io;
} ProcessOptions;

#ifndef _WIN32
// Extend ProcessIO structure with file redirections
typedef struct {
    PipeHandle* stdin_pipe;   // stdin pipe
    PipeHandle* stdout_pipe;  // stdout pipe
    PipeHandle* stderr_pipe;  // stderr pipe
    bool merge_stderr;        // whether to merge stdout and stderr.

    FileRedirection* stdout_file;  // stdout redirections
    FileRedirection* stderr_file;  // stderr redirections
} ExtendedProcessIO;

// Extended ProcessOptions to include extended IO
typedef struct {
    const char* working_directory;
    bool inherit_environment;
    char* const* environment;
    bool detached;
    ExtendedProcessIO io;
} ExtProcessOptions;

#endif  // Linux only

/**
 * @brief Result information after a process completes
 */
typedef struct {
    int exit_code;
    bool exited_normally;
    int term_signal;  // Only valid if !exited_normally
} ProcessResult;

/**
 * @brief Create a new process
 * When custom environment is provided, command must be an absolute path
 * or relative path (containing '/'), as execve() does not search PATH
 * @param[out] handle Pointer to receive the process handle
 * @param[in] command Path to executable
 * @param[in] argv NULL-terminated array of arguments (argv[0] should be command
 * name)
 * @param[in] options Process creation options (NULL for defaults)
 * @return PROCESS_SUCCESS on success, error code otherwise
 */
ProcessError process_create(ProcessHandle** handle, const char* command, const char* const argv[],
                            const ProcessOptions* options);

/**
 * @brief Wait for a process to complete
 *
 * @param[in] handle Process handle
 * @param[out] result Pointer to receive exit information (can be NULL)
 * @param[in] timeout_ms Timeout in milliseconds (-1 = wait indefinitely)
 * @return PROCESS_SUCCESS on success, error code otherwise
 */
ProcessError process_wait(ProcessHandle* handle, ProcessResult* result, int timeout_ms);

/**
 * @brief Terminate a running process
 *
 * @param[in] handle Process handle
 * @param[in] force If true, force immediate termination
 * (SIGKILL/TerminateProcess)
 * @return PROCESS_SUCCESS on success, error code otherwise
 */
ProcessError process_terminate(ProcessHandle* handle, bool force);

/**
 * @brief Free resources associated with a process handle
 *
 * @param[in] handle Process handle to free
 */
void process_free(ProcessHandle* handle);

/**
 * @brief Cross-platform sleep
 *
 * Suspends the calling thread for the given duration. On POSIX this maps
 * to nanosleep(2); on Windows to Sleep() with millisecond granularity.
 * Negative inputs are clamped to zero, and extreme durations are clamped
 * to the platform maximum.
 *
 * @param[in] seconds Whole seconds to sleep.
 * @param[in] nanoseconds Additional nanoseconds [0, 999999999].
 * @note Not signal-safe on POSIX (nanosleep may return early on signal;
 *       this implementation does not retry).
 */
void NANOSLEEP(long seconds, long nanoseconds);

/**
 * @brief Checks whether a pipe's read end has been closed.
 *
 * @param[in] handle Pipe handle to query.
 * @return true if the read end is closed, false otherwise.
 */
bool pipe_read_closed(PipeHandle* handle);

/**
 * @brief Checks whether a pipe's write end has been closed.
 *
 * @param[in] handle Pipe handle to query.
 * @return true if the write end is closed, false otherwise.
 */
bool pipe_write_closed(PipeHandle* handle);

/**
 * @brief Returns the pipe's read-end descriptor.
 *
 * @param[in] handle Pipe handle to query.
 * @return Read-end descriptor (HANDLE on Windows, fd on POSIX).
 */
PipeFd pipe_read_fd(PipeHandle* handle);

/**
 * @brief Returns the pipe's write-end descriptor.
 *
 * @param[in] handle Pipe handle to query.
 * @return Write-end descriptor (HANDLE on Windows, fd on POSIX).
 */
PipeFd pipe_write_fd(PipeHandle* handle);

/**
 * @brief Create a new pipe for IPC
 *
 * @param[out] pipe Pointer to receive the pipe handle
 * @return PROCESS_SUCCESS on success, error code otherwise
 */
ProcessError pipe_create(PipeHandle** pipe);

/**
 * @brief Set non-blocking mode on a pipe
 *
 * @param pipe Pipe handle
 * @param nonblocking true to enable non-blocking mode, false for blocking
 * @return ProcessError
 */
ProcessError pipe_set_nonblocking(PipeHandle* pipe, bool nonblocking);

/**
 * @brief Read data from a pipe
 *
 * @param[in] pipe Pipe handle
 * @param[out] buffer Buffer to receive the data
 * @param[in] size Buffer size
 * @param[out] bytes_read Pointer to receive the number of bytes read (can be
 * NULL)
 * @param[in] timeout_ms Timeout in milliseconds (-1 = wait indefinitely)
 * @return PROCESS_SUCCESS on success, error code otherwise
 */
ProcessError pipe_read(PipeHandle* pipe, void* buffer, size_t size, size_t* bytes_read, int timeout_ms);

/**
 * @brief Write data to a pipe
 *
 * @param[in] pipe Pipe handle
 * @param[in] buffer Data to write
 * @param[in] size Number of bytes to write
 * @param[out] bytes_written Pointer to receive the number of bytes written (can
 * be NULL)
 * @param[in] timeout_ms Timeout in milliseconds (-1 = wait indefinitely)
 * @return PROCESS_SUCCESS on success, error code otherwise
 */
ProcessError pipe_write(PipeHandle* pipe, const void* buffer, size_t size, size_t* bytes_written, int timeout_ms);

/**
 * @brief Close a pipe
 *
 * @param[in] pipe Pipe handle to close
 */
void pipe_close(PipeHandle* pipe);
ProcessError pipe_close_read_end(PipeHandle* pipe);
ProcessError pipe_close_write_end(PipeHandle* pipe);

/**
 * @brief Get a string description of a process error
 *
 * @param[in] error Error code
 * @return Human-readable error description
 */
const char* process_error_string(ProcessError error);

/**
 * @brief Run a command and capture its output
 *
 * Convenience function that creates a process, captures its output,
 * waits for completion, and cleans up resources.
 *
 * @param[in] command Path to executable
 * @param[in] argv NULL-terminated array of arguments
 * @param[in] options Process creation options (NULL for defaults)
 * @param[out] exit_code Pointer to receive the exit code (can be NULL)
 * @return PROCESS_SUCCESS on success, error code otherwise
 */
ProcessError process_run_and_capture(const char* command, const char* const argv[], ProcessOptions* options,
                                     int* exit_code);

#ifndef _WIN32
/**
 * @brief Create a new file redirection for a process
 *
 * @param[out] redirection Pointer to store the created redirection
 * @param[in] filepath Path to the file
 * @param[in] flags File open flags (O_RDONLY, O_WRONLY, O_RDWR, etc.)
 * @param[in] mode File mode for creation (if O_CREAT is used)
 * @return ProcessError
 */
ProcessError process_redirect_to_file(FileRedirection** redirection, const char* filepath, int flags,
                                      unsigned int mode);

/**
 * @brief Create a file redirection from an existing file descriptor
 *
 * @param[out] redirection Pointer to store the created redirection
 * @param[in] fd Existing file descriptor
 * @param[in] close_on_exec Whether to close the FD when the process exits
 * @return ProcessError
 */
ProcessError process_redirect_to_fd(FileRedirection** redirection, int fd, bool close_on_exec);

/**
 * @brief Close and free a file redirection
 *
 * @param redirection The redirection to close
 */
void process_close_redirection(FileRedirection* redirection);

/**
 * @brief Run the command in a process that duplicates output to multiple
 * destinations.
 *
 * This function sets up a process whose output is duplicated to multiple
 * files/pipes
 *
 * @param[out] result Will hold process exit information.
 * @param[in] cmd Command to execute
 * @param[in] argv Arguments (NULL-terminated)
 * @param[in] output_fds Array of file descriptors to duplicate output to
 * (NULL-terminated)
 * @param[in] error_fds Array of file descriptors to duplicate errors to
 * (NULL-terminated)
 * @return ProcessError
 */
ProcessError process_run_with_multiwriter(ProcessResult* result, const char* cmd, const char* args[], int output_fds[],
                                          int error_fds[]);

/**
 * @brief Create a process with extended redirection options
 *
 * @param[out] handle Pointer to store the process handle
 * @param[in] command Command to execute
 * @param[in] argv Arguments for the command (NULL-terminated)
 * @param[in] options Process options with extended IO
 * @return ProcessError
 */
ProcessError process_create_with_redirection(ProcessHandle** handle, const char* command, const char* const argv[],
                                             const ExtProcessOptions* options);

/**
 * @brief Create a process that redirects its output from stdout and/or stderr
 * to files.
 *
 * @param[in] handle Pointer to process handle
 * @param[in] command Command to run
 * @param[in] argv Command arguments
 * @param[in] stdout_file File to redirect stdout to, or NULL
 * @param[in] stderr_file File to redirect stderr to, or NULL
 * @param[in] append Whether to append to files (true) or overwrite (false)
 * @return ProcessError
 */
ProcessError process_run_with_file_redirection(ProcessHandle** handle, const char* command, const char* const argv[],
                                               const char* stdout_file, const char* stderr_file, bool append);

#endif  // Linux only

#ifdef __cplusplus
}
#endif

#endif /* PROCESS_H */
