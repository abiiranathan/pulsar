/**
 * @file process.c
 * @brief Portable (platform-neutral) process management logic.
 *
 * Hosts everything that does not touch OS APIs. Platform-specific
 * process creation, pipes, waiting, and signaling live in:
 *
 *   - src/process/process_posix.c  (Linux/macOS/BSD)
 *   - src/process/process_win32.c  (Win32)
 *
 * The contract between the two sides is defined in process_internal.h.
 */

#include "process_internal.h"

#include <stdlib.h>
#include <string.h>

/* Default options for process creation */
static const ProcessOptions DEFAULT_OPTIONS = {
    .working_directory = NULL,
    .inherit_environment = true,
    .environment = NULL,
    .detached = false,
    .io =
        {
            .stdin_pipe = NULL,
            .stdout_pipe = NULL,
            .stderr_pipe = NULL,
            .merge_stderr = false,
        },
};

/**
 * @brief Returns a static, human-readable description of a ProcessError code.
 *
 * @param[in] error Error code returned by the process API.
 * @return Static string; never NULL. Unknown codes yield "Invalid error code".
 */
const char* process_error_string(ProcessError error) {
    switch (error) {
        case PROCESS_SUCCESS:
            return "Success";
        case PROCESS_ERROR_INVALID_ARGUMENT:
            return "Invalid argument";
        case PROCESS_ERROR_FORK_FAILED:
            return "Fork failed";
        case PROCESS_ERROR_EXEC_FAILED:
            return "Exec failed";
        case PROCESS_ERROR_PIPE_FAILED:
            return "Pipe creation failed";
        case PROCESS_ERROR_MEMORY:
            return "Memory allocation failed";
        case PROCESS_ERROR_WAIT_FAILED:
            return "Wait for process failed";
        case PROCESS_ERROR_KILL_FAILED:
            return "Failed to terminate process";
        case PROCESS_ERROR_TERMINATE_FAILED:
            return "Failed to terminate process";
        case PROCESS_ERROR_PERMISSION_DENIED:
            return "Permission denied";
        case PROCESS_ERROR_IO:
            return "I/O error";
        case PROCESS_ERROR_TIMEOUT:
            return "Operation timed out";
        case PROCESS_ERROR_WOULD_BLOCK:
            return "Operation would block (no data available)";
        case PROCESS_ERROR_PIPE_CLOSED:
            return "Pipe was closed";
        case PROCESS_ERROR_UNKNOWN:
            return "Unknown error";
        default:
            return "Invalid error code";
    }
}

/** @brief Reports whether the read end of the pipe has been closed. @return true if the read end is closed. */
bool pipe_read_closed(PipeHandle* handle) { return handle->read_closed; }

/** @brief Reports whether the write end of the pipe has been closed. @return true if the write end is closed. */
bool pipe_write_closed(PipeHandle* handle) { return handle->write_closed; }

/** @brief Returns the native read descriptor/handle of the pipe. */
PipeFd pipe_read_fd(PipeHandle* handle) { return handle->read_fd; }

/** @brief Returns the native write descriptor/handle of the pipe. */
PipeFd pipe_write_fd(PipeHandle* handle) { return handle->write_fd; }

/** @brief Public entry point for process creation: validates arguments, applies DEFAULT_OPTIONS when options is NULL,
 * and dispatches to the platform backend (unix_create_process()/win32_create_process()). @param[out] handle Pointer to
 * receive the process handle. @return PROCESS_SUCCESS on success; PROCESS_ERROR_INVALID_ARGUMENT for NULL arguments or
 * a backend error code otherwise. */
ProcessError process_create(ProcessHandle** handle, const char* command, const char* const argv[],
                            const ProcessOptions* options) {
    if (!handle || !command || !argv || !argv[0]) {
        return PROCESS_ERROR_INVALID_ARGUMENT;
    }

    // Use default options if not provided
    ProcessOptions effective_options;
    if (options) {
        effective_options = *options;
    } else {
        effective_options = DEFAULT_OPTIONS;
    }

#ifdef _WIN32
    return win32_create_process(handle, command, argv, &effective_options);
#else
    return unix_create_process(handle, command, argv, &effective_options);
#endif
}

/** @brief Frees the memory backing a process handle. Does not wait for or terminate the process. @param[in] handle
 * Process handle to free. Safe to pass NULL. */
void process_free(ProcessHandle* handle) {
    if (!handle) return;
    free(handle);
}

/** @brief Convenience wrapper: creates the process, waits indefinitely, frees the handle and reports the exit code.
 * @param[out] exit_code Optional receiver for the child's exit status. @return PROCESS_SUCCESS only if creation,
 * waiting and a zero exit code all succeed; PROCESS_ERROR_EXEC_FAILED for a nonzero exit code; otherwise the underlying
 * ProcessError. */
ProcessError process_run_and_capture(const char* command, const char* const argv[], ProcessOptions* options,
                                     int* exit_code) {
    ProcessHandle* proc = NULL;
    ProcessError err = {0};
    err = process_create(&proc, command, argv, options);
    if (err != PROCESS_SUCCESS) {
        return err;
    }

    ProcessResult res = {0};
    err = process_wait(proc, &res, -1);
    process_free(proc);

    if (exit_code) {
        *exit_code = res.exit_code;
    }

    if (err != PROCESS_SUCCESS) {
        return err;
    }

    if (res.exit_code != 0) {
        return PROCESS_ERROR_EXEC_FAILED;
    }
    return PROCESS_SUCCESS;
}
