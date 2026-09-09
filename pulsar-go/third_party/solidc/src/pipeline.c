/**
 * @file pipeline.c
 * @brief Cross-platform execution of a linked pipeline of external commands.
 *
 * On POSIX systems (Linux, macOS, BSD), stages are launched with
 * posix_spawn() and posix_spawn_file_actions_t instead of fork()+execvp().
 * Implementations that support it (glibc, musl) run posix_spawn() as
 * clone(CLONE_VM | CLONE_VFORK) when the file actions are limited to
 * dup2/close, which skips the page-table duplication a plain fork()
 * performs on the parent's address space. On Windows, stages are launched
 * with CreateProcess(), which has no page-table-duplication equivalent to
 * avoid; the two implementations share the same pipe-plumbing and
 * fail-safe cleanup discipline so they behave identically from the
 * caller's perspective.
 */
#include "../include/pipeline.h"

#include <stdio.h>   // for fprintf, perror, stderr
#include <stdlib.h>  // for malloc, calloc, free, exit, EXIT_FAILURE
#include <string.h>  // for strerror, strpbrk, strlen

#ifdef _WIN32
    #include <fcntl.h>                // for _O_BINARY
    #include <io.h>                   // for _pipe, _close, _dup2, _get_osfhandle
    #include "../include/platform.h"  // for CreateProcess, HANDLE, STARTUPINFO, PROCESS_INFORMATION

    #define pipe(fds)          _pipe(fds, PIPELINE_PIPE_BUFFER_SIZE, _O_BINARY)
    #define close(fd)          _close(fd)
    #define dup2(oldfd, newfd) _dup2(oldfd, newfd)

#else
    #include <spawn.h>     // for posix_spawn_file_actions_t, posix_spawnp
    #include <sys/wait.h>  // for waitpid
    #include <unistd.h>    // for pipe, close, dup2, STDIN_FILENO, STDOUT_FILENO

    #if defined(__linux__)
        #include <fcntl.h>  // for fcntl, F_SETPIPE_SZ (Linux-specific)
    #endif

extern char** environ;  // for posix_spawnp's envp argument
#endif

/** Maximum length, in bytes, of a single stage's built Windows command line, including the terminating NUL. */
#define PIPELINE_MAX_CMDLINE 4096

/** Requested OS pipe buffer size, in bytes, for pipe()/_pipe() calls in this file. */
#define PIPELINE_PIPE_BUFFER_SIZE 4096

#if defined(__linux__)
    /** Enlarged pipe capacity, in bytes, requested via F_SETPIPE_SZ on Linux to reduce context switches for
     * high-throughput stages. */
    #define PIPELINE_LINUX_PIPE_SIZE (1 << 20)
#endif

/**
 * @brief Create a new CommandNode.
 *
 * @param args Array of command arguments (NULL-terminated). Not copied;
 *        the caller retains ownership and must keep it valid for the
 *        node's lifetime.
 * @return Pointer to the newly created CommandNode. Never returns NULL;
 *         allocation failure is treated as unrecoverable.
 */
CommandNode* create_command_node(char** args) {
    CommandNode* node = (CommandNode*)malloc(sizeof(CommandNode));
    if (node == NULL) {
        perror("pipeline: malloc");
        exit(EXIT_FAILURE);
    }
    node->args = args;
    node->next = NULL;
    return node;
}

#ifdef _WIN32
/**
 * @brief Execute a pipeline of commands on Windows.
 *
 * Each stage is launched with CreateProcess(); stdin/stdout are wired
 * between consecutive stages through anonymous pipes, and the final
 * stage's stdout is redirected to @p output_fd when given. On a
 * mid-pipeline failure, stages already spawned are waited on before
 * returning so they aren't orphaned.
 *
 * @param head Pointer to the first CommandNode in the pipeline.
 * @param output_fd File descriptor the last stage's stdout is redirected
 *        to, or -1 to leave it inherited from the caller.
 */
void execute_pipeline(CommandNode* head, int output_fd) {
    int pipefd[2] = {0};
    int prev_pipe_read_end = -1;
    CommandNode* current = head;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    HANDLE* proc_handles = NULL;
    DWORD proc_count = 0;
    DWORD command_count = 0;

    for (const CommandNode* n = head; n != NULL; n = n->next) {
        command_count++;
    }
    if (command_count == 0) {
        return;
    }

    /* WaitForMultipleObjects supports at most 64 handles. */
    if (command_count > MAXIMUM_WAIT_OBJECTS) {
        fprintf(stderr, "pipeline: too many stages (%lu, max %d)\n", command_count, MAXIMUM_WAIT_OBJECTS);
        exit(EXIT_FAILURE);
    }

    proc_handles = (HANDLE*)calloc(command_count, sizeof(HANDLE));
    if (proc_handles == NULL) {
        perror("pipeline: calloc");
        exit(EXIT_FAILURE);
    }

    while (current != NULL) {
        char command[PIPELINE_MAX_CMDLINE];
        size_t cmd_len = 0;

        if (current->next != NULL) {
            if (pipe(pipefd) < 0) {
                perror("pipeline: pipe");
                goto windows_reap_and_fail;
            }
        }

        /*
         * Build the command line with BOUNDED appends. Each argument is
         * quoted and backslash-escaped per the MSVCRT command-line rules;
         * the buffer is sized generously and truncation aborts the stage
         * rather than corrupting memory.
         */
        command[0] = '\0';
        for (int i = 0; current->args[i] != NULL; i++) {
            const char* a = current->args[i];
            const int needs_quote = (*a != '\0') && (strpbrk(a, " \t\"") != NULL);
            const size_t alen = strlen(a);

            if (cmd_len + alen * 2 + 4 >= sizeof(command)) {
                fprintf(stderr, "pipeline: command line too long\n");
                if (current->next != NULL) {
                    close(pipefd[0]);
                    close(pipefd[1]);
                }
                goto windows_reap_and_fail;
            }
            if (i > 0) {
                command[cmd_len++] = ' ';
            }
            if (needs_quote) {
                command[cmd_len++] = '"';
            }
            for (const char* p = a; *p != '\0'; p++) {
                if (*p == '"') {
                    command[cmd_len++] = '\\';
                }
                command[cmd_len++] = *p;
            }
            if (needs_quote) {
                command[cmd_len++] = '"';
            }
            command[cmd_len] = '\0';
        }

        si = (STARTUPINFO){0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

        if (prev_pipe_read_end != -1) {
            si.hStdInput = (HANDLE)_get_osfhandle(prev_pipe_read_end);
        }
        if (current->next != NULL) {
            si.hStdOutput = (HANDLE)_get_osfhandle(pipefd[1]);
        } else if (output_fd != -1) {
            si.hStdOutput = (HANDLE)_get_osfhandle(output_fd);
        }

        pi = (PROCESS_INFORMATION){0};
        if (!CreateProcess(NULL,    /* No module name (use command line) */
                           command, /* Command line */
                           NULL,    /* Process handle not inheritable */
                           NULL,    /* Thread handle not inheritable */
                           TRUE,    /* Handle inheritance TRUE */
                           0,       /* No creation flags */
                           NULL,    /* Use parent's environment block */
                           NULL,    /* Use parent's starting directory */
                           &si,     /* Pointer to STARTUPINFO structure */
                           &pi)) {  /* Pointer to PROCESS_INFORMATION structure */
            fprintf(stderr, "pipeline: CreateProcess failed: %lu\n", GetLastError());
            if (current->next != NULL) {
                close(pipefd[0]);
                close(pipefd[1]);
            }
            goto windows_reap_and_fail;
        }

        proc_handles[proc_count++] = pi.hProcess;
        CloseHandle(pi.hThread);

        if (current->next != NULL) {
            close(pipefd[1]);
        }
        if (prev_pipe_read_end != -1) {
            close(prev_pipe_read_end);
        }
        prev_pipe_read_end = (current->next != NULL) ? pipefd[0] : -1;

        current = current->next;
    }

    WaitForMultipleObjects(proc_count, proc_handles, TRUE, INFINITE);
    for (DWORD i = 0; i < proc_count; i++) {
        CloseHandle(proc_handles[i]);
    }
    free(proc_handles);
    return;

windows_reap_and_fail:
    /* Wait for stages already spawned before this failure so we don't
     * orphan them, mirroring the cleanup discipline on the POSIX side. */
    if (proc_count > 0) {
        WaitForMultipleObjects(proc_count, proc_handles, TRUE, INFINITE);
        for (DWORD i = 0; i < proc_count; i++) {
            CloseHandle(proc_handles[i]);
        }
    }
    free(proc_handles);
    exit(EXIT_FAILURE);
}
#else
/**
 * @brief Execute a pipeline of commands on POSIX systems.
 *
 * Each stage is launched with posix_spawn(); stdin/stdout are wired
 * between consecutive stages through anonymous pipes via
 * posix_spawn_file_actions_t, and the final stage's stdout is redirected
 * to @p output_fd when given. On a mid-pipeline failure, stages already
 * spawned are waited on before returning so they aren't orphaned.
 *
 * @param head Pointer to the first CommandNode in the pipeline.
 * @param output_fd File descriptor the last stage's stdout is redirected
 *        to, or -1 to leave it inherited from the caller.
 */
void execute_pipeline(CommandNode* head, int output_fd) {
    int pipefd[2] = {-1, -1};
    int prev_pipe_read_end = -1;
    CommandNode* current = head;
    size_t num_stages = 0;
    size_t spawned = 0;
    pid_t* pids;

    for (const CommandNode* n = head; n != NULL; n = n->next) {
        num_stages++;
    }
    if (num_stages == 0) {
        return;
    }

    pids = malloc(num_stages * sizeof(*pids));
    if (pids == NULL) {
        perror("pipeline: malloc");
        exit(EXIT_FAILURE);
    }

    while (current != NULL) {
        posix_spawn_file_actions_t actions;
        int rc;

        if (current->next != NULL) {
            if (pipe(pipefd) < 0) {
                perror("pipeline: pipe");
                goto posix_reap_and_fail;
            }
    #if defined(__linux__)
            /* Linux-only: enlarge the pipe to cut context switches for
             * high-throughput stages. Not fatal if unsupported (e.g. an
             * older kernel), so a failure here just keeps the default
             * buffer size instead of aborting the pipeline. */
            if (fcntl(pipefd[1], F_SETPIPE_SZ, PIPELINE_LINUX_PIPE_SIZE) < 0) {
                perror("pipeline: fcntl(F_SETPIPE_SZ)");
            }
    #endif
        }

        if (posix_spawn_file_actions_init(&actions) != 0) {
            perror("pipeline: posix_spawn_file_actions_init");
            if (current->next != NULL) {
                close(pipefd[0]);
                close(pipefd[1]);
            }
            goto posix_reap_and_fail;
        }

        /* stdin from the previous stage's read end. */
        if (prev_pipe_read_end != -1) {
            posix_spawn_file_actions_adddup2(&actions, prev_pipe_read_end, STDIN_FILENO);
            posix_spawn_file_actions_addclose(&actions, prev_pipe_read_end);
        }

        /* stdout to the next stage's write end, or to output_fd on the
         * last stage. Close both pipe ends afterward so the child
         * doesn't hold a stray read end that would block EOF. */
        if (current->next != NULL) {
            posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
            posix_spawn_file_actions_addclose(&actions, pipefd[0]);
            posix_spawn_file_actions_addclose(&actions, pipefd[1]);
        } else if (output_fd != -1) {
            posix_spawn_file_actions_adddup2(&actions, output_fd, STDOUT_FILENO);
            if (output_fd != STDOUT_FILENO) {
                posix_spawn_file_actions_addclose(&actions, output_fd);
            }
        }

        rc = posix_spawnp(&pids[spawned], current->args[0], &actions, NULL, current->args, environ);
        posix_spawn_file_actions_destroy(&actions);

        if (rc != 0) {
            fprintf(stderr, "pipeline: posix_spawnp: %s\n", strerror(rc));
            if (current->next != NULL) {
                close(pipefd[0]);
                close(pipefd[1]);
            }
            goto posix_reap_and_fail;
        }

        if (current->next != NULL) {
            close(pipefd[1]);
        }
        if (prev_pipe_read_end != -1) {
            close(prev_pipe_read_end);
        }
        prev_pipe_read_end = (current->next != NULL) ? pipefd[0] : -1;

        spawned++;
        current = current->next;
    }

    for (size_t i = 0; i < spawned; i++) {
        int status;
        waitpid(pids[i], &status, 0);
    }
    free(pids);
    return;

posix_reap_and_fail:
    for (size_t i = 0; i < spawned; i++) {
        int status;
        waitpid(pids[i], &status, 0);
    }
    free(pids);
    exit(EXIT_FAILURE);
}
#endif

/**
 * @brief Free the linked list of commands.
 *
 * @param head Pointer to the first CommandNode in the pipeline.
 */
void free_pipeline(CommandNode* head) {
    CommandNode* current = head;
    while (current != NULL) {
        CommandNode* next = current->next;
        free(current);
        current = next;
    }
}

/**
 * @brief Build the pipeline using a NULL-terminated array of CommandNode
 * pointers.
 *
 * @param commands Array of CommandNode pointers, terminated by NULL.
 */
void build_pipeline(CommandNode** commands) {
    if (commands == NULL) {
        return;
    }

    for (int i = 0; commands[i] != NULL; i++) {
        commands[i]->next = commands[i + 1];
    }
}

#if 0
int main(void) {
    // Create commands
    char* args1[] = {"ls", "-l", NULL};
    char* args2[] = {"grep", "-E", ".c$", NULL};
    char* args3[] = {"wc", "-l", NULL};

    CommandNode* cmd1 = create_command_node(args1);
    CommandNode* cmd2 = create_command_node(args2);
    CommandNode* cmd3 = create_command_node(args3);

    // Create a NULL-terminated array of commands
    CommandNode* commands[] = {cmd1, cmd2, cmd3, NULL};

    // Build the pipeline
    build_pipeline(commands);

    #ifdef _WIN32
    // On Windows, we need to use _open instead of open
    int output_fd = _open("output.txt", _O_WRONLY | _O_CREAT | _O_TRUNC, _S_IWRITE);
    #else
    // Open a file to capture the output of the last command
    int output_fd = open("output.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    #endif

    if (output_fd < 0) {
        perror("open");
        return EXIT_FAILURE;
    }

    // Execute the pipeline and capture the output of the last command
    execute_pipeline(cmd1, output_fd);

    // Close the output file descriptor
    close(output_fd);

    // Free the pipeline
    free_pipeline(cmd1);

    return 0;
}
#endif
