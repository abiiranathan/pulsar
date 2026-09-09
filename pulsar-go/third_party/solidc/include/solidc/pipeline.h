/**
 * @file pipeline.h
 * @brief Data pipeline utilities for processing streams.
 */

#ifndef PIPELINE_H
#define PIPELINE_H

#ifdef _WIN32
    #include <fcntl.h>
    #include <io.h>
    #include <sys/stat.h>
    #include "platform.h"
    #define O_WRONLY      _O_WRONLY
    #define O_CREAT       _O_CREAT
    #define O_TRUNC       _O_TRUNC
    #define STDIN_FILENO  0
    #define STDOUT_FILENO 1
#else
    #include <fcntl.h>
    #include <sys/wait.h>
    #include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Structure representing a command in a pipeline.
 */
typedef struct CommandNode {
    char** args;               // NULL-terminated array of command arguments
    struct CommandNode* next;  // Next command in the pipeline
} CommandNode;

/**
 * @brief Create a new CommandNode.
 *
 * @param args Array of command arguments (NULL-terminated).
 * @return Pointer to the newly created CommandNode.
 */
CommandNode* create_command_node(char** args);

/**
 * @brief Execute a pipeline of commands.
 *
 * @param head Pointer to the first CommandNode in the pipeline.
 * @param output_fd Optional file descriptor to capture the output of the last
 * command. If -1, the output is not redirected.
 */
void execute_pipeline(CommandNode* head, int output_fd);

/**
 * @brief Free the linked list of commands.
 *
 * @param head Pointer to the first CommandNode in the pipeline.
 */
void free_pipeline(CommandNode* head);

/**
 * @brief Build the pipeline using a NULL-terminated array of CommandNode
 * pointers.
 *
 * @param commands Array of CommandNode pointers, terminated by NULL.
 */
void build_pipeline(CommandNode** commands);

#ifdef __cplusplus
}
#endif

#endif  // PIPELINE_H
