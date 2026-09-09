/**
 * @file dotenv.h
 * @brief Environment variable loading from .env files.
 */

#ifndef DOTENV_H
#define DOTENV_H

#ifdef __cplusplus
extern "C" {
#endif

#include "env.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** Maximum length of an environment variable name. */
#ifndef MAX_VAR_NAME_LEN
    #define MAX_VAR_NAME_LEN 256
#endif

// Maximum length of a line in the .env file
#ifndef MAX_LINE_LENGTH
    #define MAX_LINE_LENGTH 1024
#endif

/**
 * Load .env file and populate set environment variables from the file.
 * Supports variable expansion with $(name) syntax but the variables must be defined before
 * being used.
 *
 * @param path The path to the .env file. Must not be NULL.
 * @return bool Returns true on success, false otherwise.
 */
bool load_dotenv(const char* path);

#ifdef __cplusplus
}
#endif

#endif  // DOTENV_H
