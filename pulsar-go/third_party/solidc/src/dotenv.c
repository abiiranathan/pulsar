#include "../include/dotenv.h"
#include "../include/str.h"

#include <ctype.h>   // for isspace
#include <errno.h>   // for errno
#include <stdio.h>   // for fprintf, stderr, fopen, fgets, fclose
#include <string.h>  // for strlen, strchr, memset

/**
 * Removes surrounding quotes from a string in-place.
 *
 * Double-quoted values have backslash escapes processed (\" \\ \n \t \r);
 * unknown escapes keep the escaped character without the backslash, which
 * matches shell behaviour.  Single-quoted values are fully literal.
 *
 * @param str The string to unquote. Must be non-NULL.
 * @return Pointer to the unquoted string (may be different from input).
 */
static char* remove_quotes(char* str) {
    if (str == NULL) {
        return NULL;
    }

    size_t len = strlen(str);
    if (len < 2) {
        return str;
    }

    char first = str[0], last = str[len - 1];
    bool dbl = (first == '"' && last == '"');
    bool sgl = (first == '\'' && last == '\'');
    if (!dbl && !sgl) {
        return str;
    }

    if (sgl) {
        /* Single quotes are fully literal. */
        str[len - 1] = '\0';
        return str + 1;
    }

    /* Double quotes: process backslash escapes in place.  The write
     * cursor never overtakes the read cursor, so this is safe. */
    char* w = str + 1;
    char* inner_end = str + len - 1;
    for (char* r = str + 1; r < inner_end; r++) {
        if (*r == '\\' && r + 1 < inner_end) {
            r++;
            switch (*r) {
                case 'n':
                    *w++ = '\n';
                    break;
                case 't':
                    *w++ = '\t';
                    break;
                case 'r':
                    *w++ = '\r';
                    break;
                default:
                    *w++ = *r; /* \" -> ", \\ -> \, unknown kept */
            }
        } else {
            *w++ = *r;
        }
    }
    *w = '\0';
    return str + 1;
}

/**
 * Interpolates environment variables in the format ${VAR_NAME}.
 * @param value The string containing variable references. Must be non-NULL.
 * @param result Buffer to store the interpolated result. Must be non-NULL.
 * @param result_size Size of the result buffer.
 * @return true on success, false if buffer is too small or invalid input.
 */
static bool interpolate(const char* value, char* result, size_t result_size) {
    if (value == NULL || result == NULL || result_size == 0) {
        return false;
    }

    size_t result_len = 0;
    const char* ptr = value;
    memset(result, 0, result_size);

    while (*ptr && result_len < result_size - 1) {
        // Look for variable interpolation pattern: ${VAR_NAME}
        if (*ptr == '$' && *(ptr + 1) == '{') {
            const char* start = ptr + 2;
            const char* end = strchr(start, '}');

            if (end == NULL) {
                // Malformed interpolation - copy literal characters
                fprintf(stderr, "Warning: Unclosed variable reference starting at position %td\n", ptr - value);
                result[result_len++] = *ptr++;
                continue;
            }

            // Extract variable name
            size_t var_name_len = (size_t)(end - start);
            if (var_name_len == 0) {
                // Empty variable name: ${}
                fprintf(stderr, "Warning: Empty variable name\n");
                ptr = end + 1;
                continue;
            }

            if (var_name_len >= MAX_VAR_NAME_LEN) {
                fprintf(stderr, "Error: Variable name too long (max %d)\n", MAX_VAR_NAME_LEN - 1);
                return false;
            }

            char var_name[MAX_VAR_NAME_LEN] = {0};
            snprintf(var_name, sizeof(var_name), "%.*s", (int)var_name_len, start);

            // Get variable value from environment
            const char* var_value = GETENV(var_name);
            if (var_value != NULL) {
                size_t var_value_len = strlen(var_value);
                // Check if we have enough space (account for null terminator)
                if (result_len + var_value_len >= result_size) {
                    fprintf(stderr, "Error: Result buffer too small for interpolation\n");
                    return false;
                }

                memcpy(result + result_len, var_value, var_value_len);
                result_len += var_value_len;
            } else {
                fprintf(stderr, "Warning: Environment variable '%s' not found, skipping\n", var_name);
            }

            ptr = end + 1;
        } else {
            // Regular character - copy as-is
            result[result_len++] = *ptr++;
        }
    }

    // Check if we ran out of buffer space
    if (*ptr != '\0') {
        fprintf(stderr, "Error: Result buffer too small\n");
        return false;
    }

    result[result_len] = '\0';
    return true;
}

/**
 * Validates that a key is a legal environment variable name.
 * POSIX restricts portable names to [A-Za-z_][A-Za-z0-9_]*, which also
 * rules out characters (spaces, '=', etc.) that would corrupt the
 * environment or indicate a malformed line.
 * @param key The candidate key. Must be non-NULL and non-empty.
 * @return true if key is a valid identifier, false otherwise.
 */
static bool is_valid_key(const char* key) {
    if (key == NULL || *key == '\0') {
        return false;
    }

    if (!isalpha((unsigned char)key[0]) && key[0] != '_') {
        return false;
    }

    for (const char* p = key + 1; *p != '\0'; p++) {
        if (!isalnum((unsigned char)*p) && *p != '_') {
            return false;
        }
    }

    return true;
}

/**
 * Processes a single key-value line and sets the environment variable.
 * @param key The environment variable name. Must be non-NULL.
 * @param value The value to set. Must be non-NULL.
 * @return true on success, false on error.
 */
static bool process_env_pair(char* key, char* value) {
    if (key == NULL || value == NULL) {
        return false;
    }

    // Trim key
    str_trim(key);
    if (!is_valid_key(key)) {
        fprintf(stderr, "Error: Invalid environment variable name '%s'\n", key);
        return false;
    }

    // Trim and unquote value
    str_trim(value);
    value = remove_quotes(value);

    // Check if interpolation is needed
    if (strchr(value, '$') != NULL && strchr(value, '{') != NULL && strchr(value, '}') != NULL) {
        char interpolated_value[MAX_LINE_LENGTH] = {0};
        if (!interpolate(value, interpolated_value, sizeof(interpolated_value))) {
            fprintf(stderr, "Error: Failed to interpolate value for key '%s'\n", key);
            return false;
        }

        if (SETENV(key, interpolated_value, 1) != 0) {
            fprintf(stderr, "Error: Failed to set environment variable '%s': %s\n", key, strerror(errno));
            return false;
        }
    } else {
        if (SETENV(key, value, 1) != 0) {
            fprintf(stderr, "Error: Failed to set environment variable '%s': %s\n", key, strerror(errno));
            return false;
        }
    }

    return true;
}

/**
 * Strips a trailing, unquoted "#" comment from a line, in place.
 *
 * A '#' starts a comment only when it is outside quotes AND at a word
 * boundary (start of line, or preceded by whitespace, or immediately
 * after a closing quote).  This keeps shell-style values such as
 * KEY=value#anchor intact while still supporting:
 *   KEY="a#b"          (quoted hash)
 *   KEY=val # comment  (spaced inline comment)
 *   KEY="x" # comment  (comment after closing quote)
 *
 * Backslash escapes inside double quotes (\") do not affect quote state,
 * so a comment after an escaped quote is still detected correctly.
 *
 * @param line The line to strip. Must be non-NULL.
 */
static void strip_inline_comment(char* line) {
    bool in_single = false;
    bool in_double = false;
    bool escaped = false; /* inside double quotes: next char is literal */
    char prev = 0;

    for (char* p = line; *p != '\0'; p++) {
        char c = *p;

        if (in_single) {
            if (c == '\'') {
                in_single = false;
            }
        } else if (escaped) {
            escaped = false; /* verbatim character, no state change */
        } else if (in_double) {
            if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                in_double = false;
            }
        } else {
            if (c == '#') {
                bool boundary = (prev == '\0' || prev == ' ' || prev == '\t' || prev == '"' || prev == '\'');
                if (boundary) {
                    *p = '\0';
                    return;
                }
            } else if (c == '\'') {
                in_single = true;
            } else if (c == '"') {
                in_double = true;
            }
        }

        prev = c;
    }
}

bool load_dotenv(const char* path) {
    if (path == NULL) {
        fprintf(stderr, "Error: NULL path passed to load_dotenv\n");
        return false;
    }

    FILE* file = fopen(path, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Failed to open '%s': %s\n", path, strerror(errno));
        return false;
    }

    char line[MAX_LINE_LENGTH];
    size_t line_number = 0;
    bool had_errors = false;

    while (fgets(line, sizeof(line), file) != NULL) {
        line_number++;

        // Detect a line that didn't fit in the buffer (no newline and not EOF).
        size_t len = strlen(line);
        if (len == sizeof(line) - 1 && line[len - 1] != '\n' && !feof(file)) {
            fprintf(stderr, "Warning: Line %zu exceeds maximum length (%d), skipping\n", line_number,
                    MAX_LINE_LENGTH - 1);
            had_errors = true;
            // Discard the remainder of this oversized line before continuing.
            int c;
            while ((c = fgetc(file)) != EOF && c != '\n') {
            }
            continue;
        }

        // Remove trailing newline (and a preceding '\r' for CRLF files).
        if (len > 0 && line[len - 1] == '\n') {
            line[--len] = '\0';
        }
        if (len > 0 && line[len - 1] == '\r') {
            line[--len] = '\0';
        }

        strip_inline_comment(line);
        str_trim(line);

        // Skip empty lines and full-line comments
        if (*line == '\0' || *line == '#') {
            continue;
        }

        // Optional "export " prefix, as supported by shell-style .env files.
        char* stmt = line;
        if (strncmp(stmt, "export ", 7) == 0 || strncmp(stmt, "export\t", 7) == 0) {
            stmt += 7;
            str_trim(stmt);
        }

        // Find the '=' separator
        char* equals = strchr(stmt, '=');
        if (equals == NULL) {
            fprintf(stderr, "Warning: Invalid line %zu (no '=' found): %s\n", line_number, stmt);
            had_errors = true;
            continue;
        }

        // Split into key and value
        *equals = '\0';
        char* key = stmt;
        char* value = equals + 1;

        if (!process_env_pair(key, value)) {
            fprintf(stderr, "Warning: Failed to process line %zu\n", line_number);
            had_errors = true;
        }
    }

    if (ferror(file)) {
        fprintf(stderr, "Error: Failed to read from file '%s': %s\n", path, strerror(errno));
        fclose(file);
        return false;
    }

    if (fclose(file) != 0) {
        fprintf(stderr, "Error: Failed to close '%s': %s\n", path, strerror(errno));
        return false;
    }

    return !had_errors;
}
