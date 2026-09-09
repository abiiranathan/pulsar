/**
 * @file flags.c
 * @brief Command-line flag parsing library implementation
 *
 * This library provides a flexible command-line argument parser with support for:
 * - Multiple data types (bool, integers, floats, strings, etc.)
 * - Long flags (--flag) and short flags (-f)
 * - Subcommands with nested parsing
 * - Custom validators
 * - Automatic help generation
 * - Default value display
 * - Positional arguments
 *
 * ```
 */

#include "../include/flags.h"
#include "../include/arena.h"
#include "../include/str.h"

#define INITIAL_CAPACITY  64
#define ERR_BUF_SIZE      128
#define MAX_FLAG_NAME_LEN 128
#define MAX_DEFAULT_STR   64

/**
 * @struct Flag
 * @brief Internal representation of a command-line flag
 *
 * Contains all metadata and state for a single flag including its type,
 * name variants, description, value pointer, validation, and presence tracking.
 */
struct Flag {
    FlagDataType type;       /**< Data type of the flag value */
    char* name;              /**< Long name (used with --) */
    char short_name;         /**< Short name (used with -), 0 if none */
    char* description;       /**< Help text description */
    void* value_ptr;         /**< Pointer to variable that will hold the parsed value */
    void* default_ptr;       /**< Pointer to a copy of the default value for display */
    bool required;           /**< Whether this flag must be provided */
    bool is_present;         /**< Whether this flag was found during parsing */
    FlagValidator validator; /**< Optional custom validation function */
};

/**
 * @struct FlagParser
 * @brief Main parser structure managing all flags, subcommands, and state
 *
 * Supports hierarchical command structures with subcommands, each having
 * their own flags and handlers.
 */
struct FlagParser {
    Arena* arena;      /**< Memory arena for all allocations */
    char* name;        /**< Name of this parser/command */
    char* description; /**< Description shown in help */
    char* footer;      /**< Optional footer text for help */

    Flag* flags;          /**< Dynamic array of registered flags */
    size_t flag_count;    /**< Number of registered flags */
    size_t flag_capacity; /**< Allocated capacity for flags array */

    FlagParser** subcommands; /**< Dynamic array of subcommand parsers */
    size_t cmd_count;         /**< Number of registered subcommands */
    size_t cmd_capacity;      /**< Allocated capacity for subcommands array */

    void (*handler)(void* user_data);    /**< Handler function for this command */
    void (*pre_invoke)(void* user_data); /**< Pre-invocation setup function */

    char** positional_args; /**< Array of positional arguments */
    size_t pos_count;       /**< Number of positional arguments */
    size_t pos_capacity;    /**< Allocated capacity for positional args */

    char last_error[ERR_BUF_SIZE]; /**< Last error message */
    FlagParser* active_subcommand; /**< Active subcommand after parsing */
};

// --- Memory Helpers ---

/**
 * @brief Allocate and copy default value for a flag
 * @param arena The arena to allocate from
 * @param type The data type of the flag
 * @param value_ptr Pointer to the default value
 * @return Allocated copy of the default value, or NULL on failure
 */
static void* copy_default_value(Arena* arena, FlagDataType type, void* value_ptr) {
    if (!value_ptr) return NULL;

    switch (type) {
        case TYPE_BOOL: {
            bool* copy = arena_alloc(arena, sizeof(bool));
            if (copy) *copy = *(bool*)value_ptr;
            return copy;
        }
        case TYPE_CHAR: {
            char* copy = arena_alloc(arena, sizeof(char));
            if (copy) *copy = *(char*)value_ptr;
            return copy;
        }
        case TYPE_STRING: {
            char* str = *(char**)value_ptr;
            return str ? arena_strdup(arena, str) : NULL;
        }
        case TYPE_INT8: {
            int8_t* copy = arena_alloc(arena, sizeof(int8_t));
            if (copy) *copy = *(int8_t*)value_ptr;
            return copy;
        }
        case TYPE_UINT8: {
            uint8_t* copy = arena_alloc(arena, sizeof(uint8_t));
            if (copy) *copy = *(uint8_t*)value_ptr;
            return copy;
        }
        case TYPE_INT16: {
            int16_t* copy = arena_alloc(arena, sizeof(int16_t));
            if (copy) *copy = *(int16_t*)value_ptr;
            return copy;
        }
        case TYPE_UINT16: {
            uint16_t* copy = arena_alloc(arena, sizeof(uint16_t));
            if (copy) *copy = *(uint16_t*)value_ptr;
            return copy;
        }
        case TYPE_INT32: {
            int32_t* copy = arena_alloc(arena, sizeof(int32_t));
            if (copy) *copy = *(int32_t*)value_ptr;
            return copy;
        }
        case TYPE_UINT32: {
            uint32_t* copy = arena_alloc(arena, sizeof(uint32_t));
            if (copy) *copy = *(uint32_t*)value_ptr;
            return copy;
        }
        case TYPE_INT64: {
            int64_t* copy = arena_alloc(arena, sizeof(int64_t));
            if (copy) *copy = *(int64_t*)value_ptr;
            return copy;
        }
        case TYPE_UINT64: {
            uint64_t* copy = arena_alloc(arena, sizeof(uint64_t));
            if (copy) *copy = *(uint64_t*)value_ptr;
            return copy;
        }
        case TYPE_SIZE_T: {
            size_t* copy = arena_alloc(arena, sizeof(size_t));
            if (copy) *copy = *(size_t*)value_ptr;
            return copy;
        }
        case TYPE_FLOAT: {
            float* copy = arena_alloc(arena, sizeof(float));
            if (copy) *copy = *(float*)value_ptr;
            return copy;
        }
        case TYPE_DOUBLE: {
            double* copy = arena_alloc(arena, sizeof(double));
            if (copy) *copy = *(double*)value_ptr;
            return copy;
        }
        default:
            return NULL;
    }
}

/**
 * @brief Format default value as string for display
 * @param type The data type of the flag
 * @param default_ptr Pointer to the default value
 * @param buf Buffer to write formatted string into
 * @param buf_size Size of the buffer
 */
static void format_default_value(FlagDataType type, void* default_ptr, char* buf, size_t buf_size) {
    if (!default_ptr || !buf || buf_size == 0) {
        buf[0] = '\0';
        return;
    }

    switch (type) {
        case TYPE_BOOL:
            snprintf(buf, buf_size, "%s", *(bool*)default_ptr ? "true" : "false");
            break;
        case TYPE_CHAR:
            snprintf(buf, buf_size, "'%c'", *(char*)default_ptr);
            break;
        case TYPE_STRING: {
            char* str = (char*)default_ptr;
            snprintf(buf, buf_size, "\"%s\"", str ? str : "");
            break;
        }
        case TYPE_INT8:
            snprintf(buf, buf_size, "%d", *(int8_t*)default_ptr);
            break;
        case TYPE_UINT8:
            snprintf(buf, buf_size, "%u", *(uint8_t*)default_ptr);
            break;
        case TYPE_INT16:
            snprintf(buf, buf_size, "%d", *(int16_t*)default_ptr);
            break;
        case TYPE_UINT16:
            snprintf(buf, buf_size, "%u", *(uint16_t*)default_ptr);
            break;
        case TYPE_INT32:
            snprintf(buf, buf_size, "%d", *(int32_t*)default_ptr);
            break;
        case TYPE_UINT32:
            snprintf(buf, buf_size, "%u", *(uint32_t*)default_ptr);
            break;
        case TYPE_INT64:
            snprintf(buf, buf_size, "%lld", (long long)*(int64_t*)default_ptr);
            break;
        case TYPE_UINT64:
            snprintf(buf, buf_size, "%llu", (unsigned long long)*(uint64_t*)default_ptr);
            break;
        case TYPE_SIZE_T:
            snprintf(buf, buf_size, "%zu", *(size_t*)default_ptr);
            break;
        case TYPE_FLOAT:
            snprintf(buf, buf_size, "%.6g", *(float*)default_ptr);
            break;
        case TYPE_DOUBLE:
            snprintf(buf, buf_size, "%.6g", *(double*)default_ptr);
            break;
        default:
            buf[0] = '\0';
            break;
    }
}

// --- Lifecycle ---

/**
 * @brief Create a new flag parser
 * @param name Name of the program or command
 * @param description Description shown in help text
 * @return A valid pointer to the allocated FlagParser, or NULL on
 *         arena allocation failure.
 *
 * The returned parser must be freed with flag_parser_free() when done.
 */
FlagParser* flag_parser_new(const char* name, const char* description) {
    // Create arena with default size
    Arena* arena = arena_create(0);
    if (!arena) {
        return NULL;
    }

    FlagParser* fp = arena_alloc_zero(arena, sizeof(FlagParser));
    if (!fp) {
        arena_destroy(arena);
        return NULL;
    }

    fp->arena = arena;
    fp->name = arena_strdup(arena, name);
    fp->description = arena_strdup(arena, description);
    return fp;
}

/**
 * @brief Free a flag parser and all associated resources
 * @param fp Parser to free
 *
 * Recursively frees all subcommands and their flags. Safe to call with NULL.
 */
void flag_parser_free(FlagParser* fp) {
    if (!fp) return;
    arena_destroy(fp->arena);
}

/**
 * @brief Set optional footer text for help output
 * @param parser Parser to configure
 * @param footer Footer text (will be copied)
 */
void flag_parser_set_footer(FlagParser* parser, const char* footer) {
    if (!parser) return;
    parser->footer = arena_strdup(parser->arena, footer);
}

/**
 * @brief Set pre-invocation callback for a parser
 * @param fp Parser to configure
 * @param pre_invoke Function to call before command handler
 *
 * The pre_invoke callback is called before the command handler, useful
 * for global setup or initialization.
 */
void flag_set_pre_invoke(FlagParser* fp, void (*pre_invoke)(void* user_data)) {
    if (fp) {
        fp->pre_invoke = pre_invoke;
    }
}

// --- Registration ---

/**
 * @brief Register a new flag with the parser
 * @param fp Parser to add flag to
 * @param type Data type of the flag value
 * @param name Long name (used with --)
 * @param short_name Short name (used with -), or 0 for none
 * @param desc Description for help text
 * @param value_ptr Pointer to variable that will receive parsed value
 * @param required Whether this flag is required
 * @return Pointer to created Flag for further configuration, or NULL on error
 *
 * The value_ptr should point to a variable with the initial default value.
 * This default will be preserved and displayed in help text.
 *
 * @example
 * ```c
 * int port = 8080;  // Default value
 * Flag* f = flag_add(fp, TYPE_INT32, "port", 'p', "Server port", &port, false);
 * flag_set_validator(f, my_port_validator);
 * ```
 */
Flag* flag_add(FlagParser* fp, FlagDataType type, const char* name, char short_name, const char* desc, void* value_ptr,
               bool required) {
    if (!fp || !name || !value_ptr) return NULL;

    if (fp->flag_count >= fp->flag_capacity) {
        size_t new_cap = (fp->flag_capacity == 0) ? INITIAL_CAPACITY : fp->flag_capacity * 2;
        Flag* new_flags = arena_alloc(fp->arena, sizeof(Flag) * new_cap);
        if (!new_flags) return NULL;
        if (fp->flags) {
            memcpy(new_flags, fp->flags, fp->flag_count * sizeof(Flag));
        }
        fp->flags = new_flags;
        fp->flag_capacity = new_cap;
    }

    Flag* f = &fp->flags[fp->flag_count++];
    f->type = type;
    f->name = arena_strdup(fp->arena, name);
    f->short_name = short_name;
    f->description = arena_strdup(fp->arena, desc);
    f->value_ptr = value_ptr;
    f->required = required;
    f->is_present = false;
    f->validator = NULL;

    // Copy the default value for display in help
    f->default_ptr = copy_default_value(fp->arena, type, value_ptr);
    return f;
}

/**
 * @brief Add a subcommand to the parser
 * @param fp Parent parser
 * @param name Name of the subcommand
 * @param desc Description for help text
 * @param handler Function to call when this subcommand is invoked
 * @return Newly created parser for the subcommand, or NULL on error
 *
 * Subcommands allow hierarchical command structures like "git commit" or "docker run".
 * The returned parser can have its own flags registered.
 *
 * @example
 * ```c
 * FlagParser* fp = flag_parser_new("myapp", "My application");
 * FlagParser* commit = flag_add_subcommand(fp, "commit", "Commit changes", handle_commit);
 * flag_add(commit, TYPE_STRING, "message", 'm', "Commit message", &msg, true);
 * ```
 */
FlagParser* flag_add_subcommand(FlagParser* fp, const char* name, const char* desc, void (*handler)(void* data)) {
    if (!fp || !name) return NULL;
    if (fp->cmd_count >= fp->cmd_capacity) {
        size_t new_cap = (fp->cmd_capacity == 0) ? INITIAL_CAPACITY : fp->cmd_capacity * 2;
        FlagParser** new_cmds = arena_alloc(fp->arena, sizeof(FlagParser*) * new_cap);
        if (!new_cmds) return NULL;
        if (fp->subcommands) {
            memcpy(new_cmds, fp->subcommands, fp->cmd_count * sizeof(FlagParser*));
        }
        fp->subcommands = new_cmds;
        fp->cmd_capacity = new_cap;
    }

    // Subcommands share the same arena as the root
    FlagParser* sub = arena_alloc_zero(fp->arena, sizeof(*sub));
    if (!sub) return NULL;

    sub->arena = fp->arena;
    sub->name = arena_strdup(fp->arena, name);
    sub->description = arena_strdup(fp->arena, desc);
    sub->handler = handler;
    sub->pre_invoke = NULL;
    fp->subcommands[fp->cmd_count++] = sub;
    return sub;
}

// --- Subcommand Invocation ---

/**
 * @brief Invoke the active subcommand with optional pre-invoke callback
 * @param fp Parser with active subcommand
 * @param pre_invoke Optional callback to run before handler
 * @param user_data User data passed to callbacks
 * @return true if subcommand was invoked, false if no active subcommand
 *
 * This is typically used for manual invocation. For automatic invocation
 * after parsing, use flag_parse_and_invoke() instead.
 */
bool flag_invoke_subcommand(FlagParser* fp, void (*pre_invoke)(void* user_data), void* user_data) {
    if (!fp || !fp->active_subcommand) {
        return false;
    }

    FlagParser* sub = fp->active_subcommand;

    // Run pre-invocation callback if provided
    if (pre_invoke) {
        pre_invoke(user_data);
    }

    // Invoke the subcommand handler if it exists
    if (sub->handler) {
        sub->handler(user_data);
    }

    return true;
}

/**
 * @brief Set a custom validator for a flag
 * @param flag Flag to add validator to
 * @param validator Validation function
 *
 * The validator is called after parsing if the flag is present.
 * It should return true if valid, false otherwise, and can set an error message.
 *
 * @example
 * ```c
 * bool validate_port(void* value, const char** err) {
 *     int port = *(int*)value;
 *     if (port < 1 || port > 65535) {
 *         *err = "Port must be between 1 and 65535";
 *         return false;
 *     }
 *     return true;
 * }
 * flag_set_validator(flag, validate_port);
 * ```
 */
void flag_set_validator(Flag* flag, FlagValidator validator) {
    if (flag) flag->validator = validator;
}

// --- Parsing Internals ---

/**
 * @brief Set error message on parser
 * @param fp Parser to set error on
 * @param fmt Printf-style format string
 * @param ... Format arguments
 */
static void set_error(FlagParser* fp, const char* fmt, ...) {
    if (!fp) return;
    va_list args;
    va_start(args, fmt);
    vsnprintf(fp->last_error, ERR_BUF_SIZE, fmt, args);
    va_end(args);
}

/**
 * @brief Find a flag by long name
 * @param fp Parser to search
 * @param name Long name to find
 * @return Pointer to flag, or NULL if not found
 */
static Flag* find_flag_long(FlagParser* fp, const char* name) {
    if (!fp || !name) return NULL;
    for (size_t i = 0; i < fp->flag_count; i++) {
        if (strcmp(fp->flags[i].name, name) == 0) return &fp->flags[i];
    }
    return NULL;
}

/**
 * @brief Find a flag by short name
 * @param fp Parser to search
 * @param c Short name character to find
 * @return Pointer to flag, or NULL if not found
 */
static Flag* find_flag_short(FlagParser* fp, char c) {
    if (!fp || !c) return NULL;
    for (size_t i = 0; i < fp->flag_count; i++) {
        if (fp->flags[i].short_name == c) return &fp->flags[i];
    }
    return NULL;
}

/**
 * @brief Parse a boolean flag value strictly.
 *
 * Accepts (case-insensitive): true/false, yes/no, on/off, 1/0.
 * Everything else is rejected rather than silently meaning "true".
 *
 * @param str Value text
 * @param out Receives the parsed boolean
 * @return true when recognized, false otherwise
 */
static bool parse_bool_value(const char* str, bool* out) {
    static const struct {
        const char* name;
        bool val;
    } table[] = {
        {"true", true}, {"false", false}, {"yes", true}, {"no", false},
        {"on", true},   {"off", false},   {"1", true},   {"0", false},
    };
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (strcasecmp(str, table[i].name) == 0) {
            *out = table[i].val;
            return true;
        }
    }
    return false;
}

/**
 * @brief Decide whether an argv token may be consumed as a flag VALUE.
 *
 * Tokens not starting with '-' are always consumable.  A token starting
 * with '-' is still consumable when it parses as a number, so negative
 * values work without a separator:  --offset -5   -a -2.5
 */
static bool is_value_token(const char* s) {
    if (!s || !*s) return false;
    if (s[0] != '-') return true;
    if (s[1] == '\0') return false; /* bare "-" is positional by convention */
    char* end = NULL;
    (void)strtod(s, &end);
    return end != s && *end == '\0';
}

/**
 * @brief Check if signed integer is within range
 * @param val Value to check
 * @param min Minimum allowed value
 * @param max Maximum allowed value
 * @return true if in range
 */
static bool check_range_int(long long val, long long min, long long max) { return (val >= min && val <= max); }

/**
 * @brief Check if unsigned integer is within range
 * @param val Value to check
 * @param max Maximum allowed value
 * @return true if in range
 */
static bool check_range_uint(unsigned long long val, unsigned long long max) { return (val <= max); }

/**
 * @brief Parse a string value into a flag's data type
 * @param flag Flag to parse value for
 * @param str String representation of value
 * @return FLAG_OK on success, error code otherwise
 *
 * Handles all supported data types with proper range checking and error detection.
 */
static FlagStatus parse_value(FlagParser* fp, Flag* flag, const char* str) {
    if (!str) return FLAG_ERROR_MISSING_VALUE;
    char* endptr = NULL;
    errno = 0;

    switch (flag->type) {
        case TYPE_BOOL: {
            bool val = false;
            if (!parse_bool_value(str, &val)) return FLAG_ERROR_INVALID_ARGUMENT;
            *(bool*)flag->value_ptr = val;
            break;
        }
        case TYPE_CHAR:
            if (!str || strlen(str) == 0) return FLAG_ERROR_MISSING_VALUE;
            if (strlen(str) != 1) return FLAG_ERROR_INVALID_ARGUMENT;
            *(char*)flag->value_ptr = str[0];
            break;
        case TYPE_STRING:
            // Don't free the old value - we don't know if it's malloc'd or static,
            // and we are moving to arena-managed strings.
            // if (*(char**)flag->value_ptr) free(*(char**)flag->value_ptr);
            *(char**)flag->value_ptr = arena_strdup(fp->arena, str);
            break;

        // Signed Integers
        case TYPE_INT8:
        case TYPE_INT16:
        case TYPE_INT32:
        case TYPE_INT64: {
            long long val = strtoll(str, &endptr, 10);
            if (endptr == str || *endptr != '\0' || errno == ERANGE) return FLAG_ERROR_INVALID_NUMBER;

            if (flag->type == TYPE_INT8 && !check_range_int(val, INT8_MIN, INT8_MAX)) return FLAG_ERROR_INVALID_NUMBER;
            if (flag->type == TYPE_INT16 && !check_range_int(val, INT16_MIN, INT16_MAX))
                return FLAG_ERROR_INVALID_NUMBER;
            if (flag->type == TYPE_INT32 && !check_range_int(val, INT32_MIN, INT32_MAX))
                return FLAG_ERROR_INVALID_NUMBER;

            // Assign based on type size
            if (flag->type == TYPE_INT8)
                *(int8_t*)flag->value_ptr = (int8_t)val;
            else if (flag->type == TYPE_INT16)
                *(int16_t*)flag->value_ptr = (int16_t)val;
            else if (flag->type == TYPE_INT32)
                *(int32_t*)flag->value_ptr = (int32_t)val;
            else
                *(int64_t*)flag->value_ptr = (int64_t)val;
            break;
        }

        // Unsigned Integers
        case TYPE_UINT8:
        case TYPE_UINT16:
        case TYPE_UINT32:
        case TYPE_UINT64:
        case TYPE_SIZE_T: {
            if (str[0] == '-') return FLAG_ERROR_INVALID_NUMBER;
            unsigned long long val = strtoull(str, &endptr, 10);
            if (endptr == str || *endptr != '\0' || errno == ERANGE) return FLAG_ERROR_INVALID_NUMBER;

            if (flag->type == TYPE_UINT8 && !check_range_uint(val, UINT8_MAX)) return FLAG_ERROR_INVALID_NUMBER;
            if (flag->type == TYPE_UINT16 && !check_range_uint(val, UINT16_MAX)) return FLAG_ERROR_INVALID_NUMBER;
            if (flag->type == TYPE_UINT32 && !check_range_uint(val, UINT32_MAX)) return FLAG_ERROR_INVALID_NUMBER;
            if (flag->type == TYPE_SIZE_T && !check_range_uint(val, SIZE_MAX)) return FLAG_ERROR_INVALID_NUMBER;

            if (flag->type == TYPE_UINT8)
                *(uint8_t*)flag->value_ptr = (uint8_t)val;
            else if (flag->type == TYPE_UINT16)
                *(uint16_t*)flag->value_ptr = (uint16_t)val;
            else if (flag->type == TYPE_UINT32)
                *(uint32_t*)flag->value_ptr = (uint32_t)val;
            else if (flag->type == TYPE_SIZE_T)
                *(size_t*)flag->value_ptr = (size_t)val;
            else
                *(uint64_t*)flag->value_ptr = (uint64_t)val;
            break;
        }

        case TYPE_FLOAT: {
            float val = strtof(str, &endptr);
            if (endptr == str || *endptr != '\0' || errno == ERANGE) return FLAG_ERROR_INVALID_NUMBER;
            *(float*)flag->value_ptr = val;
            break;
        }
        case TYPE_DOUBLE: {
            double val = strtod(str, &endptr);
            if (endptr == str || *endptr != '\0' || errno == ERANGE) return FLAG_ERROR_INVALID_NUMBER;
            *(double*)flag->value_ptr = val;
            break;
        }
        default:
            return FLAG_ERROR_INVALID_ARGUMENT;
    }
    return FLAG_OK;
}

// --- Main Parse Logic ---

/**
 * @brief Parse command-line arguments
 * @param fp Parser to use
 * @param argc Argument count (from main)
 * @param argv Argument vector (from main)
 * @return FLAG_OK on success, error code otherwise
 *
 * Parses argv according to registered flags and subcommands. Supports:
 * - Long flags: --flag=value or --flag value
 * - Short flags: -f value or -fvalue
 * - Boolean flags: --flag (no value needed)
 * - Flag combinations: -abc (multiple boolean flags)
 * - End of options: -- (remaining args are positional)
 * - Automatic --help handling
 *
 * After successful parsing, use flag_get_error() to retrieve error messages,
 * flag_positional_at() to access positional args, and flag_is_present() to
 * check if optional flags were provided.
 */
FlagStatus flag_parse(FlagParser* fp, int argc, char** argv) {
    if (!fp || argc < 1) return FLAG_ERROR_INVALID_ARGUMENT;

    int i = 1;
    bool end_of_opts = false;

    while (i < argc) {
        char* arg = argv[i];

        // 1. End of Options
        if (!end_of_opts && strcmp(arg, "--") == 0) {
            end_of_opts = true;
            i++;
            continue;
        }

        // 2. Positionals (or Subcommands)
        if (end_of_opts || arg[0] != '-') {
            // Check subcommands
            if (!end_of_opts && fp->cmd_count > 0) {
                for (size_t c = 0; c < fp->cmd_count; c++) {
                    if (strcmp(fp->subcommands[c]->name, arg) == 0) {
                        fp->active_subcommand = fp->subcommands[c];
                        // Recursive call for subcommand
                        return flag_parse(fp->active_subcommand, argc - i, argv + i);
                    }
                }
            }

            // Add positional
            if (fp->pos_count >= fp->pos_capacity) {
                size_t new_cap = (fp->pos_capacity == 0) ? INITIAL_CAPACITY : fp->pos_capacity * 2;
                char** new_pos = arena_alloc(fp->arena, sizeof(char*) * new_cap);
                if (!new_pos) {
                    fprintf(stderr, "failed to allocated new positional args");
                    exit(EXIT_FAILURE);
                }

                if (fp->positional_args) {
                    memcpy(new_pos, fp->positional_args, fp->pos_count * sizeof(char*));
                }
                fp->positional_args = new_pos;
                fp->pos_capacity = new_cap;
            }

            fp->positional_args[fp->pos_count++] = arg;
            i++;
            continue;
        }

        // 3. Long Flags
        if (strncmp(arg, "--", 2) == 0) {
            char* name_start = arg + 2;
            if (strcmp(name_start, "help") == 0) {
                flag_print_usage(fp);
                exit(0);
            }

            char* eq = strchr(name_start, '=');
            char name_buf[MAX_FLAG_NAME_LEN];
            const char* val_str = NULL;
            const char* lookup_name = name_start;

            if (eq) {
                size_t len = (size_t)(eq - name_start);
                if (len >= MAX_FLAG_NAME_LEN) len = MAX_FLAG_NAME_LEN - 1;
                memcpy(name_buf, name_start, len);
                name_buf[len] = '\0';
                lookup_name = name_buf;
                val_str = eq + 1;
            }

            Flag* f = find_flag_long(fp, lookup_name);
            if (!f) {
                set_error(fp, "Unknown flag: --%s", lookup_name);
                return FLAG_ERROR_UNKNOWN_FLAG;
            }

            f->is_present = true;

            if (f->type == TYPE_BOOL) {
                bool b = true;
                if (val_str && !parse_bool_value(val_str, &b)) {
                    set_error(fp, "Invalid value for --%s: '%s' (expected true/false)", f->name, val_str);
                    return FLAG_ERROR_INVALID_ARGUMENT;
                }
                *(bool*)f->value_ptr = b;
            } else {
                if (!val_str) {
                    if (i + 1 < argc && is_value_token(argv[i + 1]))
                        val_str = argv[++i];
                    else {
                        set_error(fp, "Flag --%s requires a value", f->name);
                        return FLAG_ERROR_MISSING_VALUE;
                    }
                }
                FlagStatus s = parse_value(fp, f, val_str);
                if (s != FLAG_OK) {
                    set_error(fp, "Invalid value for --%s: '%s' (Type mismatch or overflow)", f->name, val_str);
                    return s;
                }
            }
            i++;
            continue;
        }

        // 4. Short Flags
        if (arg[0] == '-') {
            size_t len = strlen(arg);
            for (size_t k = 1; k < len; k++) {
                char c = arg[k];
                Flag* f = find_flag_short(fp, c);
                if (!f) {
                    set_error(fp, "Unknown short flag: -%c", c);
                    return FLAG_ERROR_UNKNOWN_FLAG;
                }
                f->is_present = true;

                if (f->type == TYPE_BOOL) {
                    *(bool*)f->value_ptr = true;
                } else {
                    const char* val_str = NULL;
                    if (k + 1 < len) {
                        val_str = &arg[k + 1];
                        if (*val_str == '=') val_str++;
                        FlagStatus s = parse_value(fp, f, val_str);
                        if (s != FLAG_OK) {
                            set_error(fp, "Invalid value for -%c (Type mismatch or overflow)", c);
                            return s;
                        }
                        break;  // consumed rest
                    } else {
                        if (i + 1 < argc && is_value_token(argv[i + 1])) {
                            val_str = argv[++i];
                            FlagStatus s = parse_value(fp, f, val_str);
                            if (s != FLAG_OK) {
                                set_error(fp, "Invalid value for -%c (Type mismatch or overflow)", c);
                                return s;
                            }
                        } else {
                            set_error(fp, "Flag -%c requires a value", c);
                            return FLAG_ERROR_MISSING_VALUE;
                        }
                    }
                }
            }
            i++;
            continue;
        }
    }

    // Validation
    for (size_t k = 0; k < fp->flag_count; k++) {
        Flag* f = &fp->flags[k];
        if (f->required && !f->is_present) {
            set_error(fp, "Missing required flag: --%s", f->name);
            return FLAG_ERROR_REQUIRED_MISSING;
        }

        if (f->is_present && f->validator) {
            if (f->value_ptr == NULL) {
                set_error(fp, "Validation failed for --%s: %s", f->name, "value is NULL");
                return FLAG_ERROR_VALIDATION;
            }

            const char* err = NULL;
            if (!f->validator(f->value_ptr, &err)) {
                set_error(fp, "Validation failed for --%s: %s", f->name, err ? err : "invalid");
                return FLAG_ERROR_VALIDATION;
            }
        }
    }

    return FLAG_OK;
}

/**
 * @brief Parse arguments and automatically invoke the appropriate handler
 * @param fp Parser to use
 * @param argc Argument count (from main)
 * @param argv Argument vector (from main)
 * @param user_data User data to pass to handlers
 * @return FLAG_OK on success, error code otherwise
 *
 * This is a convenience function that combines parsing with handler invocation.
 * After successful parsing, it calls:
 * 1. The pre_invoke callback (if set)
 * 2. The handler of the deepest active subcommand (or main handler if no subcommand)
 *
 * @example
 * ```c
 * int main(int argc, char** argv) {
 *     FlagParser* fp = flag_parser_new("myapp", "My application");
 *     // ... register flags ...
 *
 *     MyAppData data = {0};
 *     FlagStatus status = flag_parse_and_invoke(fp, argc, argv, &data);
 *
 *     if (status != FLAG_OK) {
 *         fprintf(stderr, "Error: %s\n", flag_get_error(fp));
 *         return 1;
 *     }
 *
 *     flag_parser_free(fp);
 *     return 0;
 * }
 * ```
 */
FlagStatus flag_parse_and_invoke(FlagParser* fp, int argc, char** argv, void* user_data) {
    if (!fp || argc < 1) {
        return FLAG_ERROR_INVALID_ARGUMENT;
    }

    // Parse all arguments
    FlagStatus status = flag_parse(fp, argc, argv);
    if (status != FLAG_OK) {
        return status;
    }

    // Run pre-invocation callback (Global setup)
    if (fp->pre_invoke) {
        fp->pre_invoke(user_data);
    }

    // Find the deepest active subcommand (The "Leaf" command)
    FlagParser* target = fp;
    while (target->active_subcommand) {
        target = target->active_subcommand;
    }

    // Run the handler for the target command
    if (target->handler) {
        target->handler(user_data);
    }

    return FLAG_OK;
}

// --- Usage / Help ---

/**
 * @brief Convert data type to string representation
 * @param t Data type
 * @return String representation for help text
 */
static const char* type_to_str(FlagDataType t) {
    switch (t) {
        case TYPE_BOOL:
            return "";
        case TYPE_CHAR:
            return "CHAR";
        case TYPE_STRING:
            return "STR";
        case TYPE_INT8:
            return "INT8";
        case TYPE_UINT8:
            return "UINT8";
        case TYPE_INT16:
            return "INT16";
        case TYPE_UINT16:
            return "UINT16";
        case TYPE_INT32:
            return "INT";
        case TYPE_UINT32:
            return "UINT";
        case TYPE_INT64:
            return "INT64";
        case TYPE_UINT64:
            return "UINT64";
        case TYPE_SIZE_T:
            return "SIZE";
        case TYPE_FLOAT:
            return "FLOAT";
        case TYPE_DOUBLE:
            return "DBL";
        default:
            return "VAL";
    }
}

/**
 * @brief Calculate max width for flag column alignment
 */
static size_t calculate_flag_width(FlagParser* fp) {
    size_t max_width = 0;
    for (size_t i = 0; i < fp->flag_count; i++) {
        // Calculation: "  -s, --long-name=TYPE"
        size_t w = 6;                        // indent(2) + "-x, " (4)
        w += strlen(fp->flags[i].name) + 2;  // "--" + name

        if (fp->flags[i].type != TYPE_BOOL) {
            w += 1 + strlen(type_to_str(fp->flags[i].type));  // "=" + TYPE
        }

        if (w > max_width) max_width = w;
    }
    return max_width;
}

/**
 * @brief Calculate max width for subcommand name alignment
 */
static size_t calculate_cmd_width(FlagParser* fp) {
    size_t max_width = 0;
    for (size_t i = 0; i < fp->cmd_count; i++) {
        size_t w = strlen(fp->subcommands[i]->name) + 4;  // indent(2) + name + padding(2)
        if (w > max_width) max_width = w;
    }
    return max_width;
}

/**
 * @brief Print a single flag row
 */
static void print_flag_row(Flag* f, size_t max_width) {
    char left[256];
    int pos = 0;

    //  Short name column
    if (f->short_name) {
        pos += snprintf(left + pos, sizeof(left) - (size_t)pos, "  -%c, ", f->short_name);
    } else {
        pos += snprintf(left + pos, sizeof(left) - (size_t)pos, "      ");
    }

    // Long name column
    pos += snprintf(left + pos, sizeof(left) - (size_t)pos, "--%s", f->name);

    // Type column
    if (f->type != TYPE_BOOL) {
        pos += snprintf(left + pos, sizeof(left) - (size_t)pos, "=%s", type_to_str(f->type));
    }

    // Print Left Column aligned, then Description
    printf("%-*s  %s", (int)max_width, left, f->description ? f->description : "");

    // 4. Metadata (Required / Default)
    if (f->required) {
        printf(" (Required)");
    } else if (f->default_ptr) {
        char default_str[MAX_DEFAULT_STR];
        format_default_value(f->type, f->default_ptr, default_str, sizeof(default_str));
        if (default_str[0] != '\0') {
            printf(" (default: %s)", default_str);
        }
    }
    printf("\n");
}

/**
 * @brief Internal function to print help for a specific parser node (non-recursive)
 */
static void print_help_internal(FlagParser* fp) {
    if (!fp) return;

    // --- 1. Header & Description ---
    printf("\n%s\n", fp->description ? fp->description : fp->name);

    printf("\nUsage:\n  %s", fp->name);
    if (fp->flag_count > 0) printf(" [flags]");
    if (fp->cmd_count > 0) printf(" [command]");
    printf("\n");

    // Flags (Current level only) ---
    if (fp->flag_count > 0) {
        printf("\nFlags:\n");
        size_t width = calculate_flag_width(fp);
        if (width < 20) width = 20;

        for (size_t i = 0; i < fp->flag_count; i++) {
            print_flag_row(&fp->flags[i], width);
        }
    }

    // Subcommands (Immediate children only) ---
    if (fp->cmd_count > 0) {
        printf("\nAvailable Commands:\n");
        size_t width = calculate_cmd_width(fp);
        if (width < 20) width = 20;  // Minimum width

        for (size_t i = 0; i < fp->cmd_count; i++) {
            FlagParser* sub = fp->subcommands[i];
            printf("  %-*s%s\n", (int)(width - 2), sub->name, sub->description ? sub->description : "");
        }
    }

    // --- 4. Footer ---
    if (fp->footer) {
        printf("\n%s\n", fp->footer);
    } else if (fp->cmd_count > 0) {
        printf("\nUse \"%s [command] --help\" for more information about a command.\n", fp->name);
    }
}

/**
 * @brief Print usage/help information for the parser
 *
 * Automatically detects the active context. If a subcommand was selected
 * (parsed) or manually set active, help is shown for that subcommand.
 * Otherwise, help is shown for the root.
 */
void flag_print_usage(FlagParser* fp) {
    if (!fp) return;

    // Traverse to the deepest active subcommand to show context-sensitive help
    FlagParser* leaf = fp;
    while (leaf->active_subcommand) {
        leaf = leaf->active_subcommand;
    }

    print_help_internal(leaf);
}

// --- Accessors ---

/**
 * @brief Get the last error message
 * @param fp Parser to get error from
 * @return Error string, or empty string if no error
 *
 * Returns the error message from the most recently failed parse operation.
 * If a subcommand is active, returns that subcommand's error instead.
 */
const char* flag_get_error(FlagParser* fp) {
    if (!fp) return "";

    FlagParser* root = fp;

    if (root->active_subcommand) {
        root = fp->active_subcommand;
        while (root->active_subcommand) root = root->active_subcommand;
    }
    return root->last_error;
}

/** Get the pointer to the active subcommand. Pass in the root Parser as the only argument */
FlagParser* flag_active_subcommand(FlagParser* parser) {
    FlagParser* target = parser;
    while (target && target->active_subcommand) {
        target = target->active_subcommand;
    }
    return target;
}

/**
 * @brief Get count of positional arguments
 * @param fp Parser to query
 * @return Number of positional arguments
 */
int flag_positional_count(FlagParser* fp) { return fp ? (int)fp->pos_count : 0; }

/**
 * @brief Get positional argument at index
 * @param fp Parser to query
 * @param i Index of positional argument (0-based)
 * @return Positional argument string, or NULL if index out of range
 *
 * @example
 * ```c
 * // For command: myapp file1.txt file2.txt
 * flag_positional_at(fp, 0); // returns "file1.txt"
 * flag_positional_at(fp, 1); // returns "file2.txt"
 * ```
 */
const char* flag_positional_at(FlagParser* fp, int i) {
    return (fp && i >= 0 && (size_t)i < fp->pos_count) ? fp->positional_args[i] : NULL;
}

/**
 * @brief Check if a flag was present in the parsed arguments
 * @param fp Parser to query
 * @param name Long name of the flag
 * @return true if flag was present, false otherwise
 *
 * Useful for distinguishing between a flag not provided vs. provided with default value.
 *
 * @example
 * ```c
 * if (flag_is_present(fp, "verbose")) {
 *     printf("Verbose mode explicitly enabled\n");
 * }
 * ```
 */
bool flag_is_present(FlagParser* fp, const char* name) {
    Flag* f = find_flag_long(fp, name);
    return f ? f->is_present : false;
}

/**
 * @brief Convert FlagStatus code to string
 * @param s Status code
 * @return Human-readable status string
 */
const char* flag_status_str(FlagStatus s) {
    switch (s) {
        case FLAG_OK:
            return "OK";
        case FLAG_ERROR_MISSING_VALUE:
            return "Missing Value";
        case FLAG_ERROR_UNKNOWN_FLAG:
            return "Unknown Flag";
        case FLAG_ERROR_INVALID_NUMBER:
            return "Invalid Number";
        case FLAG_ERROR_VALIDATION:
            return "Validation Failed";
        case FLAG_ERROR_REQUIRED_MISSING:
            return "Required Flag Missing";
        case FLAG_ERROR_UNKNOWN_SUBCOMMAND:
            return "Unknown subcommand";
        case FLAG_ERROR_INVALID_ARGUMENT:
            return "Invalid Argument";
        default:
            return "Error";
    }
}

// ================ Shell completion =====================================
#include <ctype.h>

// --- Completion Generation Internals ---

// Static context to hold completion configuration
// This is necessary because the handler signature is fixed (void* user_data)
// and we need access to the root parser and specific flags during the callback.
static struct {
    FlagParser* root;
    char* shell;
    char* output;
} _comp_ctx = {0};

/**
 * @brief Escape text for use inside Zsh _arguments descriptions.
 *
 * These descriptions are embedded inside single-quoted strings. Apostrophes
 * are escaped as \' rather than the shell '\'' trick, because _arguments
 * does its own internal escape-aware re-parsing of [message] content, and
 * an unescaped quote there breaks that re-parsing even though the outer
 * shell quoting itself is fine. Other Zsh metacharacters are backslashed.
 */
static void write_zsh_description(FILE* f, const char* str) {
    if (!f || !str) return;

    for (const char* p = str; *p; ++p) {
        switch (*p) {
            case '\'':
                // \' (not '\'') -- see function doc comment.
                fprintf(f, "'\\''");
                break;
            case '[':
                fprintf(f, "\\[");
                break;
            case ']':
                fprintf(f, "\\]");
                break;
            case ':':
                fprintf(f, "\\:");
                break;
            case '\\':
                fprintf(f, "\\\\");
                break;
            default:
                fputc(*p, f);
                break;
        }
    }
}

/**
 * @brief Escape text for use inside Zsh subcommand lists ((name\:description)).
 *
 * Escapes single quotes, colons, spaces, parenthesis, and brackets in a
 * single-quoted Zsh string context. Apostrophes use the standard '\''
 * idiom (see write_zsh_description); _arguments re-parses the
 * ((value\:desc ...)) list internally, so colons stay backslashed.
 */
static void write_zsh_cmd_desc(FILE* f, const char* str) {
    if (!f || !str) return;

    for (const char* p = str; *p; ++p) {
        switch (*p) {
            case '\'':
                fprintf(f, "'\\''");
                break;
            case ' ':
            case '\t':
                fprintf(f, "\\ ");
                break;
            case ':':
                fprintf(f, "\\:");
                break;
            case '[':
                fprintf(f, "\\[");
                break;
            case ']':
                fprintf(f, "\\]");
                break;
            case '(':
                fprintf(f, "\\(");
                break;
            case ')':
                fprintf(f, "\\)");
                break;
            case '\\':
                fprintf(f, "\\\\");
                break;
            default:
                fputc(*p, f);
                break;
        }
    }
}

/**
 * @brief Write a valid shell identifier by sanitizing the input
 */
static void write_shell_identifier(FILE* f, const char* str) {
    if (!str || !f) return;

    // First char must be letter or underscore
    if (!isalpha(*str) && *str != '_') {
        fputc('_', f);
    }

    for (const char* p = str; *p; p++) {
        if (isalnum(*p) || *p == '_') {
            fputc(*p, f);
        } else {
            fputc('_', f);
        }
    }
}

/**
 * @brief Write a name for use inside a Bash case-statement pattern.
 *
 * Bash case patterns are unquoted glob text. Backslash-escape glob/shell
 * metacharacters so the name matches itself literally instead of being
 * interpreted as a pattern or breaking the case syntax.
 */
static void write_bash_pattern(FILE* f, const char* str) {
    if (!f || !str) return;

    for (const char* p = str; *p; ++p) {
        switch (*p) {
            case '*':
            case '?':
            case '[':
            case ']':
            case '(':
            case ')':
            case '|':
            case '$':
            case '`':
            case '\\':
            case '"':
            case '\'':
            case ' ':
            case '\t':
                fputc('\\', f);
                fputc(*p, f);
                break;
            default:
                fputc(*p, f);
                break;
        }
    }
}

/**
 * @brief Write a name for use inside a Bash double-quoted string, e.g.
 * local flags="--name --name2".
 *
 * Only '"', '\', '$', and '`' are special inside Bash double quotes;
 * nothing else needs (or should get) a backslash here.
 */
static void write_bash_dq(FILE* f, const char* str) {
    if (!f || !str) return;

    for (const char* p = str; *p; ++p) {
        if (*p == '"' || *p == '\\' || *p == '$' || *p == '`') {
            fputc('\\', f);
        }
        fputc(*p, f);
    }
}

/**
 * @brief Recursively flatten all nested subcommands for Bash case statement
 *
 * Bash completion is flatter than Zsh. We map the last active subcommand name
 * to its flags. Note: This handles name collisions by using full paths.
 */
static void write_bash_subcommand_cases(FILE* f, FlagParser* p, const char* prefix) {
    if (!p) return;

    // Build the full command path for this level
    char full_name[512];
    if (prefix && *prefix) {
        snprintf(full_name, sizeof(full_name), "%s_%s", prefix, p->name);
    } else {
        snprintf(full_name, sizeof(full_name), "%s", p->name);
    }

    // Write case for this command (skip root as it's handled separately)
    if (p != _comp_ctx.root && (p->flag_count > 0 || p->cmd_count > 0)) {
        fprintf(f, "        ");
        write_bash_pattern(f, p->name);
        fprintf(f, ")\n");

        // Handle flags that need arguments
        if (p->flag_count > 0) {
            fprintf(f, "            case \"$prev\" in\n");
            for (size_t i = 0; i < p->flag_count; i++) {
                Flag* flag = &p->flags[i];
                if (flag->type != TYPE_BOOL) {
                    fprintf(f, "                --");
                    write_bash_pattern(f, flag->name);
                    if (flag->short_name && isprint(flag->short_name)) {
                        fprintf(f, "|-");
                        fputc(flag->short_name, f);
                    }
                    fprintf(f, ")\n");

                    // Type-specific completion hints
                    switch (flag->type) {
                        case TYPE_STRING:
                            fprintf(f, "                    # File/directory completion\n");
                            fprintf(f,
                                    "                    COMPREPLY=( $(compgen -f -- \"$cur\") "
                                    ")\n");
                            break;
                        default:
                            fprintf(f, "                    # Value expected\n");
                            fprintf(f, "                    return 0\n");
                            break;
                    }

                    fprintf(f, "                    return 0\n");
                    fprintf(f, "                    ;;\n");
                }
            }
            fprintf(f, "            esac\n\n");
        }

        // Complete with this command's flags and immediate subcommands
        fprintf(f, "            local flags=\"");
        for (size_t i = 0; i < p->flag_count; i++) {
            fprintf(f, "--");
            write_bash_dq(f, p->flags[i].name);
            fprintf(f, " ");
        }
        fprintf(f, "\"\n");

        if (p->cmd_count > 0) {
            fprintf(f, "            local subcommands=\"");
            for (size_t i = 0; i < p->cmd_count; i++) {
                write_bash_dq(f, p->subcommands[i]->name);
                fprintf(f, " ");
            }
            fprintf(f, "\"\n");
            fprintf(f,
                    "            COMPREPLY=( $(compgen -W \"$flags $subcommands\" -- \"$cur\") "
                    ")\n");
        } else {
            fprintf(f, "            COMPREPLY=( $(compgen -W \"$flags\" -- \"$cur\") )\n");
        }

        fprintf(f, "            return 0\n");
        fprintf(f, "            ;;\n");
    }

    // Recurse into children with updated prefix
    for (size_t i = 0; i < p->cmd_count; i++) {
        write_bash_subcommand_cases(f, p->subcommands[i], full_name);
    }
}

/**
 * @brief Collect all subcommand names recursively for the global context check
 */
static void write_bash_all_subcommands_list(FILE* f, FlagParser* p) {
    if (!p) return;
    for (size_t i = 0; i < p->cmd_count; i++) {
        write_bash_dq(f, p->subcommands[i]->name);
        fprintf(f, " ");
        write_bash_all_subcommands_list(f, p->subcommands[i]);
    }
}

/**
 * @brief Generate Bash completion script
 */
static void gen_bash_completion(FlagParser* fp, FILE* f) {
    if (!fp || !f) return;

    char* bin_name = fp->name;

    fprintf(f, "#!/usr/bin/env bash\n");
    fprintf(f, "# Bash completion for %s\n", bin_name ? bin_name : "program");
    fprintf(f, "# Generated by flags.c completion generator\n\n");

    fprintf(f, "_");
    write_shell_identifier(f, bin_name);
    fprintf(f, "_completion() {\n");
    fprintf(f, "    local cur prev words cword\n");
    fprintf(f, "    _init_completion || return\n\n");

    fprintf(f, "    local global_flags=\"");
    if (fp->flag_count > 0) {
        for (size_t i = 0; i < fp->flag_count; i++) {
            fprintf(f, "--");
            write_bash_dq(f, fp->flags[i].name);
            fprintf(f, " ");
        }
    }
    fprintf(f, "--help\"\n");

    // Collect ALL subcommands (recursive) for context detection
    fprintf(f, "    local subcommands=\"");
    write_bash_all_subcommands_list(f, fp);
    fprintf(f, "\"\n\n");

    // Handle Global Flags Arguments
    fprintf(f, "    # Handle flags that require arguments\n");
    fprintf(f, "    case \"$prev\" in\n");
    for (size_t i = 0; i < fp->flag_count; i++) {
        Flag* flag = &fp->flags[i];
        if (flag->type != TYPE_BOOL) {
            fprintf(f, "        --");
            write_bash_pattern(f, flag->name);
            if (flag->short_name && isprint(flag->short_name)) {
                fprintf(f, "|-");
                fputc(flag->short_name, f);
            }
            fprintf(f, ")\n");

            // Type-specific hints
            if (flag->type == TYPE_STRING) {
                fprintf(f, "            COMPREPLY=( $(compgen -f -- \"$cur\") )\n");
            }

            fprintf(f, "            return 0\n");
            fprintf(f, "            ;;\n");
        }
    }
    fprintf(f, "    esac\n\n");

    // Context detection - find the active subcommand
    fprintf(f, "    # Detect active subcommand context\n");
    fprintf(f, "    local cmd_context=\"\"\n");
    fprintf(f, "    local i\n");
    fprintf(f, "    for ((i=1; i < cword; i++)); do\n");
    fprintf(f, "        local word=\"${words[i]}\"\n");
    fprintf(f, "        # Skip flags\n");
    fprintf(f, "        if [[ \"$word\" != -* ]]; then\n");
    fprintf(f, "            # Check if it's a known subcommand\n");
    fprintf(f, "            for cmd in $subcommands; do\n");
    fprintf(f, "                if [[ \"$word\" == \"$cmd\" ]]; then\n");
    fprintf(f, "                    cmd_context=\"$cmd\"\n");
    fprintf(f, "                    break 2\n");
    fprintf(f, "                fi\n");
    fprintf(f, "            done\n");
    fprintf(f, "        fi\n");
    fprintf(f, "    done\n\n");

    // If no subcommand active, show globals + top-level subs
    fprintf(f, "    if [[ -z \"$cmd_context\" ]]; then\n");
    if (fp->cmd_count > 0) {
        fprintf(f, "        local top_level_subs=\"");
        for (size_t i = 0; i < fp->cmd_count; i++) {
            write_bash_dq(f, fp->subcommands[i]->name);
            fprintf(f, " ");
        }
        fprintf(f, "\"\n");
        fprintf(f,
                "        COMPREPLY=( $(compgen -W \"$top_level_subs $global_flags\" -- \"$cur\") "
                ")\n");
    } else {
        fprintf(f, "        COMPREPLY=( $(compgen -W \"$global_flags\" -- \"$cur\") )\n");
    }
    fprintf(f, "        return 0\n");
    fprintf(f, "    fi\n\n");

    // Subcommand-specific completions
    if (fp->cmd_count > 0) {
        fprintf(f, "    # Handle subcommand-specific completions\n");
        fprintf(f, "    case \"$cmd_context\" in\n");
        write_bash_subcommand_cases(f, fp, NULL);
        fprintf(f, "        *)\n");
        fprintf(f, "            COMPREPLY=( $(compgen -W \"$global_flags\" -- \"$cur\") )\n");
        fprintf(f, "            ;;\n");
        fprintf(f, "    esac\n\n");
    }

    fprintf(f, "    return 0\n");
    fprintf(f, "}\n\n");

    fprintf(f, "complete -F _");
    write_shell_identifier(f, bin_name);
    fprintf(f, "_completion ");
    write_bash_pattern(f, bin_name);
    fprintf(f, "\n");
}

// --- Zsh Generation ---

/**
 * @brief Write Zsh argument specifications for a parser
 */
static void write_zsh_args(FILE* f, FlagParser* p, int indent) {
    if (!p || !f) return;

    for (size_t i = 0; i < p->flag_count; i++) {
        Flag* flag = &p->flags[i];

        for (int j = 0; j < indent; j++) fprintf(f, "    ");

        if (flag->type == TYPE_BOOL) {
            /*
             * Boolean spec form: '--flag[description]'
             * Single-quoted so we do not have to worry about shell expansions of $, `, etc.
             */
            fprintf(f, "'--");
            write_zsh_description(f, flag->name);
            fprintf(f, "[");
            if (flag->description) write_zsh_description(f, flag->description);
            fprintf(f, "]'");
        } else {
            const char* arg_type = "value";

            switch (flag->type) {
                case TYPE_STRING:
                    arg_type = "file";
                    break;
                case TYPE_INT8:
                case TYPE_INT16:
                case TYPE_INT32:
                case TYPE_INT64:
                case TYPE_UINT8:
                case TYPE_UINT16:
                case TYPE_UINT32:
                case TYPE_UINT64:
                case TYPE_SIZE_T:
                    arg_type = "integer";
                    break;
                case TYPE_FLOAT:
                case TYPE_DOUBLE:
                    arg_type = "number";
                    break;
                default:
                    break;
            }

            /*
             * Value spec form: '--flag[description]:metavar:action'
             * Single-quoted for robustness.
             */
            fprintf(f, "'--");
            write_zsh_description(f, flag->name);
            fprintf(f, "[");
            if (flag->description) write_zsh_description(f, flag->description);
            if (flag->type == TYPE_STRING)
                fprintf(f, "]:file:_files'");
            else
                fprintf(f, "]:%s:'", arg_type);
        }

        fprintf(f, " \\\n");
    }
}

/**
 * @brief Recursively write Zsh subcommand cases
 */
static void write_zsh_subcommand_cases(FILE* f, FlagParser* p, int depth) {
    if (!p || p->cmd_count == 0) return;

    for (size_t i = 0; i < p->cmd_count; i++) {
        FlagParser* sub = p->subcommands[i];

        for (int j = 0; j < depth; j++) fprintf(f, "    ");
        write_zsh_description(f, sub->name);
        fprintf(f, ")\n");

        for (int j = 0; j < depth; j++) fprintf(f, "    ");
        fprintf(f, "    _arguments -C \\\n");

        // Write flags for this subcommand
        write_zsh_args(f, sub, depth + 2);

        // Add nested subcommands if any
        if (sub->cmd_count > 0) {
            for (int j = 0; j < depth + 2; j++) fprintf(f, "    ");
            fprintf(f, "'1:command:((");
            for (size_t k = 0; k < sub->cmd_count; k++) {
                if (k > 0) fprintf(f, " ");
                write_zsh_description(f, sub->subcommands[k]->name);
                fprintf(f, "\\:");
                if (sub->subcommands[k]->description) {
                    write_zsh_cmd_desc(f, sub->subcommands[k]->description);
                }
            }
            fprintf(f, "))' \\\n");

            for (int j = 0; j < depth + 2; j++) fprintf(f, "    ");
            fprintf(f, "'*::arg:->args' \\\n");
        }

        for (int j = 0; j < depth; j++) fprintf(f, "    ");
        fprintf(f, "        && ret=0\n");

        // Handle nested state
        if (sub->cmd_count > 0) {
            for (int j = 0; j < depth; j++) fprintf(f, "    ");
            fprintf(f, "    case $state in\n");
            for (int j = 0; j < depth; j++) fprintf(f, "    ");
            fprintf(f, "        args)\n");
            for (int j = 0; j < depth; j++) fprintf(f, "    ");
            fprintf(f, "            case $line[1] in\n");

            write_zsh_subcommand_cases(f, sub, depth + 4);

            for (int j = 0; j < depth; j++) fprintf(f, "    ");
            fprintf(f, "            esac\n");
            for (int j = 0; j < depth; j++) fprintf(f, "    ");
            fprintf(f, "            ;;\n");
            for (int j = 0; j < depth; j++) fprintf(f, "    ");
            fprintf(f, "    esac\n");
        }

        for (int j = 0; j < depth; j++) fprintf(f, "    ");
        fprintf(f, "    ;;\n");
    }
}

/**
 * @brief Generate Zsh completion script
 */
static void gen_zsh_completion(FlagParser* fp, FILE* f) {
    if (!fp || !f) return;

    char* bin_name = fp->name;

    fprintf(f, "#compdef ");
    write_zsh_description(f, bin_name);
    fprintf(f, "\n");
    fprintf(f, "# Generated by flags.c completion generator\n\n");

    fprintf(f, "_");
    write_shell_identifier(f, bin_name);
    fprintf(f, "() {\n");
    fprintf(f, "    local context state line\n");
    fprintf(f, "    typeset -A opt_args\n");
    fprintf(f, "    local ret=1\n\n");

    // Main Arguments
    fprintf(f, "    _arguments -C \\\n");

    // Global flags
    write_zsh_args(f, fp, 2);

    // Help flag
    fprintf(f, "        '--help[Show help information]' \\\n");

    // Subcommands
    if (fp->cmd_count > 0) {
        fprintf(f, "        '1:command:((");
        for (size_t i = 0; i < fp->cmd_count; i++) {
            if (i > 0) fprintf(f, " ");
            write_zsh_description(f, fp->subcommands[i]->name);
            fprintf(f, "\\:");
            if (fp->subcommands[i]->description) {
                write_zsh_cmd_desc(f, fp->subcommands[i]->description);
            }
        }
        fprintf(f, "))' \\\n");
        fprintf(f, "        '*::arg:->args' \\\n");
    }

    fprintf(f, "        && ret=0\n\n");

    // State Machine for subcommands
    if (fp->cmd_count > 0) {
        fprintf(f, "    case $state in\n");
        fprintf(f, "        args)\n");
        fprintf(f, "            case $line[1] in\n");

        write_zsh_subcommand_cases(f, fp, 4);

        fprintf(f, "            esac\n");
        fprintf(f, "            ;;\n");
        fprintf(f, "    esac\n\n");
    }

    fprintf(f, "    return ret\n");
    fprintf(f, "}\n\n");

    // Call the completion function directly without arguments
    fprintf(f, "compdef _");
    write_shell_identifier(f, bin_name);
    fprintf(f, " ");
    write_zsh_description(f, bin_name);
    fprintf(f, "\n");
}

/**
 * @brief Handler for the completion subcommand
 */
static void completion_handler(void* user_data) {
    (void)user_data;  // Unused, we use _comp_ctx

    if (!_comp_ctx.shell || !*_comp_ctx.shell) {
        fprintf(stderr, "Error: --shell is required (bash or zsh)\n");
        exit(1);
    }

    if (!_comp_ctx.root) {
        fprintf(stderr, "Error: Internal error - no root parser available\n");
        exit(1);
    }

    FILE* out = stdout;
    if (_comp_ctx.output && *_comp_ctx.output) {
        out = fopen(_comp_ctx.output, "w");
        if (!out) {
            fprintf(stderr, "Error: Cannot open output file '%s': %s\n", _comp_ctx.output, strerror(errno));
            exit(1);
        }
    }

    // Normalize shell name (case-insensitive)
    char shell_lower[32];
    size_t i;
    for (i = 0; i < sizeof(shell_lower) - 1 && _comp_ctx.shell[i]; i++) {
        shell_lower[i] = (char)tolower(_comp_ctx.shell[i]);
    }
    shell_lower[i] = '\0';

    if (strcmp(shell_lower, "bash") == 0) {
        gen_bash_completion(_comp_ctx.root, out);
    } else if (strcmp(shell_lower, "zsh") == 0) {
        gen_zsh_completion(_comp_ctx.root, out);
    } else {
        fprintf(stderr, "Error: Unsupported shell '%s'. Supported: bash, zsh\n", _comp_ctx.shell);
        if (_comp_ctx.output) fclose(out);
        exit(1);
    }

    if (_comp_ctx.output && out != stdout) {
        if (fclose(out) != 0) {
            fprintf(stderr, "Warning: Error closing output file: %s\n", strerror(errno));
        }
        printf("Completion script written to: %s\n", _comp_ctx.output);
    }

    exit(0);  // Exit after generating completion
}

/**
 * @brief Add completion generation subcommand to a parser
 * @param fp Root parser to add completion command to
 *
 * This adds a "completion" subcommand with --shell and --output flags.
 * Usage: program completion --shell bash --output /path/to/completion.sh
 */
void flag_add_completion_cmd(FlagParser* fp) {
    if (!fp) return;

    // Store root parser for traversal during generation
    _comp_ctx.root = fp;

    // Ensure null initialization (defense in depth)
    _comp_ctx.shell = NULL;
    _comp_ctx.output = NULL;

    FlagParser* cmd = flag_add_subcommand(fp, "completion", "Generate shell completion scripts", completion_handler);

    if (!cmd) {
        fprintf(stderr, "Warning: Failed to add completion subcommand\n");
        return;
    }

    // Add flags - use static context addresses
    flag_add(cmd, TYPE_STRING, "shell", 's', "Target shell (bash or zsh)", &_comp_ctx.shell, true);
    flag_add(cmd, TYPE_STRING, "output", 'o', "Output file path (default: stdout)", &_comp_ctx.output, false);
}
