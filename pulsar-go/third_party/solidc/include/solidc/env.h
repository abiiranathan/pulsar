/**
 * @file env.h
 * @brief Environment variable utilities and safe access functions.
 */

#ifndef ENV_H
#define ENV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>  // for getenv, setenv, unsetenv, secure_getenv (Linux)

/**
 * Cross-platform environment variable access macros.
 *
 * GETENV: Retrieves environment variable value safely.
 *   - Linux: Uses secure_getenv() which returns NULL in secure contexts
 *   - Other: Uses standard getenv()
 *
 * SETENV: Sets environment variable value.
 *   - POSIX: Uses setenv(name, value, overwrite)
 *   - Windows: Uses _putenv_s(name, value) - always overwrites
 *
 * UNSETENV: Removes environment variable.
 *   - POSIX: Uses unsetenv(name)
 *   - Windows: Uses _putenv_s(name, "") to clear the variable
 */

// Platform detection
#if defined(__linux__)
    #define GETENV(name) secure_getenv(name)
#else
    #define GETENV(name) getenv(name)
#endif

// SETENV macro - cross-platform environment variable setting
#if defined(_WIN32) || defined(_WIN64)
    #include <stdlib.h>  // for _putenv_s
    /**
     * Sets environment variable on Windows.
     * @param name Variable name
     * @param value Variable value
     * @param overwrite Ignored on Windows (always overwrites)
     * @return 0 on success, non-zero on failure
     */
    #define SETENV(name, value, overwrite) _putenv_s(name, value)

    /**
     * Removes environment variable on Windows.
     * @param name Variable name to remove
     * @return 0 on success, non-zero on failure
     * @note Windows unsets by setting to empty string
     */
    #define UNSETENV(name) _putenv_s(name, "")
#else
    // POSIX systems (Linux, macOS, BSD, etc.)
    /**
     * Sets environment variable on POSIX systems.
     * @param name Variable name
     * @param value Variable value
     * @param overwrite 1 to overwrite existing value, 0 to preserve
     * @return 0 on success, -1 on failure
     */
    #define SETENV(name, value, overwrite) setenv(name, value, overwrite)

    /**
     * Removes environment variable on POSIX systems.
     * @param name Variable name to remove
     * @return 0 on success, -1 on failure
     */
    #define UNSETENV(name)                 unsetenv(name)
#endif

#ifdef __cplusplus
}
#endif

#endif  // ENV_H
