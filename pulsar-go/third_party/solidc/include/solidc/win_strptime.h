#ifndef WIN_STRPTIME_H
#define WIN_STRPTIME_H

#if defined(_WIN32)

    // Define timespec for older MSVC versions
    #if defined(_MSC_VER) && _MSC_VER < 1900
// Before VS2015
struct timespec {
    time_t tv_sec;  // Seconds
    long tv_nsec;   // Nanoseconds [0, 999999999]
};
    #else
        // VS2015+: Prevent redefinition if using pthread or other libs
        #ifndef HAVE_STRUCT_TIMESPEC
            #define HAVE_STRUCT_TIMESPEC
        #endif
        #include <time.h>
    #endif

    // Windows headers
    #include "platform.h"

    #ifdef __cplusplus
extern "C" {
    #endif

/**
 * @brief Parse a time string according to a format string.
 *
 * Windows implementation of POSIX strptime(). Converts a character string
 * pointed to by buf to values stored in the tm structure, using the format
 * specified by fmt.
 *
 * @param buf Pointer to the character string to parse (null-terminated)
 * @param fmt Pointer to the format string (null-terminated)
 * @param tm Pointer to struct tm where parsed values will be stored
 *
 * @return On success, returns a pointer to the character following the last
 *         character parsed in buf. On failure (parse error, invalid date,
 *         NULL parameters), returns NULL.
 *
 * @note The tm structure is NOT fully initialized by this function. Only the
 *       fields corresponding to format specifiers in fmt are modified. The
 *       caller should initialize tm (typically with memset or mktime) before
 *       calling this function if all fields need defined values.
 *
 * @note tm_isdst is set to -1 (unknown) to allow mktime() to determine DST.
 *
 * @note This implementation validates dates. Invalid dates like February 30
 *       or April 31 will cause the function to return NULL.
 *
 * @note Timezone specifiers (%z, %Z) consume input but do NOT set any fields
 *       in the tm structure. Timezone handling must be done separately by the
 *       caller, as Windows does not provide the tm_gmtoff extension field.
 *
 * Supported format specifiers:
 *
 * Date specifiers:
 *   %Y - 4-digit year (e.g., 2024)
 *   %y - 2-digit year (00-68 = 2000-2068, 69-99 = 1969-1999)
 *   %C - Century (used with %y for full year specification)
 *   %m - Month as decimal (01-12)
 *   %b - Abbreviated month name (Jan, Feb, etc., case-insensitive)
 *   %B - Full month name (January, February, etc., case-insensitive)
 *   %h - Same as %b
 *   %d - Day of month, zero-padded (01-31)
 *   %e - Day of month, space-padded ( 1-31)
 *   %j - Day of year (001-366)
 *
 * Time specifiers:
 *   %H - Hour in 24-hour format, zero-padded (00-23)
 *   %k - Hour in 24-hour format, space-padded ( 0-23)
 *   %I - Hour in 12-hour format, zero-padded (01-12)
 *   %l - Hour in 12-hour format, space-padded ( 1-12)
 *   %M - Minute (00-59)
 *   %S - Second (00-60, allowing for leap seconds)
 *   %p - AM/PM designation (case-insensitive)
 *
 * Weekday specifiers:
 *   %a - Abbreviated weekday name (Sun, Mon, etc., case-insensitive)
 *   %A - Full weekday name (Sunday, Monday, etc., case-insensitive)
 *   %u - Weekday as decimal (1-7, Monday = 1)
 *   %w - Weekday as decimal (0-6, Sunday = 0)
 *
 * Composite specifiers:
 *   %D - Date in MM/DD/YY format (equivalent to %m/%d/%y)
 *   %F - Date in YYYY-MM-DD format (equivalent to %Y-%m-%d, ISO 8601)
 *   %R - Time in HH:MM format (equivalent to %H:%M)
 *   %T - Time in HH:MM:SS format (equivalent to %H:%M:%S)
 *   %r - 12-hour time with AM/PM (equivalent to %I:%M:%S %p)
 *
 * Timezone specifiers (consumed but not processed):
 *   %z - Timezone offset (+hhmm, -hhmm, +hh:mm, -hh:mm, or Z)
 *   %Z - Timezone name or abbreviation
 *
 * Other specifiers:
 *   %n - Any whitespace
 *   %t - Any whitespace
 *   %% - Literal '%' character
 *
 * Whitespace and modifiers:
 *   - Any whitespace in fmt matches zero or more whitespace characters in buf
 *   - Modifiers %E and %O are accepted but ignored (for POSIX compatibility)
 *   - All non-% characters in fmt must match exactly (case-sensitive)
 *
 * Examples:
 * @code
 * struct tm tm;
 * memset(&tm, 0, sizeof(tm));
 *
 * // Parse ISO 8601 date/time
 * if (strptime("2024-03-15 14:30:00", "%Y-%m-%d %H:%M:%S", &tm) == NULL) {
 *     // Parse failed
 * }
 *
 * // Parse with abbreviated month
 * if (strptime("15-Mar-2024", "%d-%b-%Y", &tm) == NULL) {
 *     // Parse failed
 * }
 *
 * // Invalid date returns NULL
 * if (strptime("2024-02-30", "%Y-%m-%d", &tm) == NULL) {
 *     // February 30 doesn't exist
 * }
 * @endcode
 */
char* strptime(const char* buf, const char* fmt, struct tm* tm);

    #ifdef __cplusplus
}
    #endif

#endif  // defined(_MSC_VER)

#endif  // WIN_STRPTIME_H
