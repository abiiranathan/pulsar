/**
 * @file xtime.h
 * @brief Extended time utilities and high-precision timing functions.
 */

#ifndef XTIME_H
#define XTIME_H

#include <stdbool.h>  // for bool
#include <stdint.h>   // for int64_t, uint32_t
#include <time.h>     // for struct tm, time_t

// Definition for strptime on windows.
#if defined(_WIN32)
    #include "./win_strptime.h"
#endif

/**
 * @file xtime.h
 * @brief Cross-platform time parsing and formatting library
 *
 * Provides fast, safe time parsing and formatting with comprehensive error handling.
 * All functions are thread-safe when operating on separate xtime_t instances.
 */

/** Common time format specifiers */
#define XTIME_FMT_ISO8601     "%Y-%m-%dT%H:%M:%S"          // 2024-11-28T14:30:00
#define XTIME_FMT_RFC3339     "%Y-%m-%dT%H:%M:%S%z"        // 2024-11-28T14:30:00+00:00
#define XTIME_FMT_RFC2822     "%a, %d %b %Y %H:%M:%S"      // Thu, 28 Nov 2024 14:30:00
#define XTIME_FMT_HTTP        "%a, %d %b %Y %H:%M:%S GMT"  // HTTP date format
#define XTIME_FMT_UNIX        "%s"                         // Unix timestamp
#define XTIME_FMT_DATE        "%Y-%m-%d"                   // 2024-11-28
#define XTIME_FMT_TIME        "%H:%M:%S"                   // 14:30:00
#define XTIME_FMT_DATETIME    "%Y-%m-%d %H:%M:%S"          // 2024-11-28 14:30:00
#define XTIME_FMT_POSTGRES_TZ "%Y-%m-%d %H:%M:%S.%f%z"     // 2024-10-02 12:13:25.175387+03

/** Error codes returned by xtime functions */
typedef enum {
    XTIME_OK = 0,                 // Operation succeeded
    XTIME_ERR_INVALID_ARG,        // Invalid argument (null pointer, invalid format)
    XTIME_ERR_PARSE_FAILED,       // Failed to parse time string
    XTIME_ERR_DATE_OUT_OF_RANGE,  // Failed to parse time string
    XTIME_ERR_BUFFER_TOO_SMALL,   // Output buffer too small
    XTIME_ERR_INVALID_TIME,       // Time value is invalid or out of range
    XTIME_ERR_SYSTEM              // System call failed (check errno)
} xtime_error_t;

/** Time structure with nanosecond precision */
typedef struct {
    int64_t seconds;       // Seconds since Unix epoch (can be negative for dates before 1970)
    uint32_t nanoseconds;  // Nanoseconds component [0, 999999999]
    int16_t tz_offset;     // Timezone offset in minutes from UTC [-1439, 1439]
    bool has_tz;           // Whether timezone information is present
} xtime_t;

/**
 * Initializes an xtime_t structure to zero.
 * @param t Pointer to xtime_t to initialize.
 * @return XTIME_OK on success, XTIME_ERR_INVALID_ARG if t is null.
 */
xtime_error_t xtime_init(xtime_t* t);

/**
 * Gets current system time with nanosecond precision where available.
 * Automatically captures local timezone offset.
 * @param t Pointer to xtime_t to store current time.
 * @return XTIME_OK on success, XTIME_ERR_INVALID_ARG if t is null, XTIME_ERR_SYSTEM on system error.
 */
xtime_error_t xtime_now(xtime_t* t);

/**
 * Gets current system time in UTC (no timezone offset).
 * @param t Pointer to xtime_t to store current time.
 * @return XTIME_OK on success, XTIME_ERR_INVALID_ARG if t is null, XTIME_ERR_SYSTEM on system error.
 */
xtime_error_t xtime_utc_now(xtime_t* t);

/**
 * Parses a time string according to the specified format.
 * Supports strptime-style format specifiers plus extensions for nanoseconds and timezone.
 *
 * @param str The time string to parse.
 * @param format Format specifier (supports standard strptime formats).
 * @param t Pointer to xtime_t to store parsed time.
 * @return XTIME_OK on success, appropriate error code on failure.
 *
 * @note Supports common formats automatically. For custom formats, use strptime specifiers.
 * @note Thread-safe when operating on different xtime_t instances.
 */
xtime_error_t xtime_parse(const char* str, const char* format, xtime_t* t);

/**
 * Formats time according to the specified format string.
 * Uses local timezone if time has timezone info, otherwise uses UTC.
 *
 * @param t Pointer to xtime_t containing time to format.
 * @param format Format specifier (supports standard strftime formats).
 * @param buf Output buffer for formatted string.
 * @param buflen Size of output buffer.
 * @return XTIME_OK on success, appropriate error code on failure.
 *
 * @note Buffer must be large enough to hold formatted string including null terminator.
 * @note Thread-safe when operating on different xtime_t instances.
 */
xtime_error_t xtime_format(const xtime_t* t, const char* format, char* buf, size_t buflen);

/**
 * Formats time in UTC regardless of timezone information.
 * @param t Pointer to xtime_t containing time to format.
 * @param format Format specifier (supports standard strftime formats).
 * @param buf Output buffer for formatted string.
 * @param buflen Size of output buffer.
 * @return XTIME_OK on success, appropriate error code on failure.
 */
xtime_error_t xtime_format_utc(const xtime_t* t, const char* format, char* buf, size_t buflen);

/**
 * Converts xtime_t to Unix timestamp (seconds since epoch).
 * @param t Pointer to xtime_t to convert.
 * @return Unix timestamp, or -1 if t is null.
 */
int64_t xtime_to_unix(const xtime_t* t);

/**
 * Formats time into a JSON-compatible ISO 8601 string (RFC 3339).
 * Format: "YYYY-MM-DDTHH:MM:SS.nnnnnnnnnZ" (or +HH:MM)
 *
 * @param t Pointer to xtime_t to convert.
 * @param buf Output buffer.
 * @param buflen Size of output buffer (Recommended: at least 40 chars).
 * @return XTIME_OK on success, appropriate error code on failure.
 */
xtime_error_t xtime_to_json(const xtime_t* t, char* buf, size_t buflen);

/**
 * Creates xtime_t from Unix timestamp.
 * @param timestamp Unix timestamp (seconds since epoch).
 * @param t Pointer to xtime_t to store result.
 * @return XTIME_OK on success, XTIME_ERR_INVALID_ARG if t is null.
 */
xtime_error_t xtime_from_unix(int64_t timestamp, xtime_t* t);

/**
 * Adds seconds to a time value.
 * @param t Pointer to xtime_t to modify.
 * @param seconds Number of seconds to add (can be negative).
 * @return XTIME_OK on success, XTIME_ERR_INVALID_ARG if t is null.
 */
xtime_error_t xtime_add_seconds(xtime_t* t, int64_t seconds);

/**
 * Compares two time values.
 * @param t1 First time value.
 * @param t2 Second time value.
 * @return -1 if t1 < t2, 0 if t1 == t2, 1 if t1 > t2, or -2 if either pointer is null.
 */
int xtime_compare(const xtime_t* t1, const xtime_t* t2);

/**
 * Calculates difference between two times in seconds.
 * @param t1 First time value.
 * @param t2 Second time value.
 * @param diff Pointer to store difference (t1 - t2) in seconds.
 * @return XTIME_OK on success, XTIME_ERR_INVALID_ARG if any pointer is null.
 */
xtime_error_t xtime_diff(const xtime_t* t1, const xtime_t* t2, double* diff);

/**
 * Returns human-readable error message for error code.
 * @param err Error code.
 * @return Static error message string.
 */
const char* xtime_strerror(xtime_error_t err);

// ============== math calculation helpers =======================
//================================================================
/**
 * Adds a duration in nanoseconds to the time.
 * Handles overflow into seconds automatically.
 * @param t Pointer to xtime_t to modify.
 * @param nanos Nanoseconds to add (can be negative).
 * @return Error code.
 */
xtime_error_t xtime_add_nanoseconds(xtime_t* t, int64_t nanos);

/**
 * Adds a duration in microseconds to the time.
 * @param t Pointer to xtime_t to modify.
 * @param micros Microseconds to add (can be negative).
 * @return Error code.
 */
xtime_error_t xtime_add_microseconds(xtime_t* t, int64_t micros);

/**
 * Adds a duration in milliseconds to the time.
 * @param t Pointer to xtime_t to modify.
 * @param millis Milliseconds to add (can be negative).
 * @return Error code.
 */
xtime_error_t xtime_add_milliseconds(xtime_t* t, int64_t millis);

/**
 * Adds a duration in minutes to the time.
 * @param t Pointer to xtime_t to modify.
 * @param minutes Minutes to add (can be negative).
 * @return Error code.
 */
xtime_error_t xtime_add_minutes(xtime_t* t, int64_t minutes);

/**
 * Adds a duration in hours to the time.
 * @param t Pointer to xtime_t to modify.
 * @param hours Hours to add (can be negative).
 * @return Error code.
 */
xtime_error_t xtime_add_hours(xtime_t* t, int64_t hours);

/**
 * Adds a duration in days to the time.
 * @param t Pointer to xtime_t to modify.
 * @param days Days to add (can be negative).
 * @return Error code.
 */
xtime_error_t xtime_add_days(xtime_t* t, int64_t days);

/**
 * Adds years to the time, accounting for leap years and month boundaries.
 * If the resulting date is invalid (e.g., Feb 29 in non-leap year),
 * adjusts to the last valid day of that month.
 * @param t Pointer to xtime_t to modify.
 * @param years Years to add (can be negative).
 * @return Error code.
 */
xtime_error_t xtime_add_years(xtime_t* t, int years);

/**
 * Adds months to the time, accounting for varying month lengths.
 * If the resulting date is invalid (e.g., Jan 31 + 1 month = Feb 31),
 * adjusts to the last valid day of that month.
 * @param t Pointer to xtime_t to modify.
 * @param months Months to add (can be negative).
 * @return Error code.
 */
xtime_error_t xtime_add_months(xtime_t* t, int months);

/**
 * Calculates the duration between two times in nanoseconds.
 * Returns t1 - t2 (positive if t1 is after t2).
 * @param t1 First time.
 * @param t2 Second time.
 * @param nanos Output: difference in nanoseconds.
 * @return Error code.
 */
xtime_error_t xtime_diff_nanos(const xtime_t* t1, const xtime_t* t2, int64_t* nanos);

/**
 * Calculates the duration between two times in microseconds.
 * Returns t1 - t2 (positive if t1 is after t2).
 * @param t1 First time.
 * @param t2 Second time.
 * @param micros Output: difference in microseconds.
 * @return Error code.
 */
xtime_error_t xtime_diff_micros(const xtime_t* t1, const xtime_t* t2, int64_t* micros);

/**
 * Calculates the duration between two times in milliseconds.
 * Returns t1 - t2 (positive if t1 is after t2).
 * @param t1 First time.
 * @param t2 Second time.
 * @param millis Output: difference in milliseconds.
 * @return Error code.
 */
xtime_error_t xtime_diff_millis(const xtime_t* t1, const xtime_t* t2, int64_t* millis);

/**
 * Calculates the duration between two times in seconds (integer).
 * Returns t1 - t2 (positive if t1 is after t2).
 * @param t1 First time.
 * @param t2 Second time.
 * @param seconds Output: difference in seconds.
 * @return Error code.
 */
xtime_error_t xtime_diff_seconds(const xtime_t* t1, const xtime_t* t2, int64_t* seconds);

/**
 * Calculates the duration between two times in minutes.
 * Returns t1 - t2 (positive if t1 is after t2).
 * @param t1 First time.
 * @param t2 Second time.
 * @param minutes Output: difference in minutes.
 * @return Error code.
 */
xtime_error_t xtime_diff_minutes(const xtime_t* t1, const xtime_t* t2, int64_t* minutes);

/**
 * Calculates the duration between two times in hours.
 * Returns t1 - t2 (positive if t1 is after t2).
 * @param t1 First time.
 * @param t2 Second time.
 * @param hours Output: difference in hours.
 * @return Error code.
 */
xtime_error_t xtime_diff_hours(const xtime_t* t1, const xtime_t* t2, int64_t* hours);

/**
 * Calculates the duration between two times in days.
 * Returns t1 - t2 (positive if t1 is after t2).
 * @param t1 First time.
 * @param t2 Second time.
 * @param days Output: difference in days.
 * @return Error code.
 */
xtime_error_t xtime_diff_days(const xtime_t* t1, const xtime_t* t2, int64_t* days);

/**
 * Returns true if the time represents a leap year.
 * @param t Pointer to xtime_t.
 * @return true if leap year, false otherwise.
 */
bool xtime_is_leap_year(const xtime_t* t);

/**
 * Rounds time down to the start of the current day (00:00:00.000000000).
 * Preserves timezone information.
 * @param t Pointer to xtime_t to modify.
 * @return Error code.
 */
xtime_error_t xtime_truncate_to_day(xtime_t* t);

/**
 * Rounds time down to the start of the current hour (XX:00:00.000000000).
 * Preserves timezone information.
 * @param t Pointer to xtime_t to modify.
 * @return Error code.
 */
xtime_error_t xtime_truncate_to_hour(xtime_t* t);

/**
 * Rounds time down to the start of the current minute (XX:XX:00.000000000).
 * Preserves timezone information.
 * @param t Pointer to xtime_t to modify.
 * @return Error code.
 */
xtime_error_t xtime_truncate_to_minute(xtime_t* t);

/**
 * Rounds time down to the start of the current second (XX:XX:XX.000000000).
 * Preserves timezone information.
 * @param t Pointer to xtime_t to modify.
 * @return Error code.
 */
xtime_error_t xtime_truncate_to_second(xtime_t* t);

/**
 * Returns a new time representing the start of the week (Monday 00:00:00).
 * Does not modify the original time.
 * @param t Input time.
 * @param result Output: start of week.
 * @return Error code.
 */
xtime_error_t xtime_start_of_week(const xtime_t* t, xtime_t* result);

/**
 * Returns a new time representing the start of the month (day 1, 00:00:00).
 * Does not modify the original time.
 * @param t Input time.
 * @param result Output: start of month.
 * @return Error code.
 */
xtime_error_t xtime_start_of_month(const xtime_t* t, xtime_t* result);

/**
 * Returns a new time representing the start of the year (Jan 1, 00:00:00).
 * Does not modify the original time.
 * @param t Input time.
 * @param result Output: start of year.
 * @return Error code.
 */
xtime_error_t xtime_start_of_year(const xtime_t* t, xtime_t* result);

/**
 * Returns a new time representing the end of the day (23:59:59.999999999).
 * Does not modify the original time.
 * @param t Input time.
 * @param result Output: end of day.
 * @return Error code.
 */
xtime_error_t xtime_end_of_day(const xtime_t* t, xtime_t* result);

/**
 * Returns a new time representing the end of the month (last day, 23:59:59.999999999).
 * Does not modify the original time.
 * @param t Input time.
 * @param result Output: end of month.
 * @return Error code.
 */
xtime_error_t xtime_end_of_month(const xtime_t* t, xtime_t* result);

/**
 * Returns a new time representing the end of the year (Dec 31, 23:59:59.999999999).
 * Does not modify the original time.
 * @param t Input time.
 * @param result Output: end of year.
 * @return Error code.
 */
xtime_error_t xtime_end_of_year(const xtime_t* t, xtime_t* result);

#endif  // XTIME_H
