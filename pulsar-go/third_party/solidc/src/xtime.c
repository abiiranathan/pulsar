#include "../include/xtime.h"
#include "../include/macros.h"

#include <ctype.h>   // for isdigit
#include <errno.h>   // for errno
#include <stdio.h>   // for snprintf
#include <stdlib.h>  // for strtol, abs
#include <string.h>  // for memset, strlen

#ifdef _WIN32
    // Windows CRT provides _s variants; adapt them to the _r call sites below.
    // NULL-return contract matches POSIX so error checks keep working.
    #include <time.h>
    #define gmtime_r(timep, result)    (((gmtime_s)((result), (timep)) == 0) ? (result) : NULL)
    #define localtime_r(timep, result) (((localtime_s)((result), (timep)) == 0) ? (result) : NULL)
#endif

#if defined(__APPLE__) || defined(__unix__) || defined(__linux__)
    #include <sys/time.h>  // for gettimeofday
#endif

// Platform-specific includes for high-resolution time
#if defined(__APPLE__)
    #include <mach/mach_time.h>
#endif

/** Nanoseconds per second */
static const int64_t NANOS_PER_SEC = 1000000000LL;
static const int64_t NANOS_PER_MICRO = 1000LL;
static const int64_t NANOS_PER_MILLI = 1000000LL;

/** Maximum valid timezone offset in minutes */
static const int16_t MAX_TZ_OFFSET = 1439;  // ±23:59

/**
 * Helper: Checks if a year is a leap year.
 */
static inline bool is_leap_year(int year) { return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0); }

/**
 * Helper: Returns the number of days in a given month.
 */
static inline int days_in_month(int year, int month) {
    static const int days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    if (month < 0 || month > 11) {
        return 0;
    }

    if (month == 1 && is_leap_year(year)) {  // February in leap year
        return 29;
    }

    return days[month];
}

/**
 * Days from 1970-01-01 to the given proleptic Gregorian date.
 * Constant time, valid for any year (including < 1970 and negative).
 *
 * Reference: H. Hinnant, "chrono-Compatible Low-Level Date Algorithms"
 * (http://howardhinnant.github.io/date_algorithms.html).
 *
 * Replaces the previous `for (y = 1970; y < year; y++)` loops which never
 * executed for years before 1970 and silently returned epoch-based garbage
 * for every such date (parse, add_months, add_years).
 */
static inline int64_t days_from_civil(int y, unsigned m, unsigned d) {
    y -= (m <= 2);
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);                             /* [0, 399]      */
    const unsigned doy = (153u * (m > 2 ? m - 3u : m + 9u) + 2u) / 5u + d - 1u; /* [0, 365] */
    const unsigned doe = yoe * 365u + yoe / 4u - yoe / 100u + doy;              /* [0, 146096]   */
    return era * 146097 + (int64_t)doe - 719468;
}

xtime_error_t xtime_init(xtime_t* t) {
    if (t == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }
    *t = (xtime_t){.seconds = 0, .nanoseconds = 0, .tz_offset = 0, .has_tz = false};
    return XTIME_OK;
}

/**
 * Helper: Gets local timezone offset in minutes from UTC.
 * Returns 0 on failure.
 */
static int16_t get_local_tz_offset(time_t timestamp) {
    struct tm utc_tm, local_tm;

    // Get both UTC and local time representations
    if (gmtime_r(&timestamp, &utc_tm) == NULL) {
        return 0;
    }
    if (localtime_r(&timestamp, &local_tm) == NULL) {
        return 0;
    }

    // Calculate difference in minutes
    // Account for day boundary crossings
    int day_diff = local_tm.tm_mday - utc_tm.tm_mday;
    int hour_diff = local_tm.tm_hour - utc_tm.tm_hour;
    int min_diff = local_tm.tm_min - utc_tm.tm_min;

    // Adjust for day boundaries
    if (day_diff > 1) {
        day_diff = -1;  // Wrapped backwards
    } else if (day_diff < -1) {
        day_diff = 1;  // Wrapped forwards
    }

    int total_minutes = (day_diff * 24 * 60) + (hour_diff * 60) + min_diff;

    // Sanity check
    if (abs(total_minutes) > MAX_TZ_OFFSET) {
        return 0;
    }

    return (int16_t)total_minutes;
}

xtime_error_t xtime_now(xtime_t* t) {
    if (t == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

#if defined(_WIN32) || defined(_WIN64)
    // Windows: Use GetSystemTimePreciseAsFileTime for high precision
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);

    // Convert FILETIME (100-nanosecond intervals since 1601-01-01) to Unix time
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    // Windows epoch is 1601-01-01, Unix epoch is 1970-01-01
    // Difference: 116444736000000000 * 100ns = 11644473600 seconds
    const int64_t WINDOWS_TO_UNIX_EPOCH = 11644473600LL;
    int64_t total_100ns = (int64_t)(uli.QuadPart);

    t->seconds = (total_100ns / 10000000LL) - WINDOWS_TO_UNIX_EPOCH;
    t->nanoseconds = (uint32_t)((total_100ns % 10000000LL) * 100);

#elif defined(__APPLE__)
    // macOS: Use clock_gettime with CLOCK_REALTIME (available since macOS 10.12)
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        // Fallback to gettimeofday if clock_gettime fails
        struct timeval tv;
        if (gettimeofday(&tv, NULL) != 0) {
            return XTIME_ERR_SYSTEM;
        }
        t->seconds = (int64_t)tv.tv_sec;
        t->nanoseconds = (uint32_t)(tv.tv_usec * 1000);
    } else {
        t->seconds = (int64_t)ts.tv_sec;
        t->nanoseconds = (uint32_t)ts.tv_nsec;
    }
#else
    // Linux/POSIX: Use clock_gettime with CLOCK_REALTIME
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return XTIME_ERR_SYSTEM;
    }

    t->seconds = (int64_t)ts.tv_sec;
    t->nanoseconds = (uint32_t)ts.tv_nsec;
#endif

    // Capture local timezone offset
    t->tz_offset = get_local_tz_offset((time_t)t->seconds);
    t->has_tz = true;

    return XTIME_OK;
}

xtime_error_t xtime_utc_now(xtime_t* t) {
    xtime_error_t err = xtime_now(t);
    if (err == XTIME_OK) {
        t->tz_offset = 0;
        t->has_tz = false;
    }
    return err;
}

/**
 * Helper: Parses timezone offset from string like "+0530" or "-08:00"
 * Returns offset in minutes, or 0 if parsing fails.
 */
static bool parse_tz_offset(const char* str, int16_t* offset) {
    if (str == NULL || offset == NULL) {
        return false;
    }

    // Skip whitespace
    while (*str == ' ' || *str == '\t') {
        str++;
    }

    // Check for sign
    int sign = 1;
    if (*str == '+') {
        sign = 1;
        str++;
    } else if (*str == '-') {
        sign = -1;
        str++;
    } else if (*str == 'Z' || *str == 'z') {
        *offset = 0;
        return true;
    } else {
        return false;
    }

    // Parse hours
    if (!isdigit(str[0]) || !isdigit(str[1])) {
        return false;
    }
    int hours = (str[0] - '0') * 10 + (str[1] - '0');
    str += 2;

    // Check for colon separator (optional)
    if (*str == ':') {
        str++;
    }

    // Parse minutes
    int minutes = 0;
    if (isdigit(str[0]) && isdigit(str[1])) {
        minutes = (str[0] - '0') * 10 + (str[1] - '0');
    }

    // Validate range
    if (hours > 23 || minutes > 59) {
        return false;
    }

    int total_minutes = (hours * 60 + minutes) * sign;
    if (abs(total_minutes) > MAX_TZ_OFFSET) {
        return false;
    }

    *offset = (int16_t)total_minutes;
    return true;
}

xtime_error_t xtime_parse(const char* str, const char* format, xtime_t* t) {
    if (str == NULL || format == NULL || t == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    xtime_init(t);

    // Strip %f (fractional seconds) and %z (timezone) from the format before
    // handing to strptime — these are custom specifiers we handle manually
    // from the `remaining` pointer. Also strip the separator character
    // immediately preceding each custom specifier (e.g. '.' before %f,
    // ' ' before %z) so strptime does not try to match them as literals.
    char clean_fmt[256];
    size_t ci = 0;
    for (size_t i = 0; format[i] != '\0' && ci + 1 < sizeof(clean_fmt); i++) {
        if (format[i] == '%' && (format[i + 1] == 'f' || format[i + 1] == 'z')) {
            // Strip the separator that preceded this specifier if present
            if (ci > 0 && (clean_fmt[ci - 1] == '.' || clean_fmt[ci - 1] == ' ')) {
                ci--;
            }
            i++;  // Skip the specifier character; loop increment skips '%'
            continue;
        }
        clean_fmt[ci++] = format[i];
    }
    clean_fmt[ci] = '\0';

    struct tm tm_result;
    memset(&tm_result, 0, sizeof(tm_result));

    char* remaining = strptime(str, clean_fmt, &tm_result);
    if (remaining == NULL) {
        return XTIME_ERR_PARSE_FAILED;
    }

    // Convert broken-down time to days since Unix epoch and then to seconds.
    // Done manually to avoid mktime/timegm portability issues.
    int year = tm_result.tm_year + 1900;
    int month = tm_result.tm_mon;  // [0, 11]
    int day = tm_result.tm_mday;   // [1, 31]
    int hour = tm_result.tm_hour;
    int min = tm_result.tm_min;
    int sec = tm_result.tm_sec;

    // Validate day against actual month length
    int max_day = days_in_month(year, month);
    if (day < 1 || day > max_day) {
        return XTIME_ERR_DATE_OUT_OF_RANGE;
    }

    // Days since 1970-01-01 (constant-time; correct for any year,
    // including dates before 1970 — see days_from_civil note).
    int64_t days = days_from_civil(year, (unsigned)month + 1, (unsigned)day);

    // Wall-clock UTC seconds (timezone not yet applied)
    t->seconds = (days * 86400LL) + (hour * 3600LL) + (min * 60LL) + sec;

    // Handle fractional seconds (%f): ".175387" or ".123456789"
    // remaining points just past what strptime consumed, so it may start
    // with '.' if the caller included %f in the format.
    if (*remaining == '.') {
        remaining++;

        uint32_t nanos = 0;
        int64_t multiplier = 100000000LL;  // First digit = 100 ms worth of ns

        while (isdigit((unsigned char)*remaining)) {
            if (multiplier >= 1) {
                nanos += (uint32_t)((*remaining - '0') * multiplier);
                multiplier /= 10;
            }
            remaining++;  // Consume excess digits beyond nanosecond precision
        }
        t->nanoseconds = nanos;
    }

    // Handle timezone (%z): "+03", "+0300", "+03:00", "-05:30", "Z"
    // Skip any whitespace that may separate the time from the tz token.
    while (*remaining == ' ') {
        remaining++;
    }

    if (*remaining != '\0') {
        int16_t tz_offset = 0;
        if (parse_tz_offset(remaining, &tz_offset)) {
            t->tz_offset = tz_offset;
            t->has_tz = true;
            // t->seconds is currently the wall-clock time in the parsed
            // timezone. Subtract the offset to normalise to UTC.
            t->seconds -= (int64_t)tz_offset * 60LL;
        }
    }

    return XTIME_OK;
}

xtime_error_t xtime_format(const xtime_t* t, const char* format, char* buf, size_t buflen) {
    if (t == NULL || format == NULL || buf == NULL || buflen == 0) {
        return XTIME_ERR_INVALID_ARG;
    }

    // Handle special format: Unix timestamp
    if (strcmp(format, "%s") == 0 || strcmp(format, XTIME_FMT_UNIX) == 0) {
        int written = snprintf(buf, buflen, "%lld", (long long)t->seconds);
        if (written < 0 || (size_t)written >= buflen) {
            return XTIME_ERR_BUFFER_TOO_SMALL;
        }
        return XTIME_OK;
    }

    // Strip %f (fractional seconds) and %z (timezone) from the format before
    // passing to strftime — both are custom specifiers we handle manually.
    // Also strip the separator character immediately preceding each specifier
    // (e.g. '.' before %f) so strftime does not emit it as a literal.
    bool has_f = false;
    bool has_z = false;

    char clean_fmt[256];
    size_t ci = 0;
    for (size_t i = 0; format[i] != '\0' && ci + 1 < sizeof(clean_fmt); i++) {
        if (format[i] == '%' && format[i + 1] == 'f') {
            if (ci > 0 && clean_fmt[ci - 1] == '.') {
                ci--;  // Strip the '.' separator preceding %f
            }
            has_f = true;
            i++;  // Skip the specifier character
            continue;
        }
        if (format[i] == '%' && format[i + 1] == 'z') {
            has_z = true;
            i++;  // Skip the specifier character
            continue;
        }
        clean_fmt[ci++] = format[i];
    }
    clean_fmt[ci] = '\0';

    // Adjust timestamp for timezone: t->seconds is UTC, so add the offset
    // to display wall-clock time in the local timezone.
    time_t timestamp = (time_t)t->seconds;
    if (t->has_tz && t->tz_offset != 0) {
        timestamp += (time_t)(t->tz_offset * 60);
    }

    struct tm tm_result;
    if (gmtime_r(&timestamp, &tm_result) == NULL) {
        return XTIME_ERR_INVALID_TIME;
    }

    // Format the main date/time components
    size_t len = strftime(buf, buflen, clean_fmt, &tm_result);
    if (len == 0) {
        return XTIME_ERR_BUFFER_TOO_SMALL;
    }

    // Append fractional seconds (%f) if the format requested it and
    // nanoseconds are non-zero.
    if (has_f && t->nanoseconds > 0) {
        char frac[11];  // '.' + 9 digits + '\0'
        int written = snprintf(frac, sizeof(frac), ".%09u", t->nanoseconds);
        if (written < 0) {
            return XTIME_ERR_BUFFER_TOO_SMALL;
        }

        // Trim trailing zeros after the decimal point
        size_t frac_len = (size_t)written;
        while (frac_len > 1 && frac[frac_len - 1] == '0') {
            frac_len--;
        }
        frac[frac_len] = '\0';

        if (len + frac_len >= buflen) {
            return XTIME_ERR_BUFFER_TOO_SMALL;
        }
        memcpy(buf + len, frac, frac_len + 1);  // +1 for '\0'
        len += frac_len;
    }

    // Append timezone offset (%z) if the format requested it and timezone
    // information is present. Emitted as ±HH:MM; UTC is emitted as +00:00.
    if (has_z) {
        int hrs = abs(t->tz_offset) / 60;
        int mins = abs(t->tz_offset) % 60;
        char sign = (t->tz_offset >= 0) ? '+' : '-';

        int written = snprintf(buf + len, buflen - len, "%c%02d:%02d", sign, hrs, mins);
        if (written < 0 || len + (size_t)written >= buflen) {
            return XTIME_ERR_BUFFER_TOO_SMALL;
        }
    }

    return XTIME_OK;
}

xtime_error_t xtime_format_utc(const xtime_t* t, const char* format, char* buf, size_t buflen) {
    if (t == NULL || format == NULL || buf == NULL || buflen == 0) {
        return XTIME_ERR_INVALID_ARG;
    }

    // Handle special format: Unix timestamp
    if (strcmp(format, "%s") == 0 || strcmp(format, XTIME_FMT_UNIX) == 0) {
        int written = snprintf(buf, buflen, "%lld", (long long)t->seconds);
        if (written < 0 || (size_t)written >= buflen) {
            return XTIME_ERR_BUFFER_TOO_SMALL;
        }
        return XTIME_OK;
    }

    // Convert to struct tm in UTC
    time_t timestamp = (time_t)t->seconds;
    struct tm tm_result;

    if (gmtime_r(&timestamp, &tm_result) == NULL) {
        return XTIME_ERR_INVALID_TIME;
    }

    // Format using strftime
    size_t result = strftime(buf, buflen, format, &tm_result);
    if (result == 0) {
        return XTIME_ERR_BUFFER_TOO_SMALL;
    }

    return XTIME_OK;
}

xtime_error_t xtime_to_json(const xtime_t* t, char* buf, size_t buflen) {
    if (t == NULL || buf == NULL || buflen == 0) {
        return XTIME_ERR_INVALID_ARG;
    }

    // Adjust seconds for timezone if present for the breakdown
    time_t timestamp = (time_t)t->seconds;
    if (t->has_tz && t->tz_offset != 0) {
        timestamp += (time_t)(t->tz_offset * 60);
    }

    struct tm tm_val;
    if (gmtime_r(&timestamp, &tm_val) == NULL) {
        return XTIME_ERR_INVALID_TIME;
    }

    // 1. Format Date and Time: YYYY-MM-DDTHH:MM:SS
    int written = snprintf(buf, buflen, "%04d-%02d-%02dT%02d:%02d:%02d", tm_val.tm_year + 1900, tm_val.tm_mon + 1,
                           tm_val.tm_mday, tm_val.tm_hour, tm_val.tm_min, tm_val.tm_sec);

    if (written < 0 || (size_t)written >= buflen) {
        return XTIME_ERR_BUFFER_TOO_SMALL;
    }
    size_t current_len = (size_t)written;

    // 2. Append Nanoseconds: .nnnnnnnnn
    // RFC 3339 allows fractional seconds. We print full precision.
    if (t->nanoseconds > 0) {
        written = snprintf(buf + current_len, buflen - current_len, ".%09u", t->nanoseconds);
        if (written < 0 || current_len + (size_t)written >= buflen) {
            return XTIME_ERR_BUFFER_TOO_SMALL;
        }
        current_len += (size_t)written;
    }

    // 3. Append Timezone: Z or ±HH:MM
    if (!t->has_tz || t->tz_offset == 0) {
        // UTC
        if (current_len + 1 >= buflen) return XTIME_ERR_BUFFER_TOO_SMALL;
        buf[current_len++] = 'Z';
        buf[current_len] = '\0';
    } else {
        // Offset
        int hrs = abs(t->tz_offset) / 60;
        int mins = abs(t->tz_offset) % 60;
        char sign = (t->tz_offset >= 0) ? '+' : '-';

        written = snprintf(buf + current_len, buflen - current_len, "%c%02d:%02d", sign, hrs, mins);

        if (written < 0 || current_len + (size_t)written >= buflen) {
            return XTIME_ERR_BUFFER_TOO_SMALL;
        }
    }

    return XTIME_OK;
}

int64_t xtime_to_unix(const xtime_t* t) {
    if (t == NULL) {
        return -1;
    }
    return t->seconds;
}

xtime_error_t xtime_from_unix(int64_t timestamp, xtime_t* t) {
    if (t == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    t->seconds = timestamp;
    t->nanoseconds = 0;
    t->tz_offset = 0;
    t->has_tz = false;

    return XTIME_OK;
}

xtime_error_t xtime_add_seconds(xtime_t* t, int64_t seconds) {
    if (t == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    t->seconds += seconds;
    return XTIME_OK;
}

int xtime_compare(const xtime_t* t1, const xtime_t* t2) {
    if (t1 == NULL || t2 == NULL) {
        return -2;
    }

    if (t1->seconds < t2->seconds) {
        return -1;
    }
    if (t1->seconds > t2->seconds) {
        return 1;
    }

    // Seconds are equal, compare nanoseconds
    if (t1->nanoseconds < t2->nanoseconds) {
        return -1;
    }
    if (t1->nanoseconds > t2->nanoseconds) {
        return 1;
    }

    return 0;
}

xtime_error_t xtime_diff(const xtime_t* t1, const xtime_t* t2, double* diff) {
    if (t1 == NULL || t2 == NULL || diff == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    int64_t sec_diff = t1->seconds - t2->seconds;
    int64_t nano_diff = (int64_t)t1->nanoseconds - (int64_t)t2->nanoseconds;

    *diff = (double)sec_diff + ((double)nano_diff / (double)NANOS_PER_SEC);

    return XTIME_OK;
}

const char* xtime_strerror(xtime_error_t err) {
    switch (err) {
        case XTIME_OK:
            return "Success";
        case XTIME_ERR_INVALID_ARG:
            return "Invalid argument";
        case XTIME_ERR_PARSE_FAILED:
            return "Failed to parse time string";
        case XTIME_ERR_DATE_OUT_OF_RANGE:
            return "Date of out of range for month";
        case XTIME_ERR_BUFFER_TOO_SMALL:
            return "Output buffer too small";
        case XTIME_ERR_INVALID_TIME:
            return "Invalid time value";
        case XTIME_ERR_SYSTEM:
            return "System error";
        default:
            return "Unknown error";
    }
}

// =============== Helpers ===========================

xtime_error_t xtime_add_nanoseconds(xtime_t* t, int64_t nanos) {
    if (t == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    int64_t total_nanos = (int64_t)t->nanoseconds + nanos;

    // Handle overflow/underflow into seconds
    if (total_nanos >= NANOS_PER_SEC) {
        int64_t extra_secs = total_nanos / NANOS_PER_SEC;
        t->seconds += extra_secs;
        t->nanoseconds = (uint32_t)(total_nanos % NANOS_PER_SEC);
    } else if (total_nanos < 0) {
        int64_t borrow_secs = (-total_nanos + NANOS_PER_SEC - 1) / NANOS_PER_SEC;
        t->seconds -= borrow_secs;
        t->nanoseconds = (uint32_t)(total_nanos + (borrow_secs * NANOS_PER_SEC));
    } else {
        t->nanoseconds = (uint32_t)total_nanos;
    }

    return XTIME_OK;
}

xtime_error_t xtime_add_microseconds(xtime_t* t, int64_t micros) {
    if (t == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    return xtime_add_nanoseconds(t, micros * NANOS_PER_MICRO);
}

xtime_error_t xtime_add_milliseconds(xtime_t* t, int64_t millis) {
    if (t == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    return xtime_add_nanoseconds(t, millis * NANOS_PER_MILLI);
}

xtime_error_t xtime_add_minutes(xtime_t* t, int64_t minutes) {
    if (t == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    return xtime_add_seconds(t, minutes * 60);
}

xtime_error_t xtime_add_hours(xtime_t* t, int64_t hours) {
    if (t == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    return xtime_add_seconds(t, hours * 3600);
}

xtime_error_t xtime_add_days(xtime_t* t, int64_t days) {
    if (t == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    return xtime_add_seconds(t, days * 86400);
}

xtime_error_t xtime_add_months(xtime_t* t, int months) {
    if (t == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    // Store the time-of-day portion
    int64_t time_of_day_seconds = t->seconds % 86400;
    if (time_of_day_seconds < 0) {
        time_of_day_seconds += 86400;
    }

    // Get the date components
    time_t timestamp = (time_t)t->seconds;
    struct tm tm_val;

    if (gmtime_r(&timestamp, &tm_val) == NULL) {
        return XTIME_ERR_INVALID_TIME;
    }

    // Add months
    int total_months = tm_val.tm_mon + months;
    int year_adjust = total_months / 12;
    int new_month = total_months % 12;

    // Handle negative months
    if (new_month < 0) {
        new_month += 12;
        year_adjust -= 1;
    }

    int new_year = tm_val.tm_year + 1900 + year_adjust;

    // Adjust day if it exceeds the new month's length
    int max_day = days_in_month(new_year, new_month);
    int new_day = (tm_val.tm_mday > max_day) ? max_day : tm_val.tm_mday;

    // Days since Unix epoch — constant-time, valid for any year.
    int64_t days = days_from_civil(new_year, (unsigned)new_month + 1, (unsigned)new_day);

    // Reconstruct the timestamp
    t->seconds = (days * 86400) + time_of_day_seconds;

    return XTIME_OK;
}

xtime_error_t xtime_add_years(xtime_t* t, int years) {
    if (t == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    // Store the time-of-day portion
    int64_t time_of_day_seconds = t->seconds % 86400;
    if (time_of_day_seconds < 0) {
        time_of_day_seconds += 86400;
    }

    // Get the date components
    time_t timestamp = (time_t)t->seconds;
    struct tm tm_val;

    if (gmtime_r(&timestamp, &tm_val) == NULL) {
        return XTIME_ERR_INVALID_TIME;
    }

    int new_year = tm_val.tm_year + 1900 + years;
    int new_month = tm_val.tm_mon;
    int new_day = tm_val.tm_mday;

    // Handle Feb 29 in non-leap years
    if (new_month == 1 && new_day == 29) {
        if (!is_leap_year(new_year)) {
            new_day = 28;
        }
    }

    // Days since Unix epoch — constant-time, valid for any year.
    int64_t days = days_from_civil(new_year, (unsigned)new_month + 1, (unsigned)new_day);

    // Reconstruct the timestamp
    t->seconds = (days * 86400) + time_of_day_seconds;

    return XTIME_OK;
}

xtime_error_t xtime_diff_nanos(const xtime_t* t1, const xtime_t* t2, int64_t* nanos) {
    if (t1 == NULL || t2 == NULL || nanos == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    int64_t sec_diff = t1->seconds - t2->seconds;
    int64_t nano_diff = (int64_t)t1->nanoseconds - (int64_t)t2->nanoseconds;

    *nanos = (sec_diff * NANOS_PER_SEC) + nano_diff;

    return XTIME_OK;
}

xtime_error_t xtime_diff_micros(const xtime_t* t1, const xtime_t* t2, int64_t* micros) {
    if (t1 == NULL || t2 == NULL || micros == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    int64_t nanos;
    xtime_error_t err = xtime_diff_nanos(t1, t2, &nanos);
    if (err != XTIME_OK) {
        return err;
    }

    *micros = nanos / NANOS_PER_MICRO;

    return XTIME_OK;
}

xtime_error_t xtime_diff_millis(const xtime_t* t1, const xtime_t* t2, int64_t* millis) {
    if (t1 == NULL || t2 == NULL || millis == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    int64_t nanos;
    xtime_error_t err = xtime_diff_nanos(t1, t2, &nanos);
    if (err != XTIME_OK) {
        return err;
    }

    *millis = nanos / NANOS_PER_MILLI;

    return XTIME_OK;
}

xtime_error_t xtime_diff_seconds(const xtime_t* t1, const xtime_t* t2, int64_t* seconds) {
    if (t1 == NULL || t2 == NULL || seconds == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    *seconds = t1->seconds - t2->seconds;

    return XTIME_OK;
}

xtime_error_t xtime_diff_minutes(const xtime_t* t1, const xtime_t* t2, int64_t* minutes) {
    if (t1 == NULL || t2 == NULL || minutes == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    *minutes = (t1->seconds - t2->seconds) / 60;

    return XTIME_OK;
}

xtime_error_t xtime_diff_hours(const xtime_t* t1, const xtime_t* t2, int64_t* hours) {
    if (t1 == NULL || t2 == NULL || hours == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    *hours = (t1->seconds - t2->seconds) / 3600;

    return XTIME_OK;
}

xtime_error_t xtime_diff_days(const xtime_t* t1, const xtime_t* t2, int64_t* days) {
    if (t1 == NULL || t2 == NULL || days == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    *days = (t1->seconds - t2->seconds) / 86400;

    return XTIME_OK;
}

bool xtime_is_leap_year(const xtime_t* t) {
    if (t == NULL) {
        return false;
    }

    time_t timestamp = (time_t)t->seconds;
    struct tm tm_val;

    if (gmtime_r(&timestamp, &tm_val) == NULL) {
        return false;
    }

    return is_leap_year(tm_val.tm_year + 1900);
}

xtime_error_t xtime_truncate_to_second(xtime_t* t) {
    if (t == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    t->nanoseconds = 0;

    return XTIME_OK;
}

xtime_error_t xtime_truncate_to_minute(xtime_t* t) {
    if (t == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    // Truncate to the start of the current minute
    // Remove seconds and nanoseconds
    t->seconds = (t->seconds / 60) * 60;
    t->nanoseconds = 0;

    return XTIME_OK;
}

xtime_error_t xtime_truncate_to_hour(xtime_t* t) {
    if (t == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    // Truncate to the start of the current hour
    // Remove minutes, seconds, and nanoseconds
    t->seconds = (t->seconds / 3600) * 3600;
    t->nanoseconds = 0;

    return XTIME_OK;
}

xtime_error_t xtime_truncate_to_day(xtime_t* t) {
    if (t == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    // Truncate to the start of the current day (00:00:00 UTC)
    // Remove hours, minutes, seconds, and nanoseconds
    t->seconds = (t->seconds / 86400) * 86400;
    t->nanoseconds = 0;

    return XTIME_OK;
}

xtime_error_t xtime_start_of_week(const xtime_t* t, xtime_t* result) {
    if (t == NULL || result == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    *result = *t;

    // First truncate to start of day
    xtime_error_t err = xtime_truncate_to_day(result);
    if (err != XTIME_OK) {
        return err;
    }

    // Get the day of week
    time_t timestamp = (time_t)result->seconds;
    struct tm tm_val;

    if (gmtime_r(&timestamp, &tm_val) == NULL) {
        return XTIME_ERR_INVALID_TIME;
    }

    // Calculate days to subtract to get to Monday (tm_wday: 0=Sun, 1=Mon, ...)
    int days_to_monday = (tm_val.tm_wday == 0) ? 6 : (tm_val.tm_wday - 1);

    // Subtract days to get to Monday
    return xtime_add_days(result, -days_to_monday);
}

xtime_error_t xtime_start_of_month(const xtime_t* t, xtime_t* result) {
    if (t == NULL || result == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    *result = *t;

    time_t timestamp = (time_t)result->seconds;
    struct tm tm_val;

    if (gmtime_r(&timestamp, &tm_val) == NULL) {
        return XTIME_ERR_INVALID_TIME;
    }

    // Calculate how many days to subtract to get to day 1
    int days_to_subtract = tm_val.tm_mday - 1;

    // First truncate to start of current day
    xtime_error_t err = xtime_truncate_to_day(result);
    if (err != XTIME_OK) {
        return err;
    }

    // Then subtract days to get to the 1st
    return xtime_add_days(result, -days_to_subtract);
}

xtime_error_t xtime_start_of_year(const xtime_t* t, xtime_t* result) {
    if (t == NULL || result == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    *result = *t;

    time_t timestamp = (time_t)result->seconds;
    struct tm tm_val;

    if (gmtime_r(&timestamp, &tm_val) == NULL) {
        return XTIME_ERR_INVALID_TIME;
    }

    // Calculate days since January 1st (tm_yday is 0-based)
    int days_to_subtract = tm_val.tm_yday;

    // First truncate to start of current day
    xtime_error_t err = xtime_truncate_to_day(result);
    if (err != XTIME_OK) {
        return err;
    }

    // Then subtract days to get to Jan 1
    return xtime_add_days(result, -days_to_subtract);
}

xtime_error_t xtime_end_of_day(const xtime_t* t, xtime_t* result) {
    if (t == NULL || result == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    *result = *t;

    // Truncate to start of day
    xtime_error_t err = xtime_truncate_to_day(result);
    if (err != XTIME_OK) {
        return err;
    }

    // Add 86399 seconds (23:59:59) and 999999999 nanoseconds
    result->seconds += 86399;
    result->nanoseconds = 999999999;

    return XTIME_OK;
}

xtime_error_t xtime_end_of_month(const xtime_t* t, xtime_t* result) {
    if (t == NULL || result == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    *result = *t;

    time_t timestamp = (time_t)result->seconds;
    struct tm tm_val;

    if (gmtime_r(&timestamp, &tm_val) == NULL) {
        return XTIME_ERR_INVALID_TIME;
    }

    // Get last day of month
    int last_day = days_in_month(tm_val.tm_year + 1900, tm_val.tm_mon);

    // Calculate days to add to get to last day
    int days_to_add = last_day - tm_val.tm_mday;

    // Truncate to start of current day
    xtime_error_t err = xtime_truncate_to_day(result);
    if (err != XTIME_OK) {
        return err;
    }

    // Add days to get to last day
    err = xtime_add_days(result, days_to_add);
    if (err != XTIME_OK) {
        return err;
    }

    // Set to end of day (23:59:59.999999999)
    result->seconds += 86399;
    result->nanoseconds = 999999999;

    return XTIME_OK;
}

xtime_error_t xtime_end_of_year(const xtime_t* t, xtime_t* result) {
    if (t == NULL || result == NULL) {
        return XTIME_ERR_INVALID_ARG;
    }

    *result = *t;

    time_t timestamp = (time_t)result->seconds;
    struct tm tm_val;

    if (gmtime_r(&timestamp, &tm_val) == NULL) {
        return XTIME_ERR_INVALID_TIME;
    }

    // Calculate if leap year
    int year = tm_val.tm_year + 1900;
    int total_days_in_year = is_leap_year(year) ? 366 : 365;

    // Calculate days to add to get to Dec 31
    int days_to_add = (total_days_in_year - 1) - tm_val.tm_yday;

    // Truncate to start of current day
    xtime_error_t err = xtime_truncate_to_day(result);
    if (err != XTIME_OK) {
        return err;
    }

    // Add days to get to Dec 31
    err = xtime_add_days(result, days_to_add);
    if (err != XTIME_OK) {
        return err;
    }

    // Set to end of day (23:59:59.999999999)
    result->seconds += 86399;
    result->nanoseconds = 999999999;

    return XTIME_OK;
}
