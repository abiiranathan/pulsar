#ifndef PULSAR_ITOA_H
#define PULSAR_ITOA_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static const char DIGIT_PAIRS[200] = {
    '0', '0', '0', '1', '0', '2', '0', '3', '0', '4', '0', '5', '0', '6', '0', '7', '0', '8', '0', '9', '1', '0', '1',
    '1', '1', '2', '1', '3', '1', '4', '1', '5', '1', '6', '1', '7', '1', '8', '1', '9', '2', '0', '2', '1', '2', '2',
    '2', '3', '2', '4', '2', '5', '2', '6', '2', '7', '2', '8', '2', '9', '3', '0', '3', '1', '3', '2', '3', '3', '3',
    '4', '3', '5', '3', '6', '3', '7', '3', '8', '3', '9', '4', '0', '4', '1', '4', '2', '4', '3', '4', '4', '4', '5',
    '4', '6', '4', '7', '4', '8', '4', '9', '5', '0', '5', '1', '5', '2', '5', '3', '5', '4', '5', '5', '5', '6', '5',
    '7', '5', '8', '5', '9', '6', '0', '6', '1', '6', '2', '6', '3', '6', '4', '6', '5', '6', '6', '6', '7', '6', '8',
    '6', '9', '7', '0', '7', '1', '7', '2', '7', '3', '7', '4', '7', '5', '7', '6', '7', '7', '7', '8', '7', '9', '8',
    '0', '8', '1', '8', '2', '8', '3', '8', '4', '8', '5', '8', '6', '8', '7', '8', '8', '8', '9', '9', '0', '9', '1',
    '9', '2', '9', '3', '9', '4', '9', '5', '9', '6', '9', '7', '9', '8', '9', '9'};

static inline void put2(char* dst, uint32_t v) {
    dst[0] = (char)('0' + v / 10);
    dst[1] = (char)('0' + v % 10);
}

static inline void put4(char* dst, uint32_t v) {
    uint32_t q = (uint32_t)(((uint64_t)v * 1374389535ULL) >> 37);
    uint32_t r = v - q * 100;
    put2(dst, q);
    put2(dst + 2, r);
}

static inline void put8(char* dst, uint32_t v) {
    /* Split into two independent 4-digit halves (both execute simultaneously) */
    uint32_t hi = (uint32_t)(((uint64_t)v * 109951163ULL) >> 40); /* v / 10000 */
    uint32_t lo = v - hi * 10000;
    put4(dst, hi);
    put4(dst + 4, lo);
}

/* Branchless format for 0..99 */
static inline char* write_tail2(char* p, uint32_t v) {
    if (v >= 10) {
        put2(p, v);
        return p + 2;
    }
    *p = (char)('0' + v);
    return p + 1;
}

/* Formats any 32-bit integer forward with zero loops */
static inline char* u32_to_str(char* p, uint32_t v) {
    if (v < 100) {
        return write_tail2(p, v);
    }
    if (v < 10000) {
        uint32_t q = (uint32_t)(((uint64_t)v * 1374389535ULL) >> 37);
        uint32_t r = v - q * 100;
        p = write_tail2(p, q);
        put2(p, r);
        return p + 2;
    }
    if (v < 100000000) {
        uint32_t hi = (uint32_t)(((uint64_t)v * 109951163ULL) >> 40); /* v / 10000 */
        uint32_t lo = v - hi * 10000;
        p = u32_to_str(p, hi);
        put4(p, lo);
        return p + 4;
    }
    /* 8-9 digits */
    uint32_t hi = (uint32_t)(((uint64_t)v * 1441151881ULL) >> 57); /* v / 100000000 */
    uint32_t lo = v - hi * 100000000;
    *p++ = (char)('0' + hi);
    put8(p, lo);
    return p + 8;
}

/** Fast digit count for 0 <= v <= 9999999999999999 (16 digits max). */
static inline size_t count_digits(uint64_t v) {
    if (v < 100000000ULL) {
        if (v < 10000ULL) {
            if (v < 100ULL) return v < 10ULL ? 1 : 2;
            return v < 1000ULL ? 3 : 4;
        }
        if (v < 1000000ULL) return v < 100000ULL ? 5 : 6;
        return v < 10000000ULL ? 7 : 8;
    }
    if (v < 1000000000000ULL) {
        if (v < 10000000000ULL) return v < 1000000000ULL ? 9 : 10;
        return v < 100000000000ULL ? 11 : 12;
    }
    if (v < 100000000000000ULL) return v < 10000000000000ULL ? 13 : 14;
    return v < 1000000000000000ULL ? 15 : 16;
}

size_t pulsar_itoa(uint64_t value, char* buf) {
    char* p = buf;

    if (value <= UINT32_MAX) {
        p = u32_to_str(p, (uint32_t)value);
    } else if (value < 10000000000000000ULL) { /* 9 to 16 digits */
        uint64_t hi64 = value / 100000000ULL;
        uint32_t lo32 = (uint32_t)(value - hi64 * 100000000ULL);
        p = u32_to_str(p, (uint32_t)hi64);
        put8(p, lo32);
        p += 8;
    } else { /* 17 to 20 digits */
        uint64_t hi64 = value / 100000000ULL;
        uint32_t lo32 = (uint32_t)(value - hi64 * 100000000ULL);
        uint32_t hi_hi32 = (uint32_t)(hi64 / 100000000ULL);
        uint32_t hi_lo32 = (uint32_t)(hi64 - (uint64_t)hi_hi32 * 100000000ULL);

        p = u32_to_str(p, hi_hi32);
        put8(p, hi_lo32);
        p += 8;
        put8(p, lo32);
        p += 8;
    }

    *p = '\0';
    return (size_t)(p - buf);
}

#endif
