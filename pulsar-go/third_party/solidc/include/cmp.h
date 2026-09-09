/**
 * @file cmp.h
 * @brief Floating-point comparison library for precise and robust comparisons.
 *
 * This library provides functions and macros for comparing floating-point numbers
 * using different modes: relative epsilon, absolute epsilon, ULPS, and combined.
 *
 * Comparison Mode Recommendations:
 * - CMP_ABSOLUTE: Use when you know the expected magnitude of differences
 *   (e.g., coordinates in a fixed grid). Epsilon should be based on your
 *   application's tolerance for absolute error.
 *
 * - CMP_RELATIVE: Use for general scientific computing where values can vary
 *   widely in magnitude. Epsilon typically ranges from 1e-6 to 1e-15 depending
 *   on precision requirements.
 *
 * - CMP_ULPS: Use for bit-level comparisons, testing numerical algorithms, or
 *   when you need to ensure results are identical to a reference implementation.
 *   ULPS of 1-4 is typical for most applications.
 *
 * - CMP_COMBINED: Use when you need robustness across both very small and very
 *   large values. Combines the safety of absolute comparison near zero with
 *   the flexibility of relative comparison for larger values.
 *
 * Typical Epsilon Values:
 * - Single precision (float): 1e-6 to 1e-7
 * - Double precision (double): 1e-12 to 1e-15
 * - Long double: 1e-15 to 1e-18
 *
 * @author [Your Name]
 * @date September 2025
 */

#ifndef SOLIDC_CMP_H
    #define SOLIDC_CMP_H

    #include <float.h>
    #include <math.h>
    #include <stdbool.h>
    #include <stdint.h>
    #include <stdlib.h>

    #if defined(__cplusplus)
extern "C" {
    #endif

/**
 * @brief Comparison modes for floating-point numbers.
 */
typedef enum {
    CMP_ABSOLUTE, /**< Absolute epsilon: |a - b| ≤ ε. Best for fixed-scale data. */
    CMP_RELATIVE, /**< Relative epsilon: |a - b| ≤ ε × max(|a|, |b|). Best for scientific computing.
                   */
    CMP_ULPS,     /**< Units in Last Place: bit-wise difference ≤ N ULPS. Best for bit-exact
                     comparisons. */
    CMP_COMBINED  /**< Combined: |a - b| ≤ ε OR |a - b| ≤ ε × max(|a|, |b|). Most robust. */
} cmp_mode_t;

/**
 * @brief Default configuration for each floating-point type.
 */
typedef struct {
    cmp_mode_t mode; /**< Comparison mode */
    double epsilon;  /**< Epsilon value */
    uint64_t ulps;   /**< ULPS limit */
} cmp_config_t;

    // Default configurations
    #define CMP_DEFAULT_FLOAT  {CMP_RELATIVE, 1e-6f, 4}
    #define CMP_DEFAULT_DOUBLE {CMP_RELATIVE, 1e-12, 4}
    #define CMP_DEFAULT_LONG   {CMP_RELATIVE, 1e-15, 4}

// Helper functions
static inline bool cmp_special_cases(double a, double b) {
    return (isnan(a) && isnan(b)) || (isinf(a) && isinf(b) && signbit(a) == signbit(b));
}

static inline bool cmp_is_zero(double a) { return fabs(a) <= DBL_EPSILON; }

static inline int64_t cmp_double_to_int64(double d) {
    union {
        double d;
        int64_t i;
    } u = {d};
    return (u.i < 0) ? INT64_MIN - u.i : u.i;
}

// Core comparison functions
static inline bool cmp_absolute(double a, double b, double epsilon) {
    if (cmp_special_cases(a, b)) return true;
    return fabs(a - b) <= epsilon;
}

static inline bool cmp_relative(double a, double b, double epsilon) {
    if (cmp_special_cases(a, b)) return true;
    if (cmp_is_zero(a) && cmp_is_zero(b)) return true;
    return fabs(a - b) <= fmax(fabs(a), fabs(b)) * epsilon;
}

static inline bool cmp_ulps(double a, double b, uint64_t max_ulps) {
    if (cmp_special_cases(a, b)) return true;
    if (cmp_is_zero(a) && cmp_is_zero(b)) return true;

    int64_t a_int = cmp_double_to_int64(a);
    int64_t b_int = cmp_double_to_int64(b);

    if ((a_int < 0) != (b_int < 0)) {
        return a_int == INT64_MIN && b_int == INT64_MIN;
    }
    return (uint64_t)llabs(a_int - b_int) <= max_ulps;
}

static inline bool cmp_combined(double a, double b, double epsilon) {
    if (cmp_special_cases(a, b)) return true;
    if (cmp_is_zero(a) && cmp_is_zero(b)) return true;

    double diff = fabs(a - b);
    if (diff <= epsilon) return true;

    return diff <= fmax(fabs(a), fabs(b)) * epsilon;
}

    // Main generic comparison function
    #define CMP(a, b, ...) \
        _Generic((a), float: cmp_float, double: cmp_double, long double: cmp_long_double)(a, b, ##__VA_ARGS__)

// Type-specific comparison functions
static inline bool cmp_float(float a, float b, cmp_config_t config) {
    switch (config.mode) {
        case CMP_ABSOLUTE:
            return cmp_absolute(a, b, config.epsilon);
        case CMP_RELATIVE:
            return cmp_relative(a, b, config.epsilon);
        case CMP_ULPS:
            return cmp_ulps(a, b, config.ulps);
        case CMP_COMBINED:
            return cmp_combined(a, b, config.epsilon);
        default:
            return cmp_relative(a, b, config.epsilon);
    }
}

static inline bool cmp_double(double a, double b, cmp_config_t config) {
    switch (config.mode) {
        case CMP_ABSOLUTE:
            return cmp_absolute(a, b, config.epsilon);
        case CMP_RELATIVE:
            return cmp_relative(a, b, config.epsilon);
        case CMP_ULPS:
            return cmp_ulps(a, b, config.ulps);
        case CMP_COMBINED:
            return cmp_combined(a, b, config.epsilon);
        default:
            return cmp_relative(a, b, config.epsilon);
    }
}

static inline bool cmp_long_double(long double a, long double b, cmp_config_t config) {
    switch (config.mode) {
        case CMP_ABSOLUTE:
            return cmp_absolute((double)a, (double)b, config.epsilon);
        case CMP_RELATIVE:
            return cmp_relative((double)a, (double)b, config.epsilon);
        case CMP_ULPS:
            return cmp_ulps((double)a, (double)b, config.ulps);
        case CMP_COMBINED:
            return cmp_combined((double)a, (double)b, config.epsilon);
        default:
            return cmp_relative((double)a, (double)b, config.epsilon);
    }
}

    #define CMP_EPS(a, b, eps)                   \
        cmp(a, b,                                \
            (cmp_config_t){.mode = CMP_RELATIVE, \
                           .epsilon = (eps),     \
                           .ulps = _Generic((a), float: 4, double: 4, long double: 4)})

    #define CMP_ABS(a, b, eps)                   \
        cmp(a, b,                                \
            (cmp_config_t){.mode = CMP_ABSOLUTE, \
                           .epsilon = (eps),     \
                           .ulps = _Generic((a), float: 4, double: 4, long double: 4)})

    #define CMP_ULPS(a, b, ulps_val)                                                                  \
        cmp(a, b,                                                                                     \
            (cmp_config_t){.mode = CMP_ULPS,                                                          \
                           .epsilon = _Generic((a), float: 1e-6f, double: 1e-12, long double: 1e-15), \
                           .ulps = (ulps_val)})

    #define CMP_COMB(a, b, eps)                  \
        cmp(a, b,                                \
            (cmp_config_t){.mode = CMP_COMBINED, \
                           .epsilon = (eps),     \
                           .ulps = _Generic((a), float: 4, double: 4, long double: 4)})

    #if defined(__cplusplus)
}
    #endif

#endif /* SOLIDC_CMP_H */

/**
 * @example Example usage
 * @code
 * #include <stdio.h>
 * #include <solidc/cmp.h>
 *
 * int main() {
 *     float a = 1.0f, b = 1.0000001f;
 *
 *     // Default comparison (relative with type-appropriate epsilon)
 *     if (CMP(a, b)) {
 *         printf("Floats are equal\n");
 *     }
 *
 *     double x = 1.0, y = 1.0000000000000002;
 *
 *     // Custom epsilon
 *     if (CMP_EPS(x, y, 1e-10)) {
 *         printf("Doubles are equal within 1e-10\n");
 *     }
 *
 *     // Absolute comparison for coordinates
 *     float coord1 = 123.456f, coord2 = 123.457f;
 *     if (CMP_ABS(coord1, coord2, 0.01f)) {  // 1cm tolerance
 *         printf("Coordinates are equal\n");
 *     }
 *
 *     // ULPS comparison for exact results
 *     double result1 = some_computation();
 *     double result2 = reference_computation();
 *     if (CMP_ULPS(result1, result2, 2)) {
 *         printf("Results are bit-wise nearly identical\n");
 *     }
 *
 *     return 0;
 * }
 * @endcode
 */
