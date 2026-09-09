/**
 * @file align.h
 * @brief Memory alignment utilities and macros for cross-platform alignment.
 */

#if defined(_MSC_VER)
    /* MSVC (Windows) */
    #define ALIGN(x) __declspec(align(x))
#elif defined(__GNUC__) || defined(__clang__)
    /* GCC / Clang (Linux, macOS, MinGW) */
    #define ALIGN(x) __attribute__((aligned(x)))
#elif __STDC_VERSION__ >= 201112L
    /* C11 Standard */
    #define ALIGN(x) _Alignas(x)
#else
    /* Fallback (No alignment - risky for SIMD) */
    #define ALIGN(x)
    #pragma message("Warning: alignment attribute not supported on this compiler.")
#endif
