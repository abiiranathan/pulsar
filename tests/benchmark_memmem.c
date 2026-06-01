/**
 * @file benchmark_memmem.c
 * @brief Performance benchmark for memmem implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/memmem.h"

#define ITERATIONS 1000000

double get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

void benchmark_case(const char* name, const void* haystack, size_t hay_len, const void* needle, size_t needle_len,
                    int iterations) {
    double start = get_time_ms();

    volatile void* result; /* Prevent optimization */
    for (int i = 0; i < iterations; i++) {
        result = pulsar_memmem(haystack, hay_len, needle, needle_len);
    }
    (void)result; /* Silence unused variable warning */

    double elapsed = get_time_ms() - start;
    double per_op  = (elapsed * 1000000.0) / iterations; /* nanoseconds */

    printf("%-40s: %8.2f ms total, %8.1f ns/op\n", name, elapsed, per_op);
}

int main() {
    printf("=== MEMMEM Performance Benchmark ===\n\n");

    /* Benchmark 1: Short needle in short haystack */
    {
        const char* haystack = "The quick brown fox jumps over the lazy dog";
        const char* needle   = "fox";
        benchmark_case("Short needle in short haystack", haystack, strlen(haystack), needle, strlen(needle), ITERATIONS);
    }

    /* Benchmark 2: Single byte search */
    {
        const char* haystack = "abcdefghijklmnopqrstuvwxyz";
        const char* needle   = "z";
        benchmark_case("Single byte search", haystack, strlen(haystack), needle, 1, ITERATIONS);
    }

    /* Benchmark 3: Two byte search */
    {
        const char* haystack = "The quick brown fox jumps over the lazy dog";
        const char* needle   = "ov";
        benchmark_case("Two byte search", haystack, strlen(haystack), needle, 2, ITERATIONS);
    }

    /* Benchmark 4: Match at beginning */
    {
        const char* haystack = "The quick brown fox jumps over the lazy dog";
        const char* needle   = "The";
        benchmark_case("Match at beginning", haystack, strlen(haystack), needle, strlen(needle), ITERATIONS);
    }

    /* Benchmark 5: Match at end */
    {
        const char* haystack = "The quick brown fox jumps over the lazy dog";
        const char* needle   = "dog";
        benchmark_case("Match at end", haystack, strlen(haystack), needle, strlen(needle), ITERATIONS);
    }

    /* Benchmark 6: No match */
    {
        const char* haystack = "The quick brown fox jumps over the lazy dog";
        const char* needle   = "cat";
        benchmark_case("No match (worst case)", haystack, strlen(haystack), needle, strlen(needle), ITERATIONS);
    }

    /* Benchmark 7: Large haystack (triggers SIMD) */
    {
        size_t size     = 10000;
        char*  haystack = malloc(size);
        memset(haystack, 'a', size);
        const char* needle = "needle";
        memcpy(haystack + 5000, needle, strlen(needle));

        benchmark_case("Large haystack (10KB, SIMD path)", haystack, size, needle, strlen(needle), ITERATIONS / 100);
        free(haystack);
    }

    /* Benchmark 8: Long needle */
    {
        const char* haystack =
            "The quick brown fox jumps over the lazy dog. "
            "This is a longer sentence for testing purposes.";
        const char* needle = "jumps over the lazy dog";
        benchmark_case("Long needle (>20 bytes)", haystack, strlen(haystack), needle, strlen(needle), ITERATIONS);
    }

    /* Benchmark 9: Repeating pattern */
    {
        char haystack[1000];
        memset(haystack, 'a', 1000);
        const char* needle = "aaaa";
        benchmark_case("Repeating pattern", haystack, 1000, needle, 4, ITERATIONS / 10);
    }

    /* Benchmark 10: Binary data */
    {
        unsigned char haystack[256];
        for (int i = 0; i < 256; i++)
            haystack[i] = i;
        unsigned char needle[] = {0xAA, 0xBB, 0xCC};
        benchmark_case("Binary data search", haystack, 256, needle, 3, ITERATIONS);
    }

    /* Benchmark 11: Very large haystack (1MB) */
    {
        size_t size     = 1024 * 1024;
        char*  haystack = malloc(size);
        memset(haystack, 'x', size);
        const char* needle = "target";
        memcpy(haystack + size - 100, needle, strlen(needle));

        benchmark_case("Very large haystack (1MB)", haystack, size, needle, strlen(needle), ITERATIONS / 1000);
        free(haystack);
    }

    printf("\n");

#if defined(__AVX2__)
    printf("SIMD: AVX2 enabled\n");
#elif defined(__ARM_NEON)
    printf("SIMD: ARM NEON enabled\n");
#else
    printf("SIMD: Scalar only (no SIMD)\n");
#endif

    return 0;
}
