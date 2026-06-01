/**
 * @file test_memmem.c
 * @brief Comprehensive test suite for memmem implementation
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/memmem.h"

/* ANSI color codes for output */
#define GREEN  "\033[0;32m"
#define RED    "\033[0;31m"
#define YELLOW "\033[0;33m"
#define RESET  "\033[0m"

#define PULSAR_MEMMEM(haystack, haystack_len, needle, needle_len) \
    pulsar_memmem(haystack, haystack_len, needle, needle_len)

// #define LIBC_MEMMEM(haystack, haystack_len, needle, needle_len) memmem(haystack, haystack_len, needle, needle_len)

// Define MEMMEM to point to our implementation for testing
#define MEMMEM PULSAR_MEMMEM

int test_count = 0;
int pass_count = 0;

#define TEST(name) \
    test_count++;  \
    printf("Test %d: %s ... ", test_count, name);

#define PASS()                           \
    do {                                 \
        pass_count++;                    \
        printf(GREEN "PASS" RESET "\n"); \
    } while (0)

#define FAIL(msg)                                \
    do {                                         \
        printf(RED "FAIL" RESET " - %s\n", msg); \
    } while (0)

void test_empty_needle() {
    TEST("Empty needle");
    const char* haystack = "hello world";
    void*       result   = MEMMEM(haystack, 11, "", 0);
    if (result == haystack) {
        PASS();
    } else {
        FAIL("Expected haystack pointer");
    }
}

void test_needle_longer_than_haystack() {
    TEST("Needle longer than haystack");
    const char* haystack = "short";
    const char* needle   = "very long needle";
    void*       result   = MEMMEM(haystack, 5, needle, 16);
    if (result == NULL) {
        PASS();
    } else {
        FAIL("Expected NULL");
    }
}

void test_single_byte_needle_found() {
    TEST("Single byte needle - found");
    const char* haystack = "hello world";
    const char* needle   = "w";
    void*       result   = MEMMEM(haystack, 11, needle, 1);
    if (result == haystack + 6) {
        PASS();
    } else {
        FAIL("Expected position 6");
    }
}

void test_single_byte_needle_not_found() {
    TEST("Single byte needle - not found");
    const char* haystack = "hello world";
    const char* needle   = "z";
    void*       result   = MEMMEM(haystack, 11, needle, 1);
    if (result == NULL) {
        PASS();
    } else {
        FAIL("Expected NULL");
    }
}

void test_two_byte_needle() {
    TEST("Two byte needle");
    const char* haystack = "hello world";
    const char* needle   = "wo";
    void*       result   = MEMMEM(haystack, 11, needle, 2);
    if (result == haystack + 6) {
        PASS();
    } else {
        FAIL("Expected position 6");
    }
}

void test_exact_match() {
    TEST("Exact match (needle == haystack)");
    const char* text   = "exact";
    void*       result = MEMMEM(text, 5, text, 5);
    if (result == text) {
        PASS();
    } else {
        FAIL("Expected exact match");
    }
}

void test_match_at_beginning() {
    TEST("Match at beginning");
    const char* haystack = "prefix and more";
    const char* needle   = "prefix";
    void*       result   = MEMMEM(haystack, 15, needle, 6);
    if (result == haystack) {
        PASS();
    } else {
        FAIL("Expected position 0");
    }
}

void test_match_at_end() {
    TEST("Match at end");
    const char* haystack = "some text suffix";
    const char* needle   = "suffix";
    void*       result   = MEMMEM(haystack, 16, needle, 6);
    if (result == haystack + 10) {
        PASS();
    } else {
        FAIL("Expected position 10");
    }
}

void test_multiple_occurrences() {
    TEST("Multiple occurrences (returns first)");
    const char* haystack = "ababababab";
    const char* needle   = "abab";
    void*       result   = MEMMEM(haystack, 10, needle, 4);
    if (result == haystack) {
        PASS();
    } else {
        FAIL("Expected position 0");
    }
}

void test_overlapping_pattern() {
    TEST("Overlapping pattern");
    const char* haystack = "aaaaaaa";
    const char* needle   = "aaa";
    void*       result   = MEMMEM(haystack, 7, needle, 3);
    if (result == haystack) {
        PASS();
    } else {
        FAIL("Expected position 0");
    }
}

void test_no_match() {
    TEST("No match");
    const char* haystack = "hello world";
    const char* needle   = "xyz";
    void*       result   = MEMMEM(haystack, 11, needle, 3);
    if (result == NULL) {
        PASS();
    } else {
        FAIL("Expected NULL");
    }
}

void test_binary_data() {
    TEST("Binary data with null bytes");
    unsigned char haystack[] = {0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0xFF, 0xAA, 0xBB};
    unsigned char needle[]   = {0x00, 0xFF, 0xAA};
    void*         result     = MEMMEM(haystack, 9, needle, 3);
    if (result == haystack + 5) {
        PASS();
    } else {
        FAIL("Expected position 5");
    }
}

void test_all_same_bytes() {
    TEST("All same bytes");
    const char haystack[] = "aaaaaaaaaaaaaaaa";
    const char needle[]   = "aaaa";
    void*      result     = MEMMEM(haystack, 16, needle, 4);
    if (result == haystack) {
        PASS();
    } else {
        FAIL("Expected position 0");
    }
}

void test_long_needle() {
    TEST("Long needle (>32 bytes)");
    const char* haystack =
        "The quick brown fox jumps over the lazy dog. This is a long sentence for testing "
        "purposes.";
    const char* needle = "jumps over the lazy dog";
    void*       result = MEMMEM(haystack, strlen(haystack), needle, strlen(needle));
    if (result == haystack + 20) {
        PASS();
    } else {
        FAIL("Expected position 20");
    }
}

void test_simd_alignment() {
    TEST("SIMD alignment edge case");
    /* Create a haystack that tests alignment boundaries */
    char haystack[100];
    memset(haystack, 'x', 100);
    memcpy(haystack + 31, "FIND", 4); /* Right at 32-byte boundary */

    void* result = MEMMEM(haystack, 100, "FIND", 4);
    if (result == haystack + 31) {
        PASS();
    } else {
        FAIL("Expected position 31");
    }
}

void test_near_end_match() {
    TEST("Match very near end of haystack");
    char haystack[50];
    memset(haystack, 'a', 50);
    memcpy(haystack + 47, "xyz", 3);

    void* result = MEMMEM(haystack, 50, "xyz", 3);
    if (result == haystack + 47) {
        PASS();
    } else {
        FAIL("Expected position 47");
    }
}

void test_first_last_char_false_positive() {
    TEST("First and last char match but middle doesn't");
    const char* haystack = "abcdefghijklmnoabz";
    const char* needle   = "abc";
    void*       result   = MEMMEM(haystack, 18, needle, 3);
    if (result == haystack) {
        PASS();
    } else {
        FAIL("Expected position 0");
    }
}

void test_large_haystack() {
    TEST("Large haystack (SIMD stress test)");
    size_t haystack_size = 10000;
    char*  haystack      = malloc(haystack_size);
    memset(haystack, 'a', haystack_size);
    const char* needle = "needle";
    memcpy(haystack + 5000, needle, 6);

    void* result  = MEMMEM(haystack, haystack_size, needle, 6);
    int   success = (result == haystack + 5000);
    free(haystack);

    if (success) {
        PASS();
    } else {
        FAIL("Expected position 5000");
    }
}

void test_repeating_pattern_with_variation() {
    TEST("Repeating pattern with variation");
    const char* haystack = "abababacabababab";
    const char* needle   = "ababac";
    void*       result   = MEMMEM(haystack, 16, needle, 6);
    if (result == haystack + 2) {
        PASS();
    } else {
        FAIL("Expected position 2 (first occurrence)");
    }
}

void test_utf8_multibyte() {
    TEST("UTF-8 multibyte characters");
    const char* haystack = "Hello 世界 World";
    const char* needle   = "世界";
    void*       result   = MEMMEM(haystack, strlen(haystack), needle, strlen(needle));
    if (result != NULL && memcmp(result, needle, strlen(needle)) == 0) {
        PASS();
    } else {
        FAIL("Expected to find UTF-8 pattern");
    }
}

void test_boundary_16_bytes() {
    TEST("Boundary test - exactly 16 bytes");
    const char haystack[] = "1234567890123456";
    const char needle[]   = "456";
    void*      result     = MEMMEM(haystack, 16, needle, 3);
    if (result == haystack + 3) {
        PASS();
    } else {
        FAIL("Expected position 3 (first occurrence)");
    }
}

void test_boundary_32_bytes() {
    TEST("Boundary test - exactly 32 bytes");
    const char haystack[] = "12345678901234567890123456789012";
    const char needle[]   = "012";
    void*      result     = MEMMEM(haystack, 32, needle, 3);
    if (result == haystack + 9) {
        PASS();
    } else {
        FAIL("Expected position 9");
    }
}

int main() {
    printf("=== MEMMEM Comprehensive Test Suite ===\n\n");

    test_empty_needle();
    test_needle_longer_than_haystack();
    test_single_byte_needle_found();
    test_single_byte_needle_not_found();
    test_two_byte_needle();
    test_exact_match();
    test_match_at_beginning();
    test_match_at_end();
    test_multiple_occurrences();
    test_overlapping_pattern();
    test_no_match();
    test_binary_data();
    test_all_same_bytes();
    test_long_needle();
    test_simd_alignment();
    test_near_end_match();
    test_first_last_char_false_positive();
    test_large_haystack();
    test_repeating_pattern_with_variation();
    test_utf8_multibyte();
    test_boundary_16_bytes();
    test_boundary_32_bytes();

    printf("\n=== Results ===\n");
    printf("Total tests: %d\n", test_count);
    printf("Passed: " GREEN "%d" RESET "\n", pass_count);
    printf("Failed: %s%d%s\n", (test_count - pass_count) > 0 ? RED : GREEN, test_count - pass_count, RESET);

    if (pass_count == test_count) {
        printf("\n" GREEN "✓ All tests passed!" RESET "\n");
        return 0;
    } else {
        printf("\n" RED "✗ Some tests failed" RESET "\n");
        return 1;
    }
}
