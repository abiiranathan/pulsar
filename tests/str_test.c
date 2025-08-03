#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/str.h"

static void print_str(const char* label, str s) {
    printf("%s: \"", label);
    for (size_t i = 0; i < s.size; i++) {
        putchar(s.data[i]);
    }
    printf("\" (len: %zu)\n", s.size);
}

static void print_str_buf(const char* label, const str_buf* buf) {
    printf("%s: \"", label);
    for (size_t i = 0; i < buf->size; i++) {
        putchar(buf->data[i]);
    }
    printf("\" (len: %zu, cap: %zu)\n", buf->size, buf->capacity);
}

// ============================================================================
// String View Tests
// ============================================================================

static void test_string_views(void) {
    printf("\n=== String View Tests ===\n");

    // Basic string view operations
    str s1 = str_from_cstr("Hello, World!");
    str s2 = str_from_cstr("Hello, World!");
    str s3 = str_from_cstr("Goodbye!");

    assert(str_cmp(s1, s2) == 0 && "Identical strings should compare equal");
    assert(str_cmp(s1, s3) != 0 && "Different strings should compare unequal");

    // Substring operations
    str hello = str_substr(s1, 0, 5);
    str world = str_substr(s1, 7, 5);
    print_str("hello", hello);
    print_str("world", world);

    assert(hello.size == 5 && "Substring should have correct length");
    assert(memcmp(hello.data, "Hello", 5) == 0 && "Substring content should match");

    // String searching
    str needle = str_from_cstr("World");
    size_t pos = str_find(s1, needle);
    printf("Position of 'World' in '%.*s': %zu\n", (int)s1.size, s1.data, pos);
    assert(pos == 7 && "Should find substring at correct position");

    // Prefix/suffix testing
    str hello_prefix   = str_from_cstr("Hello");
    str exclaim_suffix = str_from_cstr("!");
    assert(str_starts_with(s1, hello_prefix) && "Should detect prefix");
    assert(str_ends_with(s1, exclaim_suffix) && "Should detect suffix");

    // Trimming
    str padded  = str_from_cstr("  \t  trim me  \n  ");
    str trimmed = str_trim(padded);
    print_str("original", padded);
    print_str("trimmed", trimmed);
    assert(trimmed.size == 7 && "Trimmed string should have correct length");
    assert(memcmp(trimmed.data, "trim me", 7) == 0 && "Trimmed content should match");

    // Case insensitive comparison
    str upper = str_from_cstr("HELLO");
    str lower = str_from_cstr("hello");
    assert(str_cmp(upper, lower) != 0 && "Case sensitive compare should differ");
    assert(str_icmp(upper, lower) == 0 && "Case insensitive compare should match");

    printf("All string view tests passed!\n");
}

// ============================================================================
// String Buffer Tests with Default Allocator
// ============================================================================

static void test_string_buffer_default(void) {
    printf("\n=== String Buffer Tests (Default Allocator) ===\n");

    str_buf buf = {0};
    str_result_t result;

    // Initialize buffer
    result = str_buf_init(&buf, NULL);
    assert(result == STR_OK && "Buffer initialization should succeed");

    // Test appending
    result = str_buf_append_cstr(&buf, "Hello");
    assert(result == STR_OK && "Appending C string should succeed");
    print_str_buf("after append", &buf);
    assert(buf.size == 5 && "Buffer size should match appended content");

    result = str_buf_append_cstr(&buf, ", ");
    assert(result == STR_OK && "Appending should succeed");

    result = str_buf_append_cstr(&buf, "World!");
    assert(result == STR_OK && "Appending should succeed");
    print_str_buf("final string", &buf);
    assert(buf.size == 13 && "Buffer size should match final content");

    // Test character append
    result = str_buf_append_char(&buf, ' ');
    assert(result == STR_OK && "Appending character should succeed");

    // Test formatted append
    result = str_buf_appendf(&buf, "Number: %d, Float: %.2f", 42, 3.14159);
    assert(result == STR_OK && "Formatted append should succeed");
    print_str_buf("after formatting", &buf);

    // Test insertion
    result = str_buf_insert(&buf, 5, str_from_cstr(" there"));
    assert(result == STR_OK && "Insertion should succeed");
    print_str_buf("after insertion", &buf);

    assert(buf.size == 43 && "Buffer size should match after insertion");

    // Test removal
    result = str_buf_remove(&buf, 5, 6);
    assert(result == STR_OK && "Removal should succeed");
    print_str_buf("after removal", &buf);
    assert(buf.size == 37 && "Buffer size should match after removal");

    // Test replacement
    result = str_buf_replace_all(&buf, str_from_cstr("World"), str_from_cstr("Universe"));
    assert(result == STR_OK && "Replacement should succeed");
    print_str_buf("after replacement", &buf);

    // Test reserve
    printf("Capacity before reserve: %zu\n", buf.capacity);
    result = str_buf_reserve(&buf, 1000);
    assert(result == STR_OK && "Reserve should succeed");
    printf("Capacity after reserve: %zu\n", buf.capacity);
    assert(buf.capacity >= 1000 && "Capacity should be at least reserved amount");

    // Test clear
    str_buf_clear(&buf);
    printf("Size after clear: %zu (capacity: %zu)\n", buf.size, buf.capacity);
    assert(buf.size == 0 && "Size should be 0 after clear");
    assert(buf.capacity > 0 && "Capacity should remain after clear");

    // Clean up
    str_buf_free(&buf);
    printf("Buffer freed\n");
}

// ============================================================================
// String Buffer Tests with Custom Arena Allocator
// ============================================================================

static void test_string_buffer_arena(void) {
    printf("\n=== String Buffer Tests (Arena Allocator) ===\n");

    str_buf buf1 = {0}, buf2 = {0};
    allocator_t* allocator = arena_allocator_create(1024);
    assert(allocator != NULL && "Arena allocator creation should succeed");

    // Initialize buffers
    str_result_t result = str_buf_init_cap(&buf1, 100, allocator);
    assert(result == STR_OK && "Buffer1 initialization should succeed");

    result = str_buf_init_cap(&buf2, 50, allocator);
    assert(result == STR_OK && "Buffer2 initialization should succeed");

    // Build a larger string in buf1
    for (int i = 0; i < 10; i++) {
        result = str_buf_appendf(&buf1, "Line %d: This is a test string. ", i);
        assert(result == STR_OK && "Appendf should succeed");
    }
    print_str_buf("buf1 after loop", &buf1);

    // Build another string in buf2
    result = str_buf_append_cstr(&buf2, "Buffer 2 contents: ");
    assert(result == STR_OK && "Append should succeed");

    for (char c = 'A'; c <= 'Z'; c++) {
        result = str_buf_append_char(&buf2, c);
        assert(result == STR_OK && "Character append should succeed");
    }
    print_str_buf("buf2 final", &buf2);

    // Test string operations
    str view1 = str_buf_view(&buf1);
    str view2 = str_buf_view(&buf2);

    assert(str_starts_with(view1, str_from_cstr("Line 0")) && "Should detect prefix");
    assert(str_ends_with(view2, str_from_cstr("Z")) && "Should detect suffix");

    // Find pattern in buf1
    size_t pos = str_find(view1, str_from_cstr("Line 5"));
    printf("Position of 'Line 5' in buf1: %zu\n", pos);
    assert(pos != SIZE_MAX && "Should find substring");

    // Free resources
    str_buf_free(&buf1);
    str_buf_free(&buf2);
    arena_allocator_destroy(allocator);
    printf("Arena allocator tests passed!\n");
}

// ============================================================================
// Performance and Stress Tests
// ============================================================================

static void test_performance(void) {
    printf("\n=== Performance Tests ===\n");

    str_buf buf;
    str_result_t result = str_buf_init(&buf, NULL);
    assert(result == STR_OK && "Buffer initialization should succeed");

    printf("Building large string...\n");

    // Build a large string by appending many small pieces
    const int iterations = 10000;
    for (int i = 0; i < iterations; i++) {
        result = str_buf_appendf(&buf, "Item %05d ", i);
        assert(result == STR_OK && "Appendf should succeed");

        if (i % 1000 == 0) {
            printf("Progress: %d/%d (size: %zu, capacity: %zu)\n", i, iterations, buf.size, buf.capacity);
        }
    }

    printf("Final string: size=%zu, capacity=%zu\n", buf.size, buf.capacity);
    printf("Growth efficiency: %.2f%% (capacity/size)\n", (double)buf.capacity / buf.size * 100.0);

    // Test operations on the large string
    str view = str_buf_view(&buf);

    printf("Testing search in large string...\n");
    size_t pos = str_find(view, str_from_cstr("Item 05000"));
    printf("Found 'Item 05000' at position: %zu\n", pos);
    assert(pos != SIZE_MAX && "Should find item in large string");

    printf("Testing replacement in large string...\n");
    result = str_buf_replace_all(&buf, str_from_cstr("Item"), str_from_cstr("Entry"));
    assert(result == STR_OK && "Mass replacement should succeed");
    printf("String size after replacement: %zu\n", buf.size);

    str_buf_free(&buf);
    printf("Performance tests completed!\n");
}

// ============================================================================
// Edge Case and Error Handling Tests
// ============================================================================

static void test_edge_cases(void) {
    printf("\n=== Edge Case Tests ===\n");

    // Test with null pointers
    str null_str = str_from_cstr(NULL);
    assert(null_str.size == 0 && "Null string should have size 0");

    // Test empty strings
    str empty = str_empty();
    assert(str_is_empty(empty) && "Empty string should be empty");

    // Test out-of-bounds substring
    str test_str   = str_from_cstr("short");
    str oob_substr = str_substr(test_str, 10, 5);
    assert(oob_substr.size == 0 && "Out-of-bounds substring should be empty");

    // Test buffer operations with invalid parameters
    str_buf buf;
    str_result_t result = str_buf_init(&buf, NULL);
    assert(result == STR_OK && "Buffer initialization should succeed");

    // Try to insert at invalid position
    result = str_buf_insert(&buf, 100, str_from_cstr("test"));
    assert(result == STR_ERR_INVALID_ARG && "Should reject invalid insert position");

    // Try to remove more than available
    str_buf_append_cstr(&buf, "Hello");
    result = str_buf_remove(&buf, 2, 100);
    assert(result == STR_OK && "Should handle over-removal gracefully");
    print_str_buf("after over-removal", &buf);
    assert(buf.size == 2 && "Should have correct size after over-removal");

    str_buf_free(&buf);
    printf("Edge case tests passed!\n");
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main(void) {
    printf("String Library Test Suite\n");
    printf("=========================\n");

    test_string_views();
    test_string_buffer_default();
    test_string_buffer_arena();
    test_performance();
    test_edge_cases();

    printf("\n=== All Tests Passed ===\n");
    return 0;
}
