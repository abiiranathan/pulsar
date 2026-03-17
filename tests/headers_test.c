/**
 * @file test_headers.c
 * @brief Comprehensive test suite for headers.h
 *
 * Covers:
 * - Static header operations
 * - Custom header operations
 * - Edge cases (capacity, duplicates, case-insensitivity)
 * - Performance characteristics
 * - Multi-value headers (Set-Cookie)
 * Link with solidc: -lsolidc
 */

#include "../include/headers.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Color output for better readability */
#define COLOR_RESET  "\033[0m"
#define COLOR_GREEN  "\033[32m"
#define COLOR_RED    "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_CYAN   "\033[36m"

#define TEST_PASS()      printf(COLOR_GREEN "✓ PASS" COLOR_RESET "\n")
#define TEST_FAIL()      printf(COLOR_RED "✗ FAIL" COLOR_RESET "\n")
#define TEST_START(name) printf(COLOR_CYAN "Testing: %s" COLOR_RESET "... ", name)

/* Test counters */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/* Test runner macro */
#define RUN_TEST(test_func)     \
    do {                        \
        TEST_START(#test_func); \
        tests_run++;            \
        if (test_func()) {      \
            tests_passed++;     \
            TEST_PASS();        \
        } else {                \
            tests_failed++;     \
            TEST_FAIL();        \
        }                       \
    } while (0)

/* ========================================================================
 * Basic Functionality Tests
 * ======================================================================== */

static bool test_headers_init(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;

    headers_init(&headers, (Arena*)arena);

    bool pass = (headers.count == 0 && headers.mask == 0 && headers.arena == (Arena*)arena);

    arena_destroy(arena);
    return pass;
}

static bool test_set_static_header(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    bool pass = headers_set(&headers, "Host", "example.com");
    pass = pass && (headers.count == 1);
    pass = pass && (headers.mask & (1ULL << HDR_HOST));

    arena_destroy(arena);
    return pass;
}

static bool test_get_static_header(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    headers_set(&headers, "Host", "example.com");
    const char* value = headers_get_static(&headers, HDR_HOST);

    bool pass = (value != NULL && strcmp(value, "example.com") == 0);

    arena_destroy(arena);
    return pass;
}

static bool test_get_by_name(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    headers_set(&headers, "Content-Type", "application/json");
    const char* value = headers_get(&headers, "Content-Type");

    bool pass = (value != NULL && strcmp(value, "application/json") == 0);

    arena_destroy(arena);
    return pass;
}

static bool test_case_insensitive_lookup(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    headers_set(&headers, "Content-Type", "text/html");

    const char* v1 = headers_get(&headers, "content-type");
    const char* v2 = headers_get(&headers, "CONTENT-TYPE");
    const char* v3 = headers_get(&headers, "CoNtEnT-TyPe");

    bool pass = (v1 != NULL && strcmp(v1, "text/html") == 0);
    pass = pass && (v2 != NULL && strcmp(v2, "text/html") == 0);
    pass = pass && (v3 != NULL && strcmp(v3, "text/html") == 0);

    arena_destroy(arena);
    return pass;
}

static bool test_update_existing_header(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    headers_set(&headers, "Host", "example.com");
    headers_set(&headers, "Host", "newhost.com");

    const char* value = headers_get(&headers, "Host");
    bool pass = (headers.count == 1);
    pass = pass && (value != NULL && strcmp(value, "newhost.com") == 0);

    arena_destroy(arena);
    return pass;
}

static bool test_custom_header(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    headers_set(&headers, "X-Custom-Header", "custom-value");
    const char* value = headers_get(&headers, "X-Custom-Header");

    bool pass = (headers.count == 1);
    pass = pass && (value != NULL && strcmp(value, "custom-value") == 0);
    // Custom headers shouldn't set bits in mask (except bit 0)
    pass = pass && ((headers.mask & ~1ULL) == 0);

    arena_destroy(arena);
    return pass;
}

static bool test_multiple_headers(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    headers_set(&headers, "Host", "example.com");
    headers_set(&headers, "User-Agent", "TestAgent/1.0");
    headers_set(&headers, "Accept", "text/html");
    headers_set(&headers, "Content-Type", "application/json");

    bool pass = (headers.count == 4);
    pass = pass && (strcmp(headers_get(&headers, "Host"), "example.com") == 0);
    pass = pass && (strcmp(headers_get(&headers, "User-Agent"), "TestAgent/1.0") == 0);
    pass = pass && (strcmp(headers_get(&headers, "Accept"), "text/html") == 0);
    pass = pass && (strcmp(headers_get(&headers, "Content-Type"), "application/json") == 0);

    arena_destroy(arena);
    return pass;
}

/* ========================================================================
 * Edge Case Tests
 * ======================================================================== */

static bool test_headers_has(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    headers_set(&headers, "Host", "example.com");

    bool pass = headers_has(&headers, "Host");
    pass = pass && headers_has(&headers, "host");
    pass = pass && !headers_has(&headers, "Content-Type");

    arena_destroy(arena);
    return pass;
}

static bool test_get_nonexistent_header(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    const char* value = headers_get(&headers, "Nonexistent");
    bool pass = (value == NULL);

    const char* static_value = headers_get_static(&headers, HDR_AUTHORIZATION);
    pass = pass && (static_value == NULL);

    arena_destroy(arena);
    return pass;
}

static bool test_headers_remove(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    headers_set(&headers, "Host", "example.com");
    headers_set(&headers, "User-Agent", "TestAgent/1.0");

    bool removed = headers_remove(&headers, "Host");

    bool pass = removed;
    pass = pass && (headers.count == 1);
    pass = pass && (headers_get(&headers, "Host") == NULL);
    pass = pass && (headers_get(&headers, "User-Agent") != NULL);
    pass = pass && !(headers.mask & (1ULL << HDR_HOST));

    arena_destroy(arena);
    return pass;
}

static bool test_remove_nonexistent(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    headers_set(&headers, "Host", "example.com");
    bool removed = headers_remove(&headers, "Nonexistent");

    bool pass = !removed;
    pass = pass && (headers.count == 1);

    arena_destroy(arena);
    return pass;
}

static bool test_remove_custom_header(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    headers_set(&headers, "X-Custom", "value");
    bool removed = headers_remove(&headers, "X-Custom");

    bool pass = removed;
    pass = pass && (headers.count == 0);
    pass = pass && (headers_get(&headers, "X-Custom") == NULL);

    arena_destroy(arena);
    return pass;
}

static bool test_capacity_limit(void) {
    Arena* arena = arena_create(65536);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    // Fill to capacity
    char name[32];
    for (int i = 0; i < HEADERS_CAPACITY; i++) {
        snprintf(name, sizeof(name), "X-Header-%d", i);
        bool success = headers_set(&headers, name, "value");
        if (!success) return false;
    }

    // Try to exceed capacity
    bool overflow = headers_set(&headers, "X-Overflow", "value");

    bool pass = !overflow;
    pass = pass && (headers.count == HEADERS_CAPACITY);

    arena_destroy(arena);
    return pass;
}

static bool test_empty_value(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    headers_set(&headers, "X-Empty", "");
    const char* value = headers_get(&headers, "X-Empty");

    bool pass = (value != NULL && strlen(value) == 0);

    arena_destroy(arena);
    return pass;
}

static bool test_set_cookie_multiple_values(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    // Set-Cookie should allow multiple values
    headers_set(&headers, "Set-Cookie", "sessionid=abc123");
    headers_set(&headers, "Set-Cookie", "userid=xyz789");

    // Should have 2 entries (Set-Cookie allows duplicates)
    bool pass = (headers.count == 2);

    // Both should be present
    int set_cookie_count = 0;
    for (size_t i = 0; i < headers.count; i++) {
        if (headers.entries[i].id == HDR_SET_COOKIE) {
            set_cookie_count++;
        }
    }
    pass = pass && (set_cookie_count == 2);

    arena_destroy(arena);
    return pass;
}

/* ========================================================================
 * Iteration Tests
 * ======================================================================== */

typedef struct {
    int count;
    bool found_host;
    bool found_user_agent;
} iter_context;

static bool count_headers_callback(const char* name, const char* value, void* userdata) {
    (void)value;  // Unused in this callback
    iter_context* ctx = (iter_context*)userdata;
    ctx->count++;

    if (strcasecmp(name, "Host") == 0) ctx->found_host = true;
    if (strcasecmp(name, "User-Agent") == 0) ctx->found_user_agent = true;

    return true;  // Continue iteration
}

static bool test_headers_foreach(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    headers_set(&headers, "Host", "example.com");
    headers_set(&headers, "User-Agent", "TestAgent/1.0");
    headers_set(&headers, "Accept", "text/html");

    iter_context ctx = {0};
    headers_foreach(&headers, count_headers_callback, &ctx);

    bool pass = (ctx.count == 3);
    pass = pass && ctx.found_host;
    pass = pass && ctx.found_user_agent;

    arena_destroy(arena);
    return pass;
}

static bool early_exit_callback(const char* name, const char* value, void* userdata) {
    (void)name;   // Unused in this callback
    (void)value;  // Unused in this callback
    int* count = (int*)userdata;
    (*count)++;
    return (*count < 2);  // Stop after 2 iterations
}

static bool test_foreach_early_exit(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    headers_set(&headers, "Host", "example.com");
    headers_set(&headers, "User-Agent", "TestAgent/1.0");
    headers_set(&headers, "Accept", "text/html");
    headers_set(&headers, "Content-Type", "application/json");

    int count = 0;
    headers_foreach(&headers, early_exit_callback, &count);

    bool pass = (count == 2);

    arena_destroy(arena);
    return pass;
}

/* ========================================================================
 * All Static Headers Test
 * ======================================================================== */

static bool test_all_static_headers(void) {
    Arena* arena = arena_create(65536);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    // Test a representative sample of all header types
    const struct {
        const char* name;
        header_id_t id;
    } test_headers[] = {
        {"Host", HDR_HOST},
        {"User-Agent", HDR_USER_AGENT},
        {"Accept", HDR_ACCEPT},
        {"Accept-Encoding", HDR_ACCEPT_ENCODING},
        {"Content-Type", HDR_CONTENT_TYPE},
        {"Content-Length", HDR_CONTENT_LENGTH},
        {"Authorization", HDR_AUTHORIZATION},
        {"Cookie", HDR_COOKIE},
        {"Set-Cookie", HDR_SET_COOKIE},
        {"Location", HDR_LOCATION},
        {"Cache-Control", HDR_CACHE_CONTROL},
        {"Access-Control-Allow-Origin", HDR_ACCESS_CONTROL_ALLOW_ORIGIN},
        {"Content-Security-Policy", HDR_CONTENT_SECURITY_POLICY},
        {"Strict-Transport-Security", HDR_STRICT_TRANSPORT_SECURITY},
        {"X-Forwarded-For", HDR_X_FORWARDED_FOR},
    };

    bool pass = true;

    for (size_t i = 0; i < sizeof(test_headers) / sizeof(test_headers[0]); i++) {
        headers_set(&headers, test_headers[i].name, "test-value");

        const char* value = headers_get(&headers, test_headers[i].name);
        if (!value || strcmp(value, "test-value") != 0) {
            printf("\nFailed for header: %s", test_headers[i].name);
            pass = false;
        }

        const char* static_value = headers_get_static(&headers, test_headers[i].id);
        if (!static_value || strcmp(static_value, "test-value") != 0) {
            printf("\nFailed static get for header: %s", test_headers[i].name);
            pass = false;
        }

        if (!(headers.mask & (1ULL << test_headers[i].id))) {
            printf("\nMask not set for header: %s", test_headers[i].name);
            pass = false;
        }
    }

    arena_destroy(arena);
    return pass;
}

/* ========================================================================
 * Performance Tests
 * ======================================================================== */

static bool test_static_header_performance(void) {
    Arena* arena = arena_create(65536);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    // Add several headers
    headers_set(&headers, "Host", "example.com");
    headers_set(&headers, "User-Agent", "TestAgent/1.0");
    headers_set(&headers, "Accept", "text/html");
    headers_set(&headers, "Content-Type", "application/json");
    headers_set(&headers, "Authorization", "Bearer token123");

    // Time static lookups (should be O(1) check + small loop)
    clock_t start = clock();
    for (int i = 0; i < 1000000; i++) {
        headers_get_static(&headers, HDR_HOST);
        headers_get_static(&headers, HDR_AUTHORIZATION);
        headers_get_static(&headers, HDR_CONTENT_TYPE);
    }
    clock_t end = clock();

    double elapsed = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("\n    Static lookups (3M ops): %.4f sec", elapsed);

    arena_destroy(arena);
    return true;  // Always pass, just informational
}

static bool test_bitmask_optimization(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    // Test that bitmask prevents unnecessary loops
    headers_set(&headers, "Host", "example.com");

    // These should return immediately (bit not set)
    clock_t start = clock();
    for (int i = 0; i < 1000000; i++) {
        headers_get_static(&headers, HDR_AUTHORIZATION);
        headers_get_static(&headers, HDR_CONTENT_TYPE);
        headers_get_static(&headers, HDR_COOKIE);
    }
    clock_t end = clock();

    double elapsed = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("\n    Bitmask short-circuit (3M ops): %.4f sec", elapsed);

    bool pass = (elapsed < 0.1);  // Should be nearly instant

    arena_destroy(arena);
    return pass;
}

/* ========================================================================
 * Mixed Static and Custom Headers
 * ======================================================================== */

static bool test_mixed_headers(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    headers_set(&headers, "Host", "example.com");
    headers_set(&headers, "X-Custom-1", "value1");
    headers_set(&headers, "Content-Type", "application/json");
    headers_set(&headers, "X-Custom-2", "value2");
    headers_set(&headers, "User-Agent", "TestAgent/1.0");

    bool pass = (headers.count == 5);
    pass = pass && (strcmp(headers_get(&headers, "Host"), "example.com") == 0);
    pass = pass && (strcmp(headers_get(&headers, "X-Custom-1"), "value1") == 0);
    pass = pass && (strcmp(headers_get(&headers, "Content-Type"), "application/json") == 0);
    pass = pass && (strcmp(headers_get(&headers, "X-Custom-2"), "value2") == 0);
    pass = pass && (strcmp(headers_get(&headers, "User-Agent"), "TestAgent/1.0") == 0);

    arena_destroy(arena);
    return pass;
}

static bool test_update_custom_header(void) {
    Arena* arena = arena_create(4096);
    headers_t headers;
    headers_init(&headers, (Arena*)arena);

    headers_set(&headers, "X-Custom", "original");
    headers_set(&headers, "X-Custom", "updated");

    const char* value = headers_get(&headers, "X-Custom");
    bool pass = (headers.count == 1);
    pass = pass && (value != NULL && strcmp(value, "updated") == 0);

    arena_destroy(arena);
    return pass;
}

/* ========================================================================
 * Main Test Runner
 * ======================================================================== */

int main(void) {
    printf(COLOR_YELLOW "\n╔════════════════════════════════════════╗\n");
    printf("║   Headers.h Test Suite                ║\n");
    printf("╚════════════════════════════════════════╝\n" COLOR_RESET);

    printf("\n" COLOR_CYAN "Basic Functionality Tests:" COLOR_RESET "\n");
    RUN_TEST(test_headers_init);
    RUN_TEST(test_set_static_header);
    RUN_TEST(test_get_static_header);
    RUN_TEST(test_get_by_name);
    RUN_TEST(test_case_insensitive_lookup);
    RUN_TEST(test_update_existing_header);
    RUN_TEST(test_custom_header);
    RUN_TEST(test_multiple_headers);

    printf("\n" COLOR_CYAN "Edge Case Tests:" COLOR_RESET "\n");
    RUN_TEST(test_headers_has);
    RUN_TEST(test_get_nonexistent_header);
    RUN_TEST(test_headers_remove);
    RUN_TEST(test_remove_nonexistent);
    RUN_TEST(test_remove_custom_header);
    RUN_TEST(test_capacity_limit);
    RUN_TEST(test_empty_value);
    RUN_TEST(test_set_cookie_multiple_values);

    printf("\n" COLOR_CYAN "Iteration Tests:" COLOR_RESET "\n");
    RUN_TEST(test_headers_foreach);
    RUN_TEST(test_foreach_early_exit);

    printf("\n" COLOR_CYAN "Comprehensive Tests:" COLOR_RESET "\n");
    RUN_TEST(test_all_static_headers);
    RUN_TEST(test_mixed_headers);
    RUN_TEST(test_update_custom_header);

    printf("\n" COLOR_CYAN "Performance Tests:" COLOR_RESET "\n");
    RUN_TEST(test_static_header_performance);
    RUN_TEST(test_bitmask_optimization);

    /* Summary */
    printf("\n" COLOR_YELLOW "╔════════════════════════════════════════╗\n");
    printf("║   Test Summary                         ║\n");
    printf("╚════════════════════════════════════════╝\n" COLOR_RESET);
    printf("Total tests:  %d\n", tests_run);
    printf(COLOR_GREEN "Passed:       %d\n" COLOR_RESET, tests_passed);
    if (tests_failed > 0) {
        printf(COLOR_RED "Failed:       %d\n" COLOR_RESET, tests_failed);
    } else {
        printf("Failed:       %d\n", tests_failed);
    }
    printf("Success rate: %.1f%%\n", (100.0 * tests_passed) / tests_run);

    if (tests_failed == 0) {
        printf("\n" COLOR_GREEN "✓ All tests passed!\n" COLOR_RESET);
        return 0;
    } else {
        printf("\n" COLOR_RED "✗ Some tests failed!\n" COLOR_RESET);
        return 1;
    }
}
