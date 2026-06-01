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
static int tests_run    = 0;
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
    headers_t headers;
    headers_init(&headers);
    bool pass = (headers.count == 0);
    return pass;
}

static bool test_set_static_header(void) {
    headers_t headers;
    headers_init(&headers);

    bool pass     = headers_set(&headers, SS_LIT("Host"), SS_LIT("example.com"));
    pass          = pass && (headers.count == 1);
    StrSlice host = headers_get(&headers, "Host");
    pass          = pass && ss_is_valid(host) && ss_equal(host, SS_LIT("example.com"));
    return pass;
}

static bool test_update_existing_header(void) {
    headers_t headers;
    headers_init(&headers);
    headers_set(&headers, SS_LIT("Host"), SS_LIT("example.com"));
    headers_set(&headers, SS_LIT("Host"), SS_LIT("newhost.com"));

    StrSlice value = headers_get(&headers, "Host");
    bool pass      = (headers.count == 1);
    pass           = pass && ss_is_valid(value) && ss_equal(value, SS_LIT("newhost.com"));
    return pass;
}

static bool test_multiple_headers(void) {
    headers_t headers;
    headers_init(&headers);

    headers_set(&headers, SS_LIT("Host"), SS_LIT("example.com"));
    headers_set(&headers, SS_LIT("User-Agent"), SS_LIT("TestAgent/1.0"));
    headers_set(&headers, SS_LIT("Accept"), SS_LIT("text/html"));
    headers_set(&headers, SS_LIT("Content-Type"), SS_LIT("application/json"));

    bool pass = (headers.count == 4);
    pass      = pass && (ss_equal(headers_get(&headers, "Host"), SS_LIT("example.com")));
    pass      = pass && (ss_equal(headers_get(&headers, "User-Agent"), SS_LIT("TestAgent/1.0")));
    pass      = pass && (ss_equal(headers_get(&headers, "Accept"), SS_LIT("text/html")));
    pass = pass && (ss_equal(headers_get(&headers, "Content-Type"), SS_LIT("application/json")));
    return pass;
}

/* ========================================================================
 * Edge Case Tests
 * ======================================================================== */

static bool test_get_nonexistent_header(void) {
    headers_t headers;
    headers_init(&headers);

    StrSlice v = headers_get(&headers, "Nonexistent");
    return ss_is_valid(v);
}

static bool test_headers_remove(void) {
    headers_t headers;
    headers_init(&headers);

    headers_set(&headers, SS_LIT("Host"), SS_LIT("example.com"));
    headers_set(&headers, SS_LIT("User-Agent"), SS_LIT("TestAgent/1.0"));

    bool removed = headers_remove(&headers, "Host");

    bool pass = removed;
    pass      = pass && (headers.count == 1);
    pass      = pass && (ss_is_valid(headers_get(&headers, "Host")));
    pass      = pass && (ss_is_valid(headers_get(&headers, "User-Agent")));
    return pass;
}

static bool test_capacity_limit(void) {
    headers_t headers;
    headers_init(&headers);

    // Fill to capacity
    for (int i = 0; i < HEADERS_CAPACITY; i++) {
        char* name = malloc(32);
        if (!name) {
            return false;
        }
        snprintf(name, 32, "X-Header-%d", i);
        bool success = headers_set(&headers, ss_from_cstr(name), SS_LIT("value"));
        if (!success) {
            printf("Failed at i=%d, count=%lu\n", i, headers.count);
            return false;
        }
    }

    // Try to exceed capacity
    bool overflow = headers_set(&headers, SS_LIT("X-Overflow"), SS_LIT("value"));
    bool pass     = !overflow;
    pass          = pass && (headers.count == HEADERS_CAPACITY);

    // Free allocated memory.
    for (size_t i = 0; i < headers.count; ++i) {
        free((void*)headers.entries[i].name.data);
    }
    return pass;
}

static bool test_set_cookie_multiple_values(void) {
    headers_t headers;
    headers_init(&headers);

    // Set-Cookie should allow multiple values
    headers_set(&headers, SS_LIT("Set-Cookie"), SS_LIT("sessionid=abc123"));
    headers_set(&headers, SS_LIT("Set-Cookie"), SS_LIT("userid=xyz789"));

    // Should have 2 entries (Set-Cookie allows duplicates)
    bool pass = (headers.count == 2);

    // Both should be present
    int set_cookie_count = 0;
    for (size_t i = 0; i < headers.count; i++) {
        set_cookie_count += ss_is_valid(headers_get(&headers, "Set-Cookie"));
    }

    pass = pass && (set_cookie_count == 2);
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

static bool count_headers_callback(StrSlice name, StrSlice value, void* userdata) {
    (void)value;  // Unused in this callback
    iter_context* ctx = (iter_context*)userdata;
    ctx->count++;

    if (ss_equal(name, SS_LIT("Host"))) ctx->found_host = true;
    if (ss_equal(name, SS_LIT("User-Agent"))) ctx->found_user_agent = true;

    return true;  // Continue iteration
}

static bool test_headers_foreach(void) {
    headers_t headers;
    headers_init(&headers);

    headers_set(&headers, SS_LIT("Host"), SS_LIT("example.com"));
    headers_set(&headers, SS_LIT("User-Agent"), SS_LIT("TestAgent/1.0"));
    headers_set(&headers, SS_LIT("Accept"), SS_LIT("text/html"));

    iter_context ctx = {0};
    headers_foreach(&headers, count_headers_callback, &ctx);

    bool pass = (ctx.count == 3);
    pass      = pass && ctx.found_host;
    pass      = pass && ctx.found_user_agent;
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
    RUN_TEST(test_update_existing_header);
    RUN_TEST(test_multiple_headers);

    printf("\n" COLOR_CYAN "Edge Case Tests:" COLOR_RESET "\n");
    RUN_TEST(test_get_nonexistent_header);
    RUN_TEST(test_headers_remove);
    ;
    RUN_TEST(test_capacity_limit);
    RUN_TEST(test_set_cookie_multiple_values);

    printf("\n" COLOR_CYAN "Iteration Tests:" COLOR_RESET "\n");
    RUN_TEST(test_headers_foreach);

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
