/* Unit tests for tcp_buffer: growth, compaction, consume, appendv. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>

#include "tcp/tcp_buffer.h"

static void test_init_empty(void) {
    tcp_buffer_t b;
    memset(&b, 0xff, sizeof(b));
    tcp_buffer_init(&b);
    assert(tcp_buffer_size(&b) == 0);
    assert(tcp_buffer_empty(&b));
    assert(tcp_buffer_data(&b) == NULL);
    tcp_buffer_free(&b);
}

static void test_append_and_consume(void) {
    tcp_buffer_t b;
    tcp_buffer_init(&b);

    assert(tcp_buffer_append(&b, "hello", 5) == 0);
    assert(tcp_buffer_size(&b) == 5);
    assert(memcmp(tcp_buffer_data(&b), "hello", 5) == 0);

    assert(tcp_buffer_append(&b, " world", 6) == 0);
    assert(tcp_buffer_size(&b) == 11);
    assert(memcmp(tcp_buffer_data(&b), "hello world", 11) == 0);

    tcp_buffer_consume(&b, 6);
    assert(tcp_buffer_size(&b) == 5);
    assert(memcmp(tcp_buffer_data(&b), "world", 5) == 0);

    tcp_buffer_consume(&b, 100); /* clamped */
    assert(tcp_buffer_size(&b) == 0);
    assert(tcp_buffer_empty(&b));

    tcp_buffer_free(&b);
}

static void test_growth_and_compaction(void) {
    tcp_buffer_t b;
    tcp_buffer_init(&b);

    char chunk[1000];
    for (int i = 0; i < 1000; i++) chunk[i] = (char)(i & 0xff);

    size_t live = 0;
    for (int round = 0; round < 50; round++) {
        assert(tcp_buffer_append(&b, chunk, sizeof(chunk)) == 0);
        live += sizeof(chunk);
        assert(tcp_buffer_size(&b) == live);

        /* Consume a little so head advances and compaction is exercised. */
        size_t take = live < 100 ? live : 100;
        tcp_buffer_consume(&b, take);
        live -= take;
        assert(tcp_buffer_size(&b) == live);
    }

    assert(b.cap >= 1000);
    tcp_buffer_free(&b);
}

static void test_appendv(void) {
    tcp_buffer_t b;
    tcp_buffer_init(&b);

    struct iovec iov[3] = {
        {.iov_base = "abc", .iov_len = 3},
        {.iov_base = "de", .iov_len = 2},
        {.iov_base = "fgh", .iov_len = 3},
    };
    assert(tcp_buffer_appendv(&b, iov, 3) == 0);
    assert(tcp_buffer_size(&b) == 8);
    assert(memcmp(tcp_buffer_data(&b), "abcdefgh", 8) == 0);

    tcp_buffer_free(&b);
}

int main(void) {
    test_init_empty();
    test_append_and_consume();
    test_growth_and_compaction();
    test_appendv();
    printf("test_tcp_buffer: OK\n");
    return 0;
}
