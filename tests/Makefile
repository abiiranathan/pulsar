CC := gcc
CFLAGS := -Wall -Wextra -O3 -march=native -std=c11 -D_POSIX_C_SOURCE=199309L
LDFLAGS := -lrt

# Detect architecture for SIMD flags
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    SIMD_FLAGS := -mavx2
else ifeq ($(ARCH),aarch64)
    SIMD_FLAGS := -march=armv8-a+simd
endif

CFLAGS += $(SIMD_FLAGS)

.PHONY: all test benchmark example clean

all: test benchmark example

test: test_memmem
	@echo "Running tests..."
	@./test_memmem

benchmark: benchmark_memmem
	@echo "Running benchmarks..."
	@./benchmark_memmem

test_memmem: test_memmem.c ../include/memmem.h
	$(CC) $(CFLAGS) -o test_memmem test_memmem.c $(LDFLAGS)

benchmark_memmem: benchmark_memmem.c ../include/memmem.h
	$(CC) $(CFLAGS) -o benchmark_memmem benchmark_memmem.c $(LDFLAGS)

clean:
	rm -f test_memmem benchmark_memmem

help:
	@echo "Available targets:"
	@echo "  all       - Build test and benchmark (default)"
	@echo "  test      - Build and run tests"
	@echo "  benchmark - Build and run benchmarks"
	@echo "  clean     - Remove built executables"