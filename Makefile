# $^: expands to all prerequisites.
# $@: expands to the target name (like server or forms_test)
# $<: first prerequisite.

# Compiler and Flags
CC := gcc
CFLAGS := -Wall -Werror -Wextra -pedantic -O3 -g -std=c23 -D_GNU_SOURCE -fno-builtin -mtune=native -march=native
LDFLAGS :=

# Target Executables
TARGET := server
TEST_TARGET := forms_test

# Source Files
SRC_DIR := src
SRC := main.c $(SRC_DIR)/pulsar.c $(SRC_DIR)/forms.c
TEST_SRCS := $(SRC_DIR)/forms_test.c $(SRC_DIR)/forms.c
LIB_SRCS := $(SRC_DIR)/pulsar.c $(SRC_DIR)/forms.c
STATIC_LIB := libpulsar.a

# Default target
all: $(TARGET)

# Main application build rule
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Test binary build rule
$(TEST_TARGET): $(TEST_SRCS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Run tests
test: $(TEST_TARGET)
	./$<

# Build static library
lib: $(STATIC_LIB)

$(STATIC_LIB): $(LIB_SRCS)
	$(CC) $(CFLAGS) -fPIC -c $(LIB_SRCS)
	ar rcs $@ *.o
	rm -f *.o

# Clean up build artifacts
clean:
	rm -f $(TARGET) $(TEST_TARGET) $(STATIC_LIB) *.o perf.data*

.PHONY: all test lib clean

