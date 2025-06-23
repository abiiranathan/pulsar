# $^: expands to all prerequisites.
# $@: expands to the target name (like server or forms_test)
# $<: first prerequisite.

# Compiler and Flags
CC := gcc
CFLAGS := -Wall -Werror -Wextra -pedantic -O3 -g -std=c23 -D_GNU_SOURCE -fno-builtin -mtune=native -march=native
LDFLAGS :=
INSTALL_PREFIX := /usr/local

# Target Executables
TARGET := server
TEST_TARGET := forms_test

# Source Files
SRC_DIR := src
HEADERS_DIR=include
HEADERS := $(HEADERS_DIR)/arena.h \
		   $(HEADERS_DIR)/forms.h \
		   $(HEADERS_DIR)/headers.h \
		   $(HEADERS_DIR)/mimetype.h \
		   $(HEADERS_DIR)/pulsar.h \
		   $(HEADERS_DIR)/status_code.h \
		   $(HEADERS_DIR)/content_types.h \
		   $(HEADERS_DIR)/utils.h

SRC := main.c $(SRC_DIR)/pulsar.c $(SRC_DIR)/forms.c
TEST_SRCS := $(SRC_DIR)/forms_test.c $(SRC_DIR)/forms.c
LIB_SRCS := $(SRC_DIR)/pulsar.c $(SRC_DIR)/forms.c
STATIC_LIB := libpulsar.a

# Default target
all: $(TARGET)

# Main application build rule
$(TARGET): $(HEADERS) $(SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Test binary build rule
$(TEST_TARGET): $(HEADERS) $(TEST_SRCS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Run tests
test: $(TEST_TARGET)
	./$<

# Build static library
lib: $(STATIC_LIB)

$(STATIC_LIB): $(HEADERS) $(LIB_SRCS)
	$(CC) $(CFLAGS) -fPIC -c $(LIB_SRCS)
	ar rcs $@ *.o
	rm -f *.o

install: lib
	cp $(STATIC_LIB) $(INSTALL_PREFIX)/lib
	mkdir -p $(INSTALL_PREFIX)/include/pulsar
	cp -r $(HEADERS) $(INSTALL_PREFIX)/include/pulsar

# Clean up build artifacts
clean:
	rm -f $(TARGET) $(TEST_TARGET) $(STATIC_LIB) *.o perf.data*

.PHONY: all test lib install clean 

