# === Configuration ===

# Compiler
CC ?= gcc

# Installation prefix
INSTALL_PREFIX ?= /usr/local

# Build mode: debug or release
BUILD ?= release

# === Platform Detection ===

UNAME := $(shell uname -s)

ifeq ($(UNAME), Darwin)
    LIBEXT := dylib
    SONAME_FLAG := -install_name
    SHARED_FLAG := -dynamiclib
else
    LIBEXT := so
    SONAME_FLAG := -soname
    SHARED_FLAG := -shared
endif

# === Compiler Flags ===

DEFINES := -DDA_IMPLEMENTATION -D_GNU_SOURCE
BASE_CFLAGS := -Wall -Werror -Wextra -pedantic -std=c23 -fPIC -Iinclude $(DEFINES) \
               -Wno-unused-function -Wno-gnu-zero-variadic-macro-arguments

ifeq ($(BUILD), debug)
    CFLAGS := $(BASE_CFLAGS) -O0 -g3 -DDEBUG
    BUILD_DIR := build/debug
else ifeq ($(BUILD), release)
    CFLAGS := $(BASE_CFLAGS) -O3 -g -mtune=native -march=native -mavx2
    BUILD_DIR := build/release
else
    $(error Invalid BUILD type: $(BUILD). Use 'debug' or 'release')
endif

LDFLAGS := -pthread -lsolidc -lm

# === Directories and Files ===

SRC_DIR := src
HEADERS_DIR := include
TEST_DIR := tests

BASE_SRC := $(SRC_DIR)/routing.c \
            $(SRC_DIR)/locals.c \
            $(SRC_DIR)/pulsar.c \
            $(SRC_DIR)/forms.c

HEADERS := $(wildcard $(HEADERS_DIR)/*.h)
LIB_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(BASE_SRC))

TEST_SRCS := $(wildcard $(TEST_DIR)/*.c)
TEST_TARGETS := $(patsubst $(TEST_DIR)/%.c,$(BUILD_DIR)/tests/%,$(TEST_SRCS))

# === Library Configuration ===

STATIC_LIB := $(BUILD_DIR)/libpulsar.a
SHARED_LIB := $(BUILD_DIR)/libpulsar.$(LIBEXT)
LIB_VERSION := 1.0.0
SONAME := libpulsar.$(LIBEXT).1

# === Targets ===

TARGET := $(BUILD_DIR)/server
MAIN_SRC := main.c

.PHONY: all test static shared lib install verify clean debug release

all: $(TARGET)

# Build main application
$(TARGET): $(MAIN_SRC) $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(MAIN_SRC) $(LIB_OBJS) -o $@ $(LDFLAGS)

# Build object files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Build static library
static: $(STATIC_LIB)

$(STATIC_LIB): $(LIB_OBJS)
	@mkdir -p $(dir $@)
	ar rcs $@ $^
	ranlib $@

# Build shared library
shared: $(SHARED_LIB)

$(SHARED_LIB): $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(SHARED_FLAG) -Wl,$(SONAME_FLAG),$(SONAME) -o $@.$(LIB_VERSION) $^ $(LDFLAGS)
	ln -sf libpulsar.$(LIBEXT).$(LIB_VERSION) $@
	ln -sf libpulsar.$(LIBEXT).$(LIB_VERSION) $(BUILD_DIR)/$(SONAME)

# Build both libraries
lib: static shared

# Build test executables
$(BUILD_DIR)/tests/%: $(TEST_DIR)/%.c $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< $(LIB_OBJS) -o $@ $(LDFLAGS)

# Run tests
test: $(TEST_TARGETS)
	@for test in $^; do \
		echo "Running $$test..."; \
		$$test || exit 1; \
	done

# Memory check with valgrind
check:
	valgrind --leak-check=full --show-leak-kinds=all --suppressions=glibc.supp $(BUILD_DIR)/server

# Install libraries and headers
install: lib
	install -d $(INSTALL_PREFIX)/lib
	install -m 644 $(STATIC_LIB) $(INSTALL_PREFIX)/lib/
	install -m 755 $(SHARED_LIB).$(LIB_VERSION) $(INSTALL_PREFIX)/lib/
	ln -sf libpulsar.$(LIBEXT).$(LIB_VERSION) $(INSTALL_PREFIX)/lib/libpulsar.$(LIBEXT)
	ln -sf libpulsar.$(LIBEXT).$(LIB_VERSION) $(INSTALL_PREFIX)/lib/$(SONAME)
	install -d $(INSTALL_PREFIX)/include/pulsar
	install -m 644 $(HEADERS) $(INSTALL_PREFIX)/include/pulsar/
ifeq ($(UNAME), Linux)
	ldconfig
endif

# Verify library architecture
verify:
ifeq ($(UNAME), Darwin)
	@echo "Verifying library..."
	@file $(SHARED_LIB).$(LIB_VERSION)
else
	@echo "Verifying shared library..."
	@file $(SHARED_LIB).$(LIB_VERSION)
endif

# Clean build artifacts
clean:
	rm -rf build *.o *.a *.so* *.dylib*

# Convenience targets
debug:
	$(MAKE) BUILD=debug all

release:
	$(MAKE) BUILD=release all
