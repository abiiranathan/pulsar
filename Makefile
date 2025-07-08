# Detect platform
UNAME := $(shell uname -s)
ARCH := $(shell uname -m)

# Build mode: release (default) or debug
BUILD ?= release

# Compiler
CC := gcc

# Base compiler flags
BASE_CFLAGS := -Wall -Werror -Wextra -pedantic -std=c23 -D_GNU_SOURCE -fPIC

# Mode-specific flags and directories
ifeq ($(BUILD),debug)
    CFLAGS := $(BASE_CFLAGS) -O0 -g3 -DDEBUG -fsanitize=address -fsanitize=undefined -fanalyzer
    BUILD_DIR := build/debug
else ifeq ($(BUILD),release)
    CFLAGS := $(BASE_CFLAGS) -O3 -DNDEBUG -flto -mavx2 -mtune=native -march=native
    BUILD_DIR := build/release
else
    $(error Invalid BUILD type: $(BUILD))
endif

# Linker flags
LDFLAGS := -lpthread

# Installation path
INSTALL_PREFIX := /usr/local

# Platform-specific adjustments
ifeq ($(UNAME), Darwin)
    CFLAGS += -arch x86_64 -arch arm64
    LIBEXT := dylib
    SONAME_FLAG := -install_name
    SHARED_FLAG := -dynamiclib
else ifeq ($(UNAME), Linux)
    LIBEXT := so
    SONAME_FLAG := -soname
    SHARED_FLAG := -shared
else
    $(error Unsupported platform: $(UNAME))
endif

# Targets
TARGET := $(BUILD_DIR)/server
TEST_TARGET := $(BUILD_DIR)/forms_test

# Source and header directories
SRC_DIR := src
HEADERS_DIR := include

# Source files
BASE_SRC := $(SRC_DIR)/routing.c $(SRC_DIR)/hashmap.c $(SRC_DIR)/method.c $(SRC_DIR)/pulsar.c $(SRC_DIR)/forms.c
TEST_SRCS := $(SRC_DIR)/forms_test.c $(SRC_DIR)/forms.c
HEADERS := $(wildcard $(HEADERS_DIR)/*.h)

# Object files (placed in build dir)
LIB_OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(BASE_SRC))

# Library names
STATIC_LIB := $(BUILD_DIR)/libpulsar.a
SHARED_LIB := $(BUILD_DIR)/libpulsar.$(LIBEXT)
LIB_VERSION := 1.0.0
SONAME := libpulsar.$(LIBEXT).1

# Default target
all: $(TARGET)

# Build the main application
MAIN_SRC := main.c
$(TARGET): $(MAIN_SRC) $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(MAIN_SRC) $(LIB_OBJS) -o $@ $(LDFLAGS)

# Build the test application
$(TEST_TARGET): $(HEADERS) $(TEST_SRCS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Run tests
test: $(TEST_TARGET)
	./$<

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
	ln -sf $@.$(LIB_VERSION) $@
	ln -sf $@.$(LIB_VERSION) $(BUILD_DIR)/$(SONAME)

# Object file rule
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(HEADERS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Build both static and shared libraries
lib: static shared

# Install binaries, libraries, and headers
install: lib
	# Install static lib
	install -d $(INSTALL_PREFIX)/lib
	install -m 644 $(STATIC_LIB) $(INSTALL_PREFIX)/lib/

	# Install shared lib
	install -m 755 $(SHARED_LIB).$(LIB_VERSION) $(INSTALL_PREFIX)/lib/
	ln -sf $(SHARED_LIB).$(LIB_VERSION) $(INSTALL_PREFIX)/lib/libpulsar.$(LIBEXT)
	ln -sf $(SHARED_LIB).$(LIB_VERSION) $(INSTALL_PREFIX)/lib/$(SONAME)

	# Install headers
	install -d $(INSTALL_PREFIX)/include/pulsar
	install -m 644 $(HEADERS) $(INSTALL_PREFIX)/include/pulsar/

	# Update linker cache (Linux only)
ifeq ($(UNAME), Linux)
	ldconfig
endif

# Verify built library
verify:
ifeq ($(UNAME), Darwin)
	@echo "Verifying universal binary..."
	@lipo -archs $(SHARED_LIB).$(LIB_VERSION)
else
	@echo "Verifying shared library..."
	@file $(SHARED_LIB).$(LIB_VERSION)
endif

# Python package preparation
pyupdate: lib
	mkdir -p python/pulsar/lib
	cp -fP $(SHARED_LIB)* python/pulsar/lib
ifeq ($(UNAME), Darwin)
	cp -fP $(STATIC_LIB) python/pulsar/lib
endif

# Clean build artifacts
clean:
	rm -rf build *.o *.a *.so* *.dylib* $(TARGET) $(TEST_TARGET)

# Explicit targets for debug and release
debug:
	$(MAKE) BUILD=debug all

release:
	$(MAKE) BUILD=release all

.PHONY: all test static shared lib install verify pyupdate clean debug release
