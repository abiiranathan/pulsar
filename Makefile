# $^: expands to all prerequisites
# $@: expands to the target name
# $<: first prerequisite

# Detect platform
UNAME := $(shell uname -s)
ARCH := $(shell uname -m)

# Compiler and Flags
CC := clang
CFLAGS := -Wall -Werror -Wextra -pedantic -O3 -mavx2 -flto -std=c23 -fno-builtin -mtune=native -D_GNU_SOURCE
LDFLAGS := -lpthread -lxxhash
INSTALL_PREFIX := /usr/local

# Platform-specific adjustments
ifeq ($(UNAME), Darwin)
    # Universal binary flags for macOS (Intel + ARM)
    CFLAGS += -arch x86_64 -arch arm64
    LIBEXT := dylib
    SONAME_FLAG := -install_name
    SHARED_FLAG := -dynamiclib
else ifeq ($(UNAME), Linux)
    CFLAGS += -mtune=native -march=native
    LIBEXT := so
    SONAME_FLAG := -soname
    SHARED_FLAG := -shared
else
    $(error Unsupported platform: $(UNAME))
endif

# Target Executables
TARGET := server
TEST_TARGET := forms_test

# Source Files
SRC_DIR := src
BASE_SRC := $(SRC_DIR)/routing.c $(SRC_DIR)/method.c $(SRC_DIR)/pulsar.c $(SRC_DIR)/forms.c
HEADERS_DIR := include
HEADERS := $(wildcard $(HEADERS_DIR)/*.h)

SRC := main.c $(BASE_SRC)
TEST_SRCS := $(SRC_DIR)/forms_test.c $(SRC_DIR)/forms.c
LIB_SRCS := $(BASE_SRC)

# Library names
STATIC_LIB := libpulsar.a
SHARED_LIB := libpulsar.$(LIBEXT)
LIB_VERSION := 1.0.0
SONAME := $(SHARED_LIB).1

# Object files
LIB_OBJS := $(patsubst $(SRC_DIR)/%.c,%.o,$(LIB_SRCS))

# Default target
all: $(TARGET)

# Main application build rule
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Test binary build rule
$(TEST_TARGET): $(HEADERS) $(TEST_SRCS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Run tests
test: $(TEST_TARGET)
	./$<

# Build static library
static: $(STATIC_LIB)

$(STATIC_LIB): $(LIB_OBJS)
	ar rcs $@ $^
	ranlib $@

# Build shared library
shared: $(SHARED_LIB)

$(SHARED_LIB): $(LIB_OBJS)
	$(CC) $(SHARED_FLAG) -Wl,$(SONAME_FLAG),$(SONAME) -o $@.$(LIB_VERSION) $^ $(LDFLAGS)
	ln -sf $@.$(LIB_VERSION) $@
	ln -sf $@.$(LIB_VERSION) $(SONAME)

# Pattern rule for object files
%.o: $(SRC_DIR)/%.c $(HEADERS)
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

# Build both libraries
lib: static shared

install: lib
	# Install static library
	install -d $(INSTALL_PREFIX)/lib
	install -m 644 $(STATIC_LIB) $(INSTALL_PREFIX)/lib/
	
	# Install shared library
	install -m 755 $(SHARED_LIB).$(LIB_VERSION) $(INSTALL_PREFIX)/lib/
	ln -sf $(SHARED_LIB).$(LIB_VERSION) $(INSTALL_PREFIX)/lib/$(SHARED_LIB)
	ln -sf $(SHARED_LIB).$(LIB_VERSION) $(INSTALL_PREFIX)/lib/$(SONAME)
	
	# Install headers
	install -d $(INSTALL_PREFIX)/include/pulsar
	install -m 644 $(HEADERS) $(INSTALL_PREFIX)/include/pulsar/
	
	# Update linker cache (Linux only)
ifeq ($(UNAME), Linux)
	ldconfig
endif

# Platform-specific verification
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
	cp -f $(SHARED_LIB)* python/pulsar/lib
ifeq ($(UNAME), Darwin)
	cp -f $(STATIC_LIB) python/pulsar/lib
endif

# Clean up build artifacts
clean:
	rm -f $(TARGET) $(TEST_TARGET) $(STATIC_LIB) $(SHARED_LIB)* $(SONAME) *.o perf.data*

.PHONY: all test static shared lib install verify pyupdate clean
