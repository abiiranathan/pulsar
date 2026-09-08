# === Configuration ===

# Compiler
CC ?= gcc

# Installation prefix
INSTALL_PREFIX ?= /usr/local

# Build mode: debug or release
BUILD ?= release

# PGO Profile Directory
PGO_DIR ?= $(CURDIR)/build/pgo

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

# === Compiler & Linker Flags ===

DEFINES := -DDA_IMPLEMENTATION -D_GNU_SOURCE -DNUM_WORKERS=4
BASE_CFLAGS := -Wall -Werror -Wextra -std=c11 -Iinclude $(DEFINES) \
               -Wno-unused-function -Wno-gnu-zero-variadic-macro-arguments
BASE_LDFLAGS := -pthread -lsolidc -lm

# --- Optional PGO Mode Flags ---
PGO_FLAGS :=
ifeq ($(PGO_MODE), generate)
    PGO_FLAGS := -fprofile-generate=$(PGO_DIR)
else ifeq ($(PGO_MODE), use)
    PGO_FLAGS := -fprofile-use=$(PGO_DIR) -fprofile-correction -Wno-error=coverage-mismatch
endif

ifeq ($(BUILD), debug)
    CFLAGS := $(BASE_CFLAGS) -fPIC -O0 -g3 -DDEBUG
    LDFLAGS := $(BASE_LDFLAGS)
    BUILD_DIR := build/bin

else ifeq ($(BUILD), release)
    # ==============================================================================
	# Architecture & Target Tuning
	# ==============================================================================
	# -march=native enables all instruction sets supported by the host (AVX2, BMI2, etc.)
	# We omit manual -mavx2 because -march=native already enables it optimally.
	ARCH_FLAGS := -march=native -mtune=native

	# ==============================================================================
	# Code Generation & Optimization
	# ==============================================================================
	# 1. -g1 / -gline-tables-only: Injects function & line debug info into non-alloc ELF
	#    sections. 0% runtime overhead, but fixes raw hex addresses in 'perf report'.
	# 2. -fno-omit-frame-pointer: Keeps RBP for zero-overhead call-graph profiling (-g fp).
	#    On x86-64 with 16 GPRs, the throughput difference is < 0.2%.
	# 3. -fvisibility=hidden: Lets LTO devirtualize, inline, and prune symbols aggressively.
	# 4. -fmerge-all-constants: Merges identical strings and constants across compilation units.
	OPT_FLAGS := -O3 -DNDEBUG -DENABLE_LOGGING=0 \
				-g1 \
				-fno-omit-frame-pointer \
				-mno-omit-leaf-frame-pointer \
				-fno-stack-protector \
				-fno-math-errno \
				-fno-trapping-math \
				-fstrict-aliasing \
				-fvisibility=hidden \
				-fmerge-all-constants \
				-ffunction-sections \
				-fdata-sections

	# ==============================================================================
	# Cache Line Alignment (x86-64 uses 64-byte cache lines)
	# ==============================================================================
	# Align function entries to 64 bytes (the hardware L1i cache line size).
	# Align loops to 32 bytes with up to 16 bytes of padding to avoid fetch-block splits.
	ALIGN_FLAGS := -falign-functions=64 \
				-falign-loops=32:24:8 \
				-falign-jumps=32:16:8 \
				-falign-labels=32:16:8

	# ==============================================================================
	# Binary Model (PIE vs PIC)
	# ==============================================================================
	# CRITICAL FIX: -fPIC is for shared libraries (.so) and forces all global variable
	# accesses through the GOT. For an executable binary, use -fPIE / -pie (or -fno-pie)
	# so the compiler can use direct RIP-relative displacement addressing.
	ifeq ($(UNAME), Linux)
		BIN_FLAGS      := -fPIE
		INTERPOS_FLAGS := -fno-semantic-interposition -fno-plt
	else
		BIN_FLAGS      := -fPIE
		INTERPOS_FLAGS :=
	endif

	# ==============================================================================
	# Link-Time Optimization (LTO)
	# ==============================================================================
	LTO_FLAGS := -flto=auto -fuse-linker-plugin

	# ==============================================================================
	# Final CFLAGS
	# ==============================================================================
	CFLAGS := $(BASE_CFLAGS) $(BIN_FLAGS) $(ARCH_FLAGS) $(OPT_FLAGS) $(ALIGN_FLAGS) \
			$(INTERPOS_FLAGS) $(LTO_FLAGS) $(PGO_FLAGS)

	# ==============================================================================
	# Final LDFLAGS
	# ==============================================================================
	LDFLAGS := $(ARCH_FLAGS) $(LTO_FLAGS) $(PGO_FLAGS) -O3 $(BASE_LDFLAGS)

	ifeq ($(UNAME), Linux)
		# -pie: Pairs with -fPIE for position-independent executable with direct RIP addressing
		# -Wl,-O2: Aggressive linker optimization
		# -Wl,--gc-sections: Removes unused functions and dead data sections
		# -Wl,--as-needed: Avoids linking unneeded dynamic libraries
		# -Wl,-z,now -Wl,-z,relro: Full RELRO binds all relocations at startup (zero runtime resolution)
		LDFLAGS += -pie -Wl,-O2 -Wl,--gc-sections -Wl,--as-needed -Wl,-z,now -Wl,-z,relro
	else ifeq ($(UNAME), Darwin)
		LDFLAGS += -Wl,-dead_strip
	endif

	BUILD_DIR := build/bin
else
    $(error Invalid BUILD type: $(BUILD). Use 'debug' or 'release')
endif

# === Directories and Files ===

SRC_DIR := src
HEADERS_DIR := include
TEST_DIR := tests

BASE_SRC := $(SRC_DIR)/routing.c \
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

TARGET := ./build/bin/server
MAIN_SRC := main.c

.PHONY: all test static shared lib install verify clean clean-objs debug release pgo

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
	valgrind --leak-check=full --show-leak-kinds=all --suppressions=glibc.supp ./build/bin/server

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

verify:
ifeq ($(UNAME), Darwin)
	@echo "Verifying library..."
	@file $(SHARED_LIB).$(LIB_VERSION)
else
	@echo "Verifying shared library..."
	@file $(SHARED_LIB).$(LIB_VERSION)
endif

# Clean only compilation objects (preserves PGO data)
clean-objs:
	rm -f $(LIB_OBJS) $(TARGET) $(STATIC_LIB) $(SHARED_LIB)*

# Full clean
clean:
	rm -rf build *.o *.a *.so* *.dylib*

debug:
	$(MAKE) BUILD=debug all

release:
	$(MAKE) BUILD=release all

# === Profile-Guided Optimization (PGO) Workflow ===
# === Profile-Guided Optimization (PGO) Workflow ===
PGO_PORT ?= 8080

pgo:
	@echo "==> [PGO 1/4] Cleaning previous builds..."
	$(MAKE) clean
	@mkdir -p $(PGO_DIR)
	@echo "==> [PGO 2/4] Compiling with instrumentation..."
	$(MAKE) BUILD=release PGO_MODE=generate all
	@echo "==> [PGO 3/4] Starting server and warming up workload..."
	@$(TARGET) & \
	PID=$$!; \
	TARGET_URL=""; \
	echo "Waiting for server to become ready on port $(PGO_PORT)..."; \
	for i in $$(seq 1 30); do \
		if curl -s -o /dev/null -m 1 http://localhost:$(PGO_PORT)/; then \
			TARGET_URL="http://localhost:$(PGO_PORT)/"; break; \
		elif curl -s -o /dev/null -m 1 http://127.0.0.1:$(PGO_PORT)/; then \
			TARGET_URL="http://127.0.0.1:$(PGO_PORT)/"; break; \
		elif curl -s -o /dev/null -m 1 -g "http://[::1]:$(PGO_PORT)/"; then \
			TARGET_URL="http://[::1]:$(PGO_PORT)/"; break; \
		fi; \
		sleep 0.1; \
	done; \
	if [ -z "$$TARGET_URL" ]; then \
		echo "[-] Error: Server failed to start on port $(PGO_PORT)"; \
		kill -INT $$PID 2>/dev/null || true; \
		exit 1; \
	fi; \
	echo "[+] Server is ready at $$TARGET_URL"; \
	if command -v wrk >/dev/null 2>&1; then \
		echo "Generating profile data with wrk..."; \
		wrk -t 4 -c 64 -d 5s "$$TARGET_URL" || true; \
	else \
		echo "wrk not found, generating profile data with curl loop..."; \
		for i in $$(seq 1 1000); do curl -s "$$TARGET_URL" >/dev/null 2>&1 || true; done; \
	fi; \
	echo "Shutting down instrumented server..."; \
	kill -INT $$PID 2>/dev/null || true; \
	wait $$PID 2>/dev/null || true; \
	sleep 1
	@echo "==> [PGO 4/4] Rebuilding with profile feedback..."
	$(MAKE) BUILD=release PGO_MODE=use clean-objs all
	@echo "==> PGO Optimized build complete: $(TARGET)"
	
