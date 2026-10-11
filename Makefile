# Make drives CMake; compiler and linker settings live in CMakeLists.txt.
.DEFAULT_GOAL := all

CMAKE ?= cmake
BUILD_DIR ?= build
BUILD ?= release
INSTALL_PREFIX ?= /usr/local

ifeq ($(BUILD),debug)
CMAKE_BUILD_TYPE := Debug
else ifeq ($(BUILD),release)
CMAKE_BUILD_TYPE := Release
else
$(error Invalid BUILD type: $(BUILD). Use 'debug' or 'release')
endif

CMAKE_CONFIGURE_ARGS = -DCMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE) \
	-DCMAKE_INSTALL_PREFIX=$(INSTALL_PREFIX)

.PHONY: configure all test static shared lib install clean clean-objs debug release check

configure:
	$(CMAKE) -S . -B $(BUILD_DIR) $(CMAKE_CONFIGURE_ARGS)

all: configure
	$(CMAKE) --build $(BUILD_DIR) --parallel

test: all
	ctest --test-dir $(BUILD_DIR) --output-on-failure

static: configure
	$(CMAKE) --build $(BUILD_DIR) --target pulsar_static --parallel

shared: configure
	$(CMAKE) --build $(BUILD_DIR) --target pulsar_shared --parallel

lib: configure
	$(CMAKE) --build $(BUILD_DIR) --target pulsar_static pulsar_shared --parallel

# Build as the current user first; this target only installs existing outputs.
install:
	$(CMAKE) --install $(BUILD_DIR) --prefix $(INSTALL_PREFIX)

clean:
	$(CMAKE) --build $(BUILD_DIR) --target clean

clean-objs: clean

debug:
	$(MAKE) BUILD=debug all

release:
	$(MAKE) BUILD=release all

check: all
	valgrind --leak-check=full --show-leak-kinds=all --suppressions=glibc.supp $(BUILD_DIR)/bin/server


