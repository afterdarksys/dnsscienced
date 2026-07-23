# DNSASM - Ultra-Fast DNS Packet Processor
# Makefile for building assembly modules and test clients

# Detect architecture
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
    ARCH ?= x86_64
else ifeq ($(UNAME_M),aarch64)
    ARCH ?= arm64
else ifeq ($(UNAME_M),arm64)
    ARCH ?= arm64
else
    $(error Unsupported architecture: $(UNAME_M))
endif

# Detect OS
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    OS := macos
    ASM_FLAGS := -f macho64 -DMACOS --prefix _
    SHARED_EXT := dylib
    CC := clang
else ifeq ($(UNAME_S),Linux)
    OS := linux
    ASM_FLAGS := -f elf64 -DLINUX
    SHARED_EXT := so
    CC := gcc
else
    $(error Unsupported OS: $(UNAME_S))
endif

# Directories
SRC_DIR := src
BUILD_DIR := build
OBJ_DIR := $(BUILD_DIR)/obj
LIB_DIR := $(BUILD_DIR)/lib
BIN_DIR := $(BUILD_DIR)/bin
INCLUDE_DIR := include

# Tools
NASM := nasm
AS := as
AR := ar
LD := ld

# Flags
CFLAGS := -O3 -Wall -Wextra -I$(INCLUDE_DIR)
LDFLAGS := -L$(LIB_DIR)

# C source files (always included)
C_SRCS := $(wildcard $(SRC_DIR)/*.c)
C_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(C_SRCS))

# Assembly source files (architecture-specific)
# Default to C implementation if assembly not available/desired
USE_ASM ?= 0

ifeq ($(USE_ASM),1)
ifeq ($(ARCH),x86_64)
    # Header parsing is the measured fast path. Keep the more complex name
    # parser on the audited C implementation until it has equivalent fuzzing.
    ASM_SRCS := $(SRC_DIR)/x86_64/header.asm
    ASM_OBJS := $(patsubst $(SRC_DIR)/x86_64/%.asm,$(OBJ_DIR)/%.o,$(ASM_SRCS))
else ifeq ($(ARCH),arm64)
    ASM_SRCS := $(SRC_DIR)/arm64/header.s
    ASM_OBJS := $(patsubst $(SRC_DIR)/arm64/%.s,$(OBJ_DIR)/%.o,$(ASM_SRCS))
endif
    CFLAGS += -DDNSASM_ASM_HEADER
else
    ASM_OBJS :=
endif

# All objects
ALL_OBJS := $(ASM_OBJS) $(C_OBJS)

# Targets
STATIC_LIB := $(LIB_DIR)/libdnsasm.a
SHARED_LIB := $(LIB_DIR)/libdnsasm.$(SHARED_EXT)
CONSOLE := $(BIN_DIR)/dnsasm-console

# Default target
.PHONY: all
all: dirs $(STATIC_LIB) $(CONSOLE)

# Create directories
.PHONY: dirs
dirs:
	@mkdir -p $(OBJ_DIR) $(LIB_DIR) $(BIN_DIR)

# Compile x86_64 assembly
ifeq ($(ARCH),x86_64)
$(OBJ_DIR)/%.o: $(SRC_DIR)/x86_64/%.asm
	@echo "  NASM    $<"
	@$(NASM) $(ASM_FLAGS) -o $@ $<
endif

# Compile ARM64 assembly
ifeq ($(ARCH),arm64)
$(OBJ_DIR)/%.o: $(SRC_DIR)/arm64/%.s
	@echo "  AS      $<"
	@$(AS) -o $@ $<
endif

# Compile C files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(INCLUDE_DIR)/dnsasm.h
	@echo "  CC      $<"
	@$(CC) $(CFLAGS) -c -o $@ $<

# Static library
$(STATIC_LIB): $(ALL_OBJS)
	@echo "  AR      $@"
	@$(AR) rcs $@ $^

# Shared library
$(SHARED_LIB): $(ALL_OBJS)
	@echo "  LD      $@"
ifeq ($(OS),macos)
	@$(CC) -shared -o $@ $^
else
	@$(CC) -shared -o $@ $^ -Wl,-soname,libdnsasm.so
endif

# Console test client
$(CONSOLE): console/main.c $(STATIC_LIB)
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) -o $@ $< -L$(LIB_DIR) -ldnsasm

# Clean
.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR)

# Run benchmarks
.PHONY: bench
bench: $(CONSOLE)
	@echo "Running benchmarks..."
	@$(CONSOLE) --bench

# Test
.PHONY: test
test: $(CONSOLE)
	@echo "Running tests..."
	@$(CONSOLE) --test

# Install
.PHONY: install
install: $(STATIC_LIB) $(SHARED_LIB)
	@echo "Installing to /usr/local..."
	@install -d /usr/local/lib /usr/local/include/dnsasm
	@install -m 644 $(STATIC_LIB) /usr/local/lib/
	@install -m 755 $(SHARED_LIB) /usr/local/lib/
	@install -m 644 $(INCLUDE_DIR)/*.h /usr/local/include/dnsasm/

# Help
.PHONY: help
help:
	@echo "DNSASM Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build static library and console (default)"
	@echo "  clean    - Remove build artifacts"
	@echo "  test     - Run tests"
	@echo "  bench    - Run benchmarks"
	@echo "  install  - Install to /usr/local"
	@echo ""
	@echo "Variables:"
	@echo "  ARCH     - Target architecture (x86_64, arm64)"
	@echo "             Current: $(ARCH)"
	@echo "  USE_ASM  - Use assembly (1) or C fallback (0)"
	@echo "             Current: $(USE_ASM)"
	@echo ""
	@echo "Detected:"
	@echo "  Architecture: $(UNAME_M) -> $(ARCH)"
	@echo "  OS: $(UNAME_S) -> $(OS)"
	@echo ""
	@echo "Examples:"
	@echo "  make                  # Build with C implementation"
	@echo "  make USE_ASM=1        # Build with assembly optimizations"
	@echo "  make bench            # Run performance benchmarks"
