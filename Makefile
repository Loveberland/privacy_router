# this Makefile can handle on X86_64 and AArch64

# get architecture
ARCH := $(shell uname -m)

ifeq ($(ARCH),x86_64)
CC := aarch64-linux-gnu-gcc
LD := aarch64-linux-gnu-ld
AS := aarch64-linux-gnu-as
else ifeq ($(ARCH),aarch64)
CC := gcc
LD := ld
AS := as
else
$(error unsupported architecture: $(ARCH))
endif

TARGET := out/privacy_router

SRC_DIR := src
ASM_DIR := asm
INC_DIR := include
OUT_DIR := out
TEST_DIR := test
TEST_OUT_DIR := $(OUT_DIR)/test

CFLAGS := -Wall -Wextra -Werror -I$(INC_DIR) -O3 -fno-pie
ASFLAGS :=

# find all .c files in src/
C_SRCS := $(wildcard $(SRC_DIR)/*.c)

# find all .S files in asm/
ASM_SRCS := $(wildcard $(ASM_DIR)/*.S)

# src/main.c -> out/main.o
C_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OUT_DIR)/%.o,$(C_SRCS))

# asm/function.S -> out/function.o
ASM_OBJS := $(patsubst $(ASM_DIR)/%.S,$(OUT_DIR)/%.o,$(ASM_SRCS))

OBJS := $(C_OBJS) $(ASM_OBJS)

# find all test files matching test/t_*.c
TEST_SRCS := $(wildcard $(TEST_DIR)/t_*.c)

# test/t_common.c -> out/test/t_common
TEST_BINS := $(patsubst $(TEST_DIR)/%.c,$(TEST_OUT_DIR)/%,$(TEST_SRCS))

# project objects used by tests; exclude main.o because every test has its own main()
TEST_PROJECT_OBJS := $(filter-out $(OUT_DIR)/main.o,$(OBJS))

# find C runtime files
CRT1 := $(shell $(CC) -print-file-name=crt1.o)
CRTI := $(shell $(CC) -print-file-name=crti.o)
CRTN := $(shell $(CC) -print-file-name=crtn.o)
CRTBEGIN := $(shell $(CC) -print-file-name=crtbegin.o)
CRTEND := $(shell $(CC) -print-file-name=crtend.o)

# find GCC runtime library
LIBGCC := $(shell $(CC) -print-libgcc-file-name)

# AArch64 dynamic linker
DYNAMIC_LINKER := /lib/ld-linux-aarch64.so.1

.PHONY: all compile run clean test flex

all: compile

compile: $(TARGET)

$(TARGET): $(OBJS) | $(OUT_DIR)
	$(LD) \
		--dynamic-linker $(DYNAMIC_LINKER) \
		-o $@ \
		$(CRT1) \
		$(CRTI) \
		$(CRTBEGIN) \
		$(OBJS) \
		-lc \
		$(LIBGCC) \
		$(CRTEND) \
		$(CRTN)

$(OUT_DIR)/%.o: $(SRC_DIR)/%.c | $(OUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT_DIR)/%.o: $(ASM_DIR)/%.S | $(OUT_DIR)
	$(AS) $(ASFLAGS) $< -o $@

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

run: compile
	sudo ./$(TARGET)

clean:
	rm -rf $(OUT_DIR)

test: $(TEST_BINS)
	@set -e; \
	for test_bin in $(TEST_BINS); do \
		echo "==> Running $$test_bin"; \
		./$$test_bin; \
	done

$(TEST_OUT_DIR)/%: $(TEST_DIR)/%.c $(TEST_PROJECT_OBJS) | $(TEST_OUT_DIR)
	$(CC) $(CFLAGS) -no-pie $< $(TEST_PROJECT_OBJS) -o $@

$(TEST_OUT_DIR):
	mkdir -p $(TEST_OUT_DIR)

flex:
	git ls-files | xargs wc -l