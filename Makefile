# this Makefile can handle on X86_64 and AArch64

ARCH := $(shell uname -m)	# get architechure
ifeq ($(ARCH), x86_64)	# if architechure is x86_64
	CC = aarch64-linux-gnu-gcc
	LD = aarch64-linux-gnu-ld
	AS = aarch64-linux-gnu-as
else ifeq ($(ARCH), aarch64)	# if architechure is AArch64
	CC = gcc
	LD = ld
	AS = as
else	# otherwise
	$(error unsupported architechture: $(ARCH))
endif

TARGET := out/privacy_router

SRC_DIR := src
ASM_DIR := asm
INC_DIR := include
OUT_DIR := out

CFLAGS := -Wall -Wextra -Werror -I$(INC_DIR) -O3 -fno-pie
ASFLAGS :=

C_SRCS := $(wildcard $(SRC_DIR)/*.c)	# find all .c in SRC_DIR
ASM_SRCS := $(wildcard $(ASM_DIR)/*.S)	# find all .S in ASM_DIR

C_OBJS := $(patsubst $(SRC_DIR)/%.c, $(OUT_DIR)/%.o, $(C_SRCS))	# keep name in .c to .o e.g. src/main.c -> out/main.o
ASM_OBJS := $(patsubst $(ASM_DIR)/%.S, $(OUT_DIR)/%.o, $(ASM_SRCS))	# keep name in .S to .o e.g. asm/main.S -> out/main.o

OBJS := $(C_OBJS) $(ASM_OBJS)

# finding library path
CRT1 := $(shell $(CC) -print-file-name=crt1.o)
CRTI := $(shell $(CC) -print-file-name=crti.o)
CRTN := $(shell $(CC) -print-file-name=crtn.o)
CRTBEGIN := $(shell $(CC) -print-file-name=crtbegin.o)
CRTEND := $(shell $(CC) -print-file-name=crtend.o)
LIBGCC := $(shell $(CC) -print-libgcc-file-name)

DYNAMIC_LINKER := /lib/ld-linux-aarch64.so.1

.PHONY: all compile run clean test

all: compile

compile: $(TARGET)

$(TARGET): $(OBJS)
	$(LD) \
		-dynamic_linker $(DYNAMIC_LINKER) \
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

test: