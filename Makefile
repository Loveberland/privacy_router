CC := gcc
TARGET := out/privacy_router

SRC_DIR := src
ASM_DIR := asm
INC_DIR := include
OUT_DIR := out

CFLAGS := -Wall -Wextra -Werror -I$(INC_DIR) -O3
LDFLAGS := 

C_SRCS := $(wildcard $(SRC_DIR)/*.c)
ARM_SRCS := $(wildcard $(ASM_DIR)/*.S)

C_OBJS := $(patsubst $(SRC_DIR)/%.c, $(OUT_DIR)/%.o, $(C_SRCS))
ASM_OBJS := $(patsubst $(ASM_DIR)/%.S, $(OUT_DIR)/%.o, $(ASM_SRCS))

OBJS := $(C_OBJS) $(ASM_OBJS)

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

$(OUT_DIR)/%.o: $(SRC_DIR)/%.c | $(OUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT_DIR)/%.o: $(ASM_DIR)/%.S | $(OUT_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

run: $(TARGET)
	sudo ./$(TARGET)

clean:
	rm -rf $(OUT_DIR)
