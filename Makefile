# native Linux-AArch64

.DEFAULT_GOAL := all
.DELETE_ON_ERROR:

BUILD_GOALS := $(if $(MAKECMDGOALS),$(filter-out clean flex,$(MAKECMDGOALS)),all)

ifneq ($(strip $(BUILD_GOALS)),)
  ifneq ($(shell uname -s),Linux)
    $(error This project requires Linux)
  endif
endif

CC := gcc
CPPFLAGS += -Iinclude
CFLAGS ?= -Wall -Wextra -Werror -O3
ASFLAGS ?=
LDFLAGS ?=
LDLIBS ?=

OUT_DIR := out
TARGET := $(OUT_DIR)/privacy_router

C_SRCS := $(wildcard src/*.c)
ASM_SRCS := $(wildcard asm/*.S)
TEST_SRCS := $(wildcard test/t_*.c)

C_OBJS := $(patsubst src/%.c,$(OUT_DIR)/src/%.o,$(C_SRCS))
ASM_OBJS := $(patsubst asm/%.S,$(OUT_DIR)/asm/%.o,$(ASM_SRCS))
TEST_OBJS := $(patsubst test/%.c,$(OUT_DIR)/test/%.o,$(TEST_SRCS))
TEST_BINS := $(patsubst test/%.c,$(OUT_DIR)/test/%,$(TEST_SRCS))

OBJS := $(C_OBJS) $(ASM_OBJS)
TEST_PROJECT_OBJS := $(filter-out $(OUT_DIR)/src/main.o,$(OBJS))
DEPS := $(OBJS:.o=.d) $(TEST_OBJS:.o=.d)

.PHONY: all compile run clean test flex
.SECONDARY: $(TEST_OBJS)

all: compile

compile: $(TARGET)

$(TARGET): $(OBJS) Makefile
	$(CC) $(LDFLAGS) -pthread -o $@ $(OBJS) $(LDLIBS)

$(OUT_DIR)/src/%.o: src/%.c Makefile
	mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -pthread -MMD -MP -c $< -o $@

$(OUT_DIR)/asm/%.o: asm/%.S Makefile
	mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -MMD -MP -c $< -o $@

$(OUT_DIR)/test/%.o: test/%.c Makefile
	mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -pthread -MMD -MP -c $< -o $@

$(OUT_DIR)/test/%: $(OUT_DIR)/test/%.o $(TEST_PROJECT_OBJS) Makefile
	$(CC) $(LDFLAGS) -pthread -o $@ $< $(TEST_PROJECT_OBJS) $(LDLIBS)

run: compile
	sudo ./$(TARGET)

test: $(TEST_BINS)
	@set -e; \
	for test_bin in $(TEST_BINS); do \
		printf '==> Running %s\n' "$$test_bin"; \
		./"$$test_bin"; \
	done

clean:
	rm -rf -- $(OUT_DIR)

flex:
	git ls-files -z | xargs -0 wc -l

-include $(DEPS)
