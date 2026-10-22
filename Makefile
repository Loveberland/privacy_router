.DEFAULT_GOAL := all
.DELETE_ON_ERROR:

BUILD_GOALS := $(if $(MAKECMDGOALS),$(filter-out clean flex,$(MAKECMDGOALS)),all)

# linux-only check
ifneq ($(strip $(BUILD_GOALS)), )
	ifneq ($(shell uname -s), Linux)
		$(error This project requires Linux)
	endif
endif

# compiler and Flags
CC := gcc
CPPFLAGS += -Iinclude
CFLAGS ?= -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Wpedantic -Werror -O2
ASFLAGS ?=
LDFLAGS ?=
LDLIBS ?=

OUT_DIR ?= out
RUNNER ?=
TARGET := $(OUT_DIR)/privacy_router

# compile target
C_SRCS := $(wildcard src/*.c)
COMPILER_TARGET := $(shell $(CC) -dumpmachine)
ASM_SRCS := $(if $(filter aarch64%,$(COMPILER_TARGET)),$(wildcard asm/*.S))
TEST_SRCS := $(wildcard test/t_*.c)
TEST_ASM_SRCS := $(if $(filter aarch64%,$(COMPILER_TARGET)),$(wildcard test/*.S))

# mapping source files to outputs
C_OBJS := $(patsubst src/%.c,$(OUT_DIR)/src/%.o,$(C_SRCS))
ASM_OBJS := $(patsubst asm/%.S,$(OUT_DIR)/asm/%.o,$(ASM_SRCS))
TEST_OBJS := $(patsubst test/%.c,$(OUT_DIR)/test/%.o,$(TEST_SRCS))
TEST_ASM_OBJS := $(patsubst test/%.S,$(OUT_DIR)/test/%.o,$(TEST_ASM_SRCS))
TEST_BINS := $(patsubst test/%.c,$(OUT_DIR)/test/%,$(TEST_SRCS))

OBJS := $(C_OBJS) $(ASM_OBJS)	# combine object files without test files
TEST_PROJECT_OBJS := $(filter-out $(OUT_DIR)/src/main.o,$(OBJS))	# project objects linked into tests (all except main.o)
DEPS := $(OBJS:.o=.d) $(TEST_OBJS:.o=.d) $(TEST_ASM_OBJS:.o=.d)

.PHONY: all compile run clean test sanitize flex	# all targets
.SECONDARY: $(TEST_OBJS)

all: compile

compile: $(TARGET)

# link object files to binary
$(TARGET): $(OBJS) Makefile
	$(CC) $(LDFLAGS) -pthread -o $@ $(OBJS) $(LDLIBS)

# compile source to object files
$(OUT_DIR)/src/%.o: src/%.c Makefile
	mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -pthread -MMD -MP -c $< -o $@
$(OUT_DIR)/asm/%.o: asm/%.S Makefile
	mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -MMD -MP -c $< -o $@

# compile test source to object files
$(OUT_DIR)/test/%.o: test/%.c Makefile
	mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(CFLAGS) -pthread -MMD -MP -c $< -o $@
$(OUT_DIR)/test/%.o: test/%.S Makefile
	mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(ASFLAGS) -MMD -MP -c $< -o $@

# link test object to binary files
$(OUT_DIR)/test/%: $(OUT_DIR)/test/%.o $(TEST_PROJECT_OBJS) $(TEST_ASM_OBJS) Makefile
	$(CC) $(LDFLAGS) -pthread -o $@ $< $(filter-out $(OUT_DIR)/src/$(patsubst t_%,%,$*).o,$(TEST_PROJECT_OBJS)) $(TEST_ASM_OBJS) $(LDLIBS)

# run main program
run: compile
	sudo $(TARGET)

# run test programs
test: $(TEST_BINS)
	@set -e; \
	for test_bin in $(TEST_BINS); do \
		printf '==> Running %s\n' "$$test_bin"; \
		$(RUNNER) "$$test_bin"; \
	done

# rebuild into out/sanitize with ASan/UBSan and run tests
sanitize:
	$(MAKE) compile test OUT_DIR=$(OUT_DIR)/sanitize CC='$(CC)' RUNNER='$(RUNNER)' \
		CFLAGS='-std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Wpedantic -Werror -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined' \
		LDFLAGS='-fsanitize=address,undefined'

# delete whole outputs
clean:
	rm -rf -- $(OUT_DIR)

# count line in each files
flex:
	git ls-files -z | xargs -0 wc -l

-include $(DEPS)
