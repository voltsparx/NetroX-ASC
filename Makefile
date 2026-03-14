NASM ?= nasm
LD ?= ld

BUILD_DIR := build/linux
SRC_DIR := src/linux

LINUX_OBJS := $(BUILD_DIR)/main.o

.PHONY: all linux clean

all: linux

linux: $(LINUX_OBJS)
	$(LD) -o netx-asm-linux $(LINUX_OBJS)

$(BUILD_DIR)/main.o: $(SRC_DIR)/main.asm src/common/constants.inc src/common/parse.inc src/common/checksum.inc
	@mkdir -p $(BUILD_DIR)
	$(NASM) -f elf64 -D LINUX $< -o $@

clean:
	rm -rf build netx-asm-linux