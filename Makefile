PTRACE_DIR ?= ../lib-ps-ptrace

ifneq ($(MAKECMDGOALS),kernel)
    ifdef PS4_PAYLOAD_SDK
        include $(PS4_PAYLOAD_SDK)/toolchain/orbis.mk
    else
        $(error PS4_PAYLOAD_SDK is undefined)
    endif

    ifeq ($(wildcard $(PTRACE_DIR)/include/ptrace.h),)
        $(error $(PTRACE_DIR)/include/ptrace.h not found; set PTRACE_DIR to a lib-ps-ptrace checkout)
    endif
endif

OBJCOPY ?= objcopy
.DEFAULT_GOAL := all
BUILD ?= build
OBJ := $(BUILD)/obj/kstuff
LIB := $(BUILD)/lib/libkstuff.a
KERNEL_ELF := $(BUILD)/bin/kstuff-kernel.elf
KERNEL_BIN := $(BUILD)/bin/kstuff-kernel.bin
GEN := $(BUILD)/generated/kstuff_kernel.h
INCFLAGS := -Iheaders -I$(PTRACE_DIR)/include
BASEFLAGS := -fPIC -Oz $(if $(DEBUG),-g) -Wall -Werror -mstackrealign -ffunction-sections -fdata-sections $(INCFLAGS) -MMD -MP
CFLAGS := $(BASEFLAGS) -std=gnu11
CXXFLAGS := $(BASEFLAGS) -std=c++2b -fno-exceptions -fno-rtti -fno-threadsafe-statics
SOURCES := $(wildcard source/*.c source/*.cpp)
OBJECTS := $(SOURCES:%=$(OBJ)/%.o)
KERNELOBJ := $(patsubst kernel/%.c,$(OBJ)/kernel/%.o,$(wildcard kernel/*.c))
KERNEL_CC ?= gcc
KERNEL_CFLAGS := -Os -std=gnu11 -fpie -fno-builtin -fno-stack-protector -fcf-protection=none -fno-asynchronous-unwind-tables -fno-unwind-tables -fno-omit-frame-pointer -mno-red-zone -mno-sse -mno-mmx -msoft-float -masm=intel -march=btver2 -m64 -Wall -Werror -Wno-frame-address -Ikernel -Iheaders -Iinclude -MMD -MP
.PHONY: all kernel clean master
all: $(LIB)
kernel: $(KERNEL_BIN)
$(OBJ)/kernel/%.o: kernel/%.c Makefile
	@mkdir -p $(dir $@)
	$(KERNEL_CC) $(KERNEL_CFLAGS) -c $< -o $@
$(KERNEL_ELF): $(KERNELOBJ) kernel/linker.x
	@mkdir -p $(dir $@)
	$(KERNEL_CC) -nostdlib -nostartfiles -no-pie -Wl,--build-id=none,-T,kernel/linker.x $(KERNELOBJ) -o $@
$(KERNEL_BIN): $(KERNEL_ELF)
	$(OBJCOPY) -O binary --only-section=.payload $< $@
$(GEN): $(KERNEL_BIN)
	@mkdir -p $(dir $@)
	xxd -i -n kstuff_kernel $< > $@
$(OBJ)/source/kpayload.cpp.o: $(GEN)
$(OBJ)/source/kernel_exec.c.o: CFLAGS += -mno-red-zone -mno-sse -mno-mmx -fno-stack-protector -fno-builtin
$(OBJ)/%.c.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@
$(OBJ)/%.cpp.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -I$(BUILD)/generated -c $< -o $@
$(LIB): $(OBJECTS)
	@mkdir -p $(dir $@)
	rm -f $@
	$(AR) rcs $@ $^
-include $(OBJECTS:.o=.d) $(KERNELOBJ:.o=.d)
clean:
	rm -rf $(OBJ) $(LIB) $(KERNEL_ELF) $(KERNEL_BIN) $(GEN)
master:
	@$(MAKE) clean
	@$(MAKE) all
