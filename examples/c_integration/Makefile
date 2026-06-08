# A2G C Integration Example — Makefile
#
# Variables (override on the command line):
#
#   A2G_LIB_DIR   Path to the directory containing liba2g_ffi.a (or .so).
#                 Default: ../../target/release   (after `cargo build --release`)
#
#   A2G_INCLUDE   Path to the directory containing a2g.h / a2g_integration.h.
#                 Default: ../../crates/a2g-ffi/include
#
#   CC            C compiler.  Default: cc
#   CFLAGS        Extra compiler flags.
#
# Usage:
#   make                                       # host build, default lib path
#   make A2G_LIB_DIR=/path/to/release          # custom lib path
#   make CC=aarch64-linux-gnu-gcc \
#        A2G_LIB_DIR=/path/to/aarch64/release  # aarch64 cross-compile
#   make clean

A2G_LIB_DIR ?= ../../target/release
A2G_INCLUDE  ?= ../../crates/a2g-ffi/include

CC      ?= cc
CFLAGS  += -Wall -Wextra -std=c99 -I$(A2G_INCLUDE)
TARGET  := a2g_integration

# Link the static archive explicitly by path so the linker cannot fall back to
# liba2g_ffi.so when both are present in A2G_LIB_DIR.  This matches the
# expected deployment model on ECU targets where a shared Rust runtime is not
# available.
LDFLAGS :=
LDLIBS  := $(A2G_LIB_DIR)/liba2g_ffi.a -lpthread -ldl -lm

.PHONY: all clean

all: $(TARGET)

$(TARGET): main.c $(A2G_INCLUDE)/a2g.h $(A2G_INCLUDE)/a2g_integration.h
	$(CC) $(CFLAGS) -o $@ main.c $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET)
