CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra
LDFLAGS ?=

TARGET := rv64emu2

.PHONY: all run clean

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) main.c -o $@ $(LDFLAGS)

# Boot the parent kernel.elf with sane defaults.
run: $(TARGET)
	./$(TARGET) -i ../kernel.elf

clean:
	rm -f $(TARGET)
