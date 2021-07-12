CC=gcc

SRC=richie_rich.c pe.c rich.c util.c

VPATH=src
INCLUDE=include
BUILD=build

BIN=$(SRC:%.c=$(BUILD)/%.o)
CFLAGS=-I$(INCLUDE) -O2 -Wall -Wextra -pedantic -Wshadow -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes -Wdeclaration-after-statement

PROG=richie_rich

# Edit this value accordingly
MINGWCC=x86_64-w64-mingw32-gcc

# Building in Windows
ifeq ($(OS),Windows_NT)
	CFLAGS+=-D_WINDOWS
# Cross Compling for Windows with mingw
else ifeq ($(cc-win),true)
	CFLAGS+=-D_WINDOWS
	CC=x86_64-w64-mingw32-gcc
# Linux/BSD/Darwin
else
	CFLAGS+=-D_UNIX
endif

ifeq ($(debug),true)
	CFLAGS+=-DDEBUG_BUILD
endif

.PHONY: all clean

all: $(PROG)

$(BIN): $(BUILD)/%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@

$(PROG): $(BIN)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	-rm $(PROG)
	-rm $(PROG).exe
	-rm $(BIN)
