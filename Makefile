CC=gcc
SRC=richie_rich.c
BIN=richie_rich

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

.PHONY: all

all: $(BIN)

$(BIN): $(SRC)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	-rm $(BIN)
	-rm $(BIN).exe
