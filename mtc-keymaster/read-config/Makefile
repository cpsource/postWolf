CC      = gcc
CFLAGS  = -Wall -Wextra -O2 $(shell pkg-config --cflags augeas)
LDLIBS  = $(shell pkg-config --libs augeas)

BIN     = read-config-test
SRC     = read-config.c

.PHONY: all test clean

all: $(BIN)

$(BIN): $(SRC) read-config.h
	$(CC) -DTEST_MAIN $(CFLAGS) -o $@ $(SRC) $(LDLIBS)

test: $(BIN)
	./$(BIN)

clean:
	rm -f $(BIN) *.o
