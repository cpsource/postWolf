# socket-level-wrapper Makefile
#
# Builds libslc.a and example echo client/server.
# Requires wolfssl-new built in the parent directory.

WOLFSSL_DIR = ..
WOLFSSL_INC = $(WOLFSSL_DIR)
WOLFSSL_LIB = $(WOLFSSL_DIR)/src/.libs

CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2
CFLAGS  += -I$(WOLFSSL_INC)
LDFLAGS += -L$(WOLFSSL_LIB) -lwolfssl -lm -lpthread

AR      ?= ar

LIB     = libslc.a
TARGETS = $(LIB) examples/echo_server examples/echo_client

all: $(TARGETS)

$(LIB): slc.o
	$(AR) rcs $@ $<

slc.o: slc.c slc.h
	$(CC) $(CFLAGS) -c -o $@ slc.c

examples/echo_server: examples/echo_server.c $(LIB) slc.h
	$(CC) $(CFLAGS) -I. -o $@ $< -L. -lslc $(LDFLAGS)

examples/echo_client: examples/echo_client.c $(LIB) slc.h
	$(CC) $(CFLAGS) -I. -o $@ $< -L. -lslc $(LDFLAGS)

clean:
	rm -f slc.o $(LIB) examples/echo_server examples/echo_client

.PHONY: all clean
