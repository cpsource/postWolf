CC      ?= gcc
CFLAGS  += -Wall -Wextra -O2
CFLAGS  += $(shell pkg-config --cflags wolfssl) -DWOLFSSL_USE_OPTIONS_H
CFLAGS  += $(shell pkg-config --cflags json-c)
LDFLAGS += $(shell pkg-config --libs wolfssl)
LDFLAGS += $(shell pkg-config --libs json-c)

all: mtc_server

mtc_server: mtc_server.c mtc_merkle.c mtc_merkle.h mtc_store.c mtc_store.h mtc_http.c mtc_http.h
	$(CC) $(CFLAGS) -o $@ mtc_server.c mtc_merkle.c mtc_store.c mtc_http.c $(LDFLAGS)

clean:
	rm -f mtc_server

.PHONY: all clean
