CC      ?= gcc
CFLAGS  += -Wall -Wextra -O2
CFLAGS  += $(shell pkg-config --cflags libngtcp2 libngtcp2_crypto_wolfssl wolfssl)
CFLAGS  += -DWOLFSSL_USE_OPTIONS_H
LDFLAGS += $(shell pkg-config --libs libngtcp2 libngtcp2_crypto_wolfssl wolfssl)

all: quic_server quic_client

quic_server: server.c quic_common.h
	$(CC) $(CFLAGS) -o $@ server.c $(LDFLAGS)

quic_client: client.c quic_common.h
	$(CC) $(CFLAGS) -o $@ client.c $(LDFLAGS)

clean:
	rm -f quic_server quic_client

.PHONY: all clean
