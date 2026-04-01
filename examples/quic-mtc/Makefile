CC      ?= gcc
WOLFSSL_ROOT ?= ../..

CFLAGS  += -Wall -Wextra -O2
CFLAGS  += $(shell pkg-config --cflags libngtcp2 libngtcp2_crypto_wolfssl wolfssl)
CFLAGS  += -DWOLFSSL_USE_OPTIONS_H -DHAVE_MTC -DHAVE_MTC_API
CFLAGS  += -I$(WOLFSSL_ROOT)

LDFLAGS += $(shell pkg-config --libs libngtcp2 libngtcp2_crypto_wolfssl wolfssl)
LDFLAGS += -ljson-c -lcurl

# The MTC C API is compiled from source (not in libwolfssl)
MTC_SRC = $(WOLFSSL_ROOT)/src/ssl_mtc_standalone.c

all: quic_mtc_server quic_mtc_client

quic_mtc_server: server.c quic_mtc_common.h $(MTC_SRC)
	$(CC) $(CFLAGS) -o $@ server.c $(MTC_SRC) $(LDFLAGS)

quic_mtc_client: client.c quic_mtc_common.h $(MTC_SRC)
	$(CC) $(CFLAGS) -o $@ client.c $(MTC_SRC) $(LDFLAGS)

clean:
	rm -f quic_mtc_server quic_mtc_client

.PHONY: all clean
