CC      ?= gcc
CFLAGS  += -Wall -Wextra -O2
CFLAGS  += $(shell pkg-config --cflags wolfssl) -DWOLFSSL_USE_OPTIONS_H
CFLAGS  += $(shell pkg-config --cflags json-c)
CFLAGS  += $(shell pkg-config --cflags libpq)
LDFLAGS += $(shell pkg-config --libs wolfssl)
LDFLAGS += $(shell pkg-config --libs json-c)
LDFLAGS += $(shell pkg-config --libs libpq)
LDFLAGS += -lresolv

SRCS = mtc_server.c mtc_merkle.c mtc_store.c mtc_http.c mtc_db.c

all: mtc_server

mtc_server: $(SRCS) mtc_merkle.h mtc_store.h mtc_http.h mtc_db.h
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

make-mtc-checkpoint: mtc_checkendpoint.c mtc_checkendpoint.h mtc_db.c mtc_db.h
	$(CC) -Wall -Wextra -O2 -DTEST_MAIN \
		$(shell pkg-config --cflags json-c) \
		$(shell pkg-config --cflags libpq) \
		-o mtc_checkendpoint mtc_checkendpoint.c mtc_db.c \
		$(shell pkg-config --libs json-c) \
		$(shell pkg-config --libs libpq) -lcurl

clean:
	rm -f mtc_server mtc_checkendpoint

.PHONY: all clean make-mtc-checkpoint
