CC      ?= gcc
CFLAGS  += -Wall -Wextra -Werror -O2
CFLAGS  += $(shell pkg-config --cflags wolfssl) -DWOLFSSL_USE_OPTIONS_H
CFLAGS  += $(shell pkg-config --cflags json-c)
CFLAGS  += $(shell pkg-config --cflags libpq)
CFLAGS  += -I../../../socket-level-wrapper
LDFLAGS += $(shell pkg-config --libs wolfssl)
LDFLAGS += $(shell pkg-config --libs json-c)
LDFLAGS += $(shell pkg-config --libs libpq)
LDFLAGS += -lresolv -lhiredis -lpthread

SLC_DIR = ../../../socket-level-wrapper
SLC_LIB = $(SLC_DIR)/libslc.a

SRCS = mtc_server.c mtc_merkle.c mtc_store.c mtc_http.c mtc_db.c mtc_checkendpoint.c mtc_log.c mtc_ratelimit.c mtc_crypt.c mtc_bootstrap.c
LDFLAGS += -lcurl

all: mtc_server

$(SLC_LIB):
	$(MAKE) -C $(SLC_DIR)

mtc_server: $(SRCS) mtc_merkle.h mtc_store.h mtc_http.h mtc_db.h mtc_checkendpoint.h mtc_log.h mtc_ratelimit.h mtc_crypt.h mtc_bootstrap.h $(SLC_LIB)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(SLC_LIB) $(LDFLAGS)

make-mtc-checkpoint: mtc_checkendpoint.c mtc_checkendpoint.h mtc_db.c mtc_db.h
	$(CC) -Wall -Wextra -O2 -DTEST_MAIN \
		$(shell pkg-config --cflags json-c) \
		$(shell pkg-config --cflags libpq) \
		-o mtc_checkendpoint mtc_checkendpoint.c mtc_db.c \
		$(shell pkg-config --libs json-c) \
		$(shell pkg-config --libs libpq) -lcurl

doxygen:
	doxygen Doxyfile

bootstrap_leaf: bootstrap_leaf.c mtc_crypt.c mtc_crypt.h
	$(CC) -Wall -Wextra -O2 \
		$(shell pkg-config --cflags wolfssl) -DWOLFSSL_USE_OPTIONS_H \
		$(shell pkg-config --cflags json-c) \
		-o bootstrap_leaf bootstrap_leaf.c mtc_crypt.c \
		$(shell pkg-config --libs wolfssl) \
		$(shell pkg-config --libs json-c)

test-mtc-crypt: mtc_crypt.c mtc_crypt.h
	$(CC) -Wall -Wextra -O2 -DTEST_MAIN \
		$(shell pkg-config --cflags wolfssl) -DWOLFSSL_USE_OPTIONS_H \
		-o mtc_crypt_test mtc_crypt.c \
		$(shell pkg-config --libs wolfssl)

clean:
	rm -f mtc_server mtc_checkendpoint mtc_crypt_test bootstrap_leaf

clean-doxygen:
	rm -rf html

.PHONY: all clean clean-doxygen doxygen make-mtc-checkpoint test-mtc-crypt bootstrap_leaf
