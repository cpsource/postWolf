CC      ?= gcc
CFLAGS  += -Wall -Wextra -O2
CFLAGS  += $(shell pkg-config --cflags postWolf) -DWOLFSSL_USE_OPTIONS_H
CFLAGS  += $(shell pkg-config --cflags json-c)
CFLAGS  += $(shell pkg-config --cflags augeas)
CFLAGS  += -I../../server2/c
CFLAGS  += -I../../../socket-level-wrapper-MQC
CFLAGS  += -I../../read-config

POSTWOLF_LIBS = $(shell pkg-config --libs postWolf)
JSON_LIBS     = $(shell pkg-config --libs json-c)
AUGEAS_LIBS   = $(shell pkg-config --libs augeas)

READ_CONFIG_SRC = ../../read-config/read-config.c

MQC_DIR = ../../../socket-level-wrapper-MQC
MQC_LIB = $(MQC_DIR)/libmqc.a

SERVER_DIR = ../../server2/c

all: test_revoke_matrix test_merkle_tiled

$(MQC_LIB):
	$(MAKE) -C $(MQC_DIR)

test_revoke_matrix: test_revoke_matrix.c $(READ_CONFIG_SRC) $(MQC_LIB)
	$(CC) $(CFLAGS) -o $@ test_revoke_matrix.c \
		$(READ_CONFIG_SRC) $(MQC_LIB) \
		$(POSTWOLF_LIBS) $(JSON_LIBS) $(AUGEAS_LIBS) \
		-lcurl -lhiredis -lpthread -lm -lunbound -lcrypto

# Equivalence test: legacy mtc_merkle vs tiled mtc_merkle_tiled.
# Links the in-process mock store (mtc_tile_store_mock.c) instead of
# the Postgres backend, so the binary needs no DB.  We don't link
# libpq either; the mock signatures take a PGconn* but ignore it.
TILED_TEST_SRCS = test_merkle_tiled.c \
                  mtc_tile_store_mock.c \
                  $(SERVER_DIR)/mtc_merkle.c \
                  $(SERVER_DIR)/mtc_merkle_tiled.c \
                  $(SERVER_DIR)/mtc_tile_cache.c

TILED_TEST_HDRS = $(SERVER_DIR)/mtc_merkle.h \
                  $(SERVER_DIR)/mtc_merkle_tiled.h \
                  $(SERVER_DIR)/mtc_tile.h \
                  $(SERVER_DIR)/mtc_tile_cache.h \
                  $(SERVER_DIR)/mtc_tile_store.h

# We need libpq.h for the PGconn typedef even though no PG calls are
# made; pull cflags but no lib link.
test_merkle_tiled: $(TILED_TEST_SRCS) $(TILED_TEST_HDRS)
	$(CC) $(CFLAGS) $(shell pkg-config --cflags libpq) \
		-o $@ $(TILED_TEST_SRCS) \
		$(POSTWOLF_LIBS)

clean:
	rm -f test_revoke_matrix test_merkle_tiled

.PHONY: all clean
