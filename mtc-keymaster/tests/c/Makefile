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

all: test_revoke_matrix

$(MQC_LIB):
	$(MAKE) -C $(MQC_DIR)

test_revoke_matrix: test_revoke_matrix.c $(READ_CONFIG_SRC) $(MQC_LIB)
	$(CC) $(CFLAGS) -o $@ test_revoke_matrix.c \
		$(READ_CONFIG_SRC) $(MQC_LIB) \
		$(POSTWOLF_LIBS) $(JSON_LIBS) $(AUGEAS_LIBS) \
		-lcurl -lhiredis -lpthread -lm -lunbound -lcrypto

clean:
	rm -f test_revoke_matrix

.PHONY: all clean
