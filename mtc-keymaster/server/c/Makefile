CC      ?= gcc
CFLAGS  += -Wall -Wextra -Werror -O2
CFLAGS  += $(shell pkg-config --cflags postWolf) -DWOLFSSL_USE_OPTIONS_H
CFLAGS  += $(shell pkg-config --cflags json-c)
CFLAGS  += $(shell pkg-config --cflags libpq)
CFLAGS  += -I../../../socket-level-wrapper
CFLAGS  += -I../../../socket-level-wrapper-MQC
LDFLAGS += $(shell pkg-config --libs postWolf)
LDFLAGS += $(shell pkg-config --libs json-c)
LDFLAGS += $(shell pkg-config --libs libpq)
LDFLAGS += -lresolv -lhiredis -lpthread

SLC_DIR = ../../../socket-level-wrapper
SLC_LIB = $(SLC_DIR)/libslc.a

MQC_DIR = ../../../socket-level-wrapper-MQC
MQC_LIB = $(MQC_DIR)/libmqc.a

SRCS = mtc_server.c mtc_merkle.c mtc_store.c mtc_http.c mtc_db.c mtc_checkendpoint.c mtc_log.c mtc_ratelimit.c mtc_crypt.c mtc_bootstrap.c mtc_ca_validate.c
LDFLAGS += -lcurl

all: mtc_server show-tpm bootstrap_ca bootstrap_leaf admin_recosign

$(SLC_LIB):
	$(MAKE) -C $(SLC_DIR)

$(MQC_LIB):
	$(MAKE) -C $(MQC_DIR)

mtc_server: $(SRCS) mtc_merkle.h mtc_store.h mtc_http.h mtc_db.h mtc_checkendpoint.h mtc_log.h mtc_ratelimit.h mtc_crypt.h mtc_bootstrap.h mtc_ca_validate.h $(SLC_LIB) $(MQC_LIB)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(SLC_LIB) $(MQC_LIB) $(LDFLAGS)

make-mtc-checkpoint: mtc_checkendpoint.c mtc_checkendpoint.h mtc_db.c mtc_db.h
	$(CC) -Wall -Wextra -O2 -DTEST_MAIN \
		$(shell pkg-config --cflags json-c) \
		$(shell pkg-config --cflags libpq) \
		-o mtc_checkendpoint mtc_checkendpoint.c mtc_db.c \
		$(shell pkg-config --libs json-c) \
		$(shell pkg-config --libs libpq) -lcurl

doxygen:
	doxygen Doxyfile

bootstrap_ca: bootstrap_ca.c mtc_crypt.c mtc_crypt.h mtc_pubkey_db.c mtc_pubkey_db.h
	$(CC) -Wall -Wextra -O2 \
		$(shell pkg-config --cflags postWolf) -DWOLFSSL_USE_OPTIONS_H \
		$(shell pkg-config --cflags json-c) \
		$(shell pkg-config --cflags libpq) \
		-o bootstrap_ca bootstrap_ca.c mtc_crypt.c mtc_pubkey_db.c \
		$(shell pkg-config --libs postWolf) \
		$(shell pkg-config --libs json-c) \
		$(shell pkg-config --libs libpq)

bootstrap_leaf: bootstrap_leaf.c mtc_crypt.c mtc_crypt.h mtc_pubkey_db.c mtc_pubkey_db.h
	$(CC) -Wall -Wextra -O2 \
		$(shell pkg-config --cflags postWolf) -DWOLFSSL_USE_OPTIONS_H \
		$(shell pkg-config --cflags json-c) \
		$(shell pkg-config --cflags libpq) \
		-o bootstrap_leaf bootstrap_leaf.c mtc_crypt.c mtc_pubkey_db.c \
		$(shell pkg-config --libs postWolf) \
		$(shell pkg-config --libs json-c) \
		$(shell pkg-config --libs libpq)

admin_recosign: admin_recosign.c mtc_store.c mtc_store.h mtc_merkle.c mtc_merkle.h mtc_db.c mtc_db.h mtc_log.c mtc_log.h
	$(CC) -Wall -Wextra -O2 \
		$(shell pkg-config --cflags postWolf) -DWOLFSSL_USE_OPTIONS_H \
		$(shell pkg-config --cflags json-c) \
		$(shell pkg-config --cflags libpq) \
		-o admin_recosign admin_recosign.c mtc_store.c mtc_merkle.c mtc_db.c mtc_log.c \
		$(shell pkg-config --libs postWolf) \
		$(shell pkg-config --libs json-c) \
		$(shell pkg-config --libs libpq) \
		-lcurl

show-tpm: show-tpm.c $(MQC_LIB)
	$(CC) -Wall -Wextra -O2 \
		$(shell pkg-config --cflags postWolf) -DWOLFSSL_USE_OPTIONS_H \
		$(shell pkg-config --cflags json-c) \
		-I../../../socket-level-wrapper-MQC \
		-o show-tpm show-tpm.c $(MQC_LIB) \
		$(shell pkg-config --libs postWolf) \
		$(shell pkg-config --libs json-c) -lcurl -lhiredis -lpthread -lm

test-mtc-crypt: mtc_crypt.c mtc_crypt.h
	$(CC) -Wall -Wextra -O2 -DTEST_MAIN \
		$(shell pkg-config --cflags postWolf) -DWOLFSSL_USE_OPTIONS_H \
		-o mtc_crypt_test mtc_crypt.c \
		$(shell pkg-config --libs postWolf)

BINDIR ?= /usr/local/bin

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 mtc_server     $(DESTDIR)$(BINDIR)/mtc_server
	install -m 755 show-tpm       $(DESTDIR)$(BINDIR)/show-tpm
	install -m 755 bootstrap_ca   $(DESTDIR)$(BINDIR)/bootstrap_ca
	install -m 755 bootstrap_leaf $(DESTDIR)$(BINDIR)/bootstrap_leaf
	install -m 755 admin_recosign $(DESTDIR)$(BINDIR)/admin_recosign

clean:
	rm -f mtc_server mtc_checkendpoint mtc_crypt_test bootstrap_leaf bootstrap_ca show-tpm admin_recosign

clean-doxygen:
	rm -rf html

.PHONY: all install clean clean-doxygen doxygen make-mtc-checkpoint test-mtc-crypt
