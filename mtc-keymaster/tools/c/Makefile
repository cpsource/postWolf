CC      ?= gcc
CFLAGS  += -Wall -Wextra -O2
CFLAGS  += $(shell pkg-config --cflags postWolf) -DWOLFSSL_USE_OPTIONS_H
CFLAGS  += $(shell pkg-config --cflags json-c)
CFLAGS  += $(shell pkg-config --cflags libpq)
CFLAGS  += -I../../server2/c
CFLAGS  += -I../../../socket-level-wrapper-MQC

POSTWOLF_LIBS = $(shell pkg-config --libs postWolf)
JSON_LIBS     = $(shell pkg-config --libs json-c)
PQ_LIBS       = $(shell pkg-config --libs libpq)

SERVER_DIR = ../../server2/c

MQC_DIR = ../../../socket-level-wrapper-MQC
MQC_LIB = $(MQC_DIR)/libmqc.a

all: admin_recosign bootstrap_ca bootstrap_leaf show-tpm issue_leaf_nonce

$(MQC_LIB):
	$(MAKE) -C $(MQC_DIR)

admin_recosign: admin_recosign.c \
                $(SERVER_DIR)/mtc_store.c $(SERVER_DIR)/mtc_store.h \
                $(SERVER_DIR)/mtc_merkle.c $(SERVER_DIR)/mtc_merkle.h \
                $(SERVER_DIR)/mtc_db.c $(SERVER_DIR)/mtc_db.h \
                $(SERVER_DIR)/mtc_log.c $(SERVER_DIR)/mtc_log.h
	$(CC) $(CFLAGS) -o $@ \
		admin_recosign.c \
		$(SERVER_DIR)/mtc_store.c \
		$(SERVER_DIR)/mtc_merkle.c \
		$(SERVER_DIR)/mtc_db.c \
		$(SERVER_DIR)/mtc_log.c \
		$(POSTWOLF_LIBS) $(JSON_LIBS) $(PQ_LIBS) -lcurl

bootstrap_ca: bootstrap_ca.c mtc_pubkey_db.c mtc_pubkey_db.h \
              $(SERVER_DIR)/mtc_crypt.c $(SERVER_DIR)/mtc_crypt.h
	$(CC) $(CFLAGS) -o $@ \
		bootstrap_ca.c mtc_pubkey_db.c $(SERVER_DIR)/mtc_crypt.c \
		$(POSTWOLF_LIBS) $(JSON_LIBS) $(PQ_LIBS)

bootstrap_leaf: bootstrap_leaf.c mtc_pubkey_db.c mtc_pubkey_db.h \
                $(SERVER_DIR)/mtc_crypt.c $(SERVER_DIR)/mtc_crypt.h
	$(CC) $(CFLAGS) -o $@ \
		bootstrap_leaf.c mtc_pubkey_db.c $(SERVER_DIR)/mtc_crypt.c \
		$(POSTWOLF_LIBS) $(JSON_LIBS) $(PQ_LIBS)

show-tpm: show-tpm.c $(MQC_LIB)
	$(CC) $(CFLAGS) -o $@ show-tpm.c $(MQC_LIB) \
		$(POSTWOLF_LIBS) $(JSON_LIBS) -lcurl -lhiredis -lpthread -lm

issue_leaf_nonce: issue_leaf_nonce.c $(MQC_LIB)
	$(CC) $(CFLAGS) -o $@ issue_leaf_nonce.c $(MQC_LIB) \
		$(POSTWOLF_LIBS) $(JSON_LIBS) -lcurl -lhiredis -lpthread -lm

BINDIR ?= /usr/local/bin

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 admin_recosign    $(DESTDIR)$(BINDIR)/admin_recosign
	install -m 755 bootstrap_ca      $(DESTDIR)$(BINDIR)/bootstrap_ca
	install -m 755 bootstrap_leaf    $(DESTDIR)$(BINDIR)/bootstrap_leaf
	install -m 755 show-tpm          $(DESTDIR)$(BINDIR)/show-tpm
	install -m 755 issue_leaf_nonce  $(DESTDIR)$(BINDIR)/issue_leaf_nonce

clean:
	rm -f admin_recosign bootstrap_ca bootstrap_leaf show-tpm issue_leaf_nonce

.PHONY: all install clean
