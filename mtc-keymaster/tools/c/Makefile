CC      ?= gcc
CFLAGS  += -Wall -Wextra -O2
CFLAGS  += $(shell pkg-config --cflags postWolf) -DWOLFSSL_USE_OPTIONS_H
CFLAGS  += $(shell pkg-config --cflags json-c)
CFLAGS  += $(shell pkg-config --cflags libpq)
CFLAGS  += $(shell pkg-config --cflags augeas)
CFLAGS  += -I../../server2/c
CFLAGS  += -I../../../socket-level-wrapper-MQC
CFLAGS  += -I../../read-config

POSTWOLF_LIBS = $(shell pkg-config --libs postWolf)
JSON_LIBS     = $(shell pkg-config --libs json-c)
PQ_LIBS       = $(shell pkg-config --libs libpq)
AUGEAS_LIBS   = $(shell pkg-config --libs augeas)

READ_CONFIG_SRC = ../../read-config/read-config.c

SERVER_DIR = ../../server2/c

MQC_DIR = ../../../socket-level-wrapper-MQC
MQC_LIB = $(MQC_DIR)/libmqc.a

all: admin_recosign migrate-cosigner backfill-pubkey bootstrap_ca bootstrap_leaf show-tpm issue_leaf_nonce revoke-key renew-cert check-renewal-cert cancel-nonce mqc attack-port-8445 attack-port-8446

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

# One-shot Ed25519 → ML-DSA-87 cosigner rotation; see TODO #47.
migrate-cosigner: migrate-cosigner.c \
                  $(SERVER_DIR)/mtc_store.c $(SERVER_DIR)/mtc_store.h \
                  $(SERVER_DIR)/mtc_merkle.c $(SERVER_DIR)/mtc_merkle.h \
                  $(SERVER_DIR)/mtc_db.c $(SERVER_DIR)/mtc_db.h \
                  $(SERVER_DIR)/mtc_log.c $(SERVER_DIR)/mtc_log.h
	$(CC) $(CFLAGS) -o $@ \
		migrate-cosigner.c \
		$(SERVER_DIR)/mtc_store.c \
		$(SERVER_DIR)/mtc_merkle.c \
		$(SERVER_DIR)/mtc_db.c \
		$(SERVER_DIR)/mtc_log.c \
		$(POSTWOLF_LIBS) $(JSON_LIBS) $(PQ_LIBS) -lcurl

# Upsert a leaf/CA pubkey into Neon's mtc_public_keys.
backfill-pubkey: backfill-pubkey.c \
                 $(SERVER_DIR)/mtc_store.c $(SERVER_DIR)/mtc_store.h \
                 $(SERVER_DIR)/mtc_merkle.c $(SERVER_DIR)/mtc_merkle.h \
                 $(SERVER_DIR)/mtc_db.c $(SERVER_DIR)/mtc_db.h \
                 $(SERVER_DIR)/mtc_log.c $(SERVER_DIR)/mtc_log.h
	$(CC) $(CFLAGS) -o $@ \
		backfill-pubkey.c \
		$(SERVER_DIR)/mtc_store.c \
		$(SERVER_DIR)/mtc_merkle.c \
		$(SERVER_DIR)/mtc_db.c \
		$(SERVER_DIR)/mtc_log.c \
		$(POSTWOLF_LIBS) $(JSON_LIBS) $(PQ_LIBS) -lcurl

bootstrap_ca: bootstrap_ca.c \
              $(SERVER_DIR)/mtc_crypt.c $(SERVER_DIR)/mtc_crypt.h \
              $(SERVER_DIR)/mtc_domain.c $(SERVER_DIR)/mtc_domain.h \
              $(SERVER_DIR)/mtc_dnssec_pin.c $(SERVER_DIR)/mtc_dnssec_pin.h \
              $(READ_CONFIG_SRC)
	$(CC) $(CFLAGS) -o $@ \
		bootstrap_ca.c $(SERVER_DIR)/mtc_crypt.c \
		$(SERVER_DIR)/mtc_domain.c \
		$(SERVER_DIR)/mtc_dnssec_pin.c \
		$(READ_CONFIG_SRC) \
		$(POSTWOLF_LIBS) $(JSON_LIBS) $(AUGEAS_LIBS) \
		-lunbound -lcrypto

bootstrap_leaf: bootstrap_leaf.c \
                $(SERVER_DIR)/mtc_crypt.c $(SERVER_DIR)/mtc_crypt.h \
                $(SERVER_DIR)/mtc_domain.c $(SERVER_DIR)/mtc_domain.h \
                $(READ_CONFIG_SRC)
	$(CC) $(CFLAGS) -o $@ \
		bootstrap_leaf.c $(SERVER_DIR)/mtc_crypt.c \
		$(SERVER_DIR)/mtc_domain.c \
		$(READ_CONFIG_SRC) \
		$(POSTWOLF_LIBS) $(JSON_LIBS) $(AUGEAS_LIBS)

show-tpm: show-tpm.c $(READ_CONFIG_SRC) $(MQC_LIB)
	$(CC) $(CFLAGS) -o $@ show-tpm.c $(READ_CONFIG_SRC) $(MQC_LIB) \
		$(POSTWOLF_LIBS) $(JSON_LIBS) $(AUGEAS_LIBS) \
		-lcurl -lhiredis -lpthread -lm -lunbound -lcrypto

issue_leaf_nonce: issue_leaf_nonce.c $(SERVER_DIR)/mtc_domain.c \
                  $(SERVER_DIR)/mtc_domain.h $(READ_CONFIG_SRC) $(MQC_LIB)
	$(CC) $(CFLAGS) -o $@ issue_leaf_nonce.c \
		$(SERVER_DIR)/mtc_domain.c $(READ_CONFIG_SRC) $(MQC_LIB) \
		$(POSTWOLF_LIBS) $(JSON_LIBS) $(AUGEAS_LIBS) \
		-lcurl -lhiredis -lpthread -lm -lunbound -lcrypto

revoke-key: revoke-key.c $(READ_CONFIG_SRC) $(MQC_LIB)
	$(CC) $(CFLAGS) -o $@ revoke-key.c $(READ_CONFIG_SRC) $(MQC_LIB) \
		$(POSTWOLF_LIBS) $(JSON_LIBS) $(AUGEAS_LIBS) \
		-lcurl -lhiredis -lpthread -lm -lunbound -lcrypto

renew-cert: renew-cert.c $(READ_CONFIG_SRC) $(MQC_LIB)
	$(CC) $(CFLAGS) -o $@ renew-cert.c $(READ_CONFIG_SRC) $(MQC_LIB) \
		$(POSTWOLF_LIBS) $(JSON_LIBS) $(AUGEAS_LIBS) \
		-lcurl -lhiredis -lpthread -lm -lunbound -lcrypto

check-renewal-cert: check-renewal-cert.c $(READ_CONFIG_SRC) $(MQC_LIB)
	$(CC) $(CFLAGS) -o $@ check-renewal-cert.c $(READ_CONFIG_SRC) $(MQC_LIB) \
		$(POSTWOLF_LIBS) $(JSON_LIBS) $(AUGEAS_LIBS) \
		-lcurl -lhiredis -lpthread -lm -lunbound -lcrypto

cancel-nonce: cancel-nonce.c $(SERVER_DIR)/mtc_domain.c \
              $(SERVER_DIR)/mtc_domain.h $(READ_CONFIG_SRC) $(MQC_LIB)
	$(CC) $(CFLAGS) -o $@ cancel-nonce.c \
		$(SERVER_DIR)/mtc_domain.c $(READ_CONFIG_SRC) $(MQC_LIB) \
		$(POSTWOLF_LIBS) $(JSON_LIBS) $(AUGEAS_LIBS) \
		-lcurl -lhiredis -lpthread -lm -lunbound -lcrypto

# Standalone symmetric-crypto pipe tool.  No MQC link needed — pure
# wolfCrypt + json-c.
mqc: mqc.c
	$(CC) $(CFLAGS) -o $@ mqc.c \
		$(POSTWOLF_LIBS) $(JSON_LIBS)

# Adversarial probes — raw sockets only, no MQC/postWolf link dep.
# read-config (Augeas) pulled in so they pick up [global] url-{server,bootstrap}.
attack-port-8445: attack-port-8445.c $(READ_CONFIG_SRC)
	$(CC) -Wall -Wextra -O2 $(shell pkg-config --cflags augeas) \
		-I../../read-config \
		-o $@ attack-port-8445.c $(READ_CONFIG_SRC) $(AUGEAS_LIBS)

attack-port-8446: attack-port-8446.c $(READ_CONFIG_SRC)
	$(CC) -Wall -Wextra -O2 $(shell pkg-config --cflags augeas) \
		-I../../read-config \
		-o $@ attack-port-8446.c $(READ_CONFIG_SRC) $(AUGEAS_LIBS)

BINDIR ?= /usr/local/bin

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 admin_recosign    $(DESTDIR)$(BINDIR)/admin_recosign
	install -m 755 migrate-cosigner  $(DESTDIR)$(BINDIR)/migrate-cosigner
	install -m 755 backfill-pubkey   $(DESTDIR)$(BINDIR)/backfill-pubkey
	install -m 755 bootstrap_ca      $(DESTDIR)$(BINDIR)/bootstrap_ca
	install -m 755 bootstrap_leaf    $(DESTDIR)$(BINDIR)/bootstrap_leaf
	install -m 755 show-tpm          $(DESTDIR)$(BINDIR)/show-tpm
	install -m 755 issue_leaf_nonce  $(DESTDIR)$(BINDIR)/issue_leaf_nonce
	install -m 755 revoke-key        $(DESTDIR)$(BINDIR)/revoke-key
	install -m 755 renew-cert        $(DESTDIR)$(BINDIR)/renew-cert
	install -m 755 check-renewal-cert $(DESTDIR)$(BINDIR)/check-renewal-cert
	install -m 755 cancel-nonce      $(DESTDIR)$(BINDIR)/cancel-nonce
	install -m 755 mqc               $(DESTDIR)$(BINDIR)/mqc
	install -m 755 attack-port-8445  $(DESTDIR)$(BINDIR)/attack-port-8445
	install -m 755 attack-port-8446  $(DESTDIR)$(BINDIR)/attack-port-8446

clean:
	rm -f admin_recosign migrate-cosigner backfill-pubkey bootstrap_ca bootstrap_leaf show-tpm issue_leaf_nonce revoke-key renew-cert check-renewal-cert cancel-nonce mqc attack-port-8445 attack-port-8446

.PHONY: all install clean
