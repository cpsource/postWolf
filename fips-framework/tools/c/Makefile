# fips-framework/tools/c — C tools for the FIPS-manifest workflow.
# Built against the installed postWolf library via pkg-config; MQC
# transport sources are pulled directly from the in-tree wrapper.

CC      ?= gcc
CFLAGS  += -Wall -Wextra -Werror -O2
CFLAGS  += $(shell pkg-config --cflags postWolf) -DWOLFSSL_USE_OPTIONS_H
CFLAGS  += $(shell pkg-config --cflags json-c)

POSTWOLF_LIBS = $(shell pkg-config --libs postWolf)
JSON_LIBS     = $(shell pkg-config --libs json-c)

# fips-manifest-list talks to the server over MQC (port 8446) — no
# direct DB credentials required.  It pulls in the in-tree libmqc.a +
# the read-config helper for url-server lookup.
MQC_DIR        = ../../../socket-level-wrapper-MQC
MQC_LIB        = $(MQC_DIR)/libmqc.a
MTC_KEYMASTER  = ../../../mtc-keymaster
READ_CONFIG_SRC = $(MTC_KEYMASTER)/read-config/read-config.c

LIST_CFLAGS = -I$(MQC_DIR) -I$(MTC_KEYMASTER)/read-config \
              $(shell pkg-config --cflags augeas)
LIST_LIBS   = $(shell pkg-config --libs augeas) \
              -lhiredis -lpthread -lunbound -lcrypto -lcurl

TARGETS = fips-manifest-submit fips-manifest-verify fips-manifest-list \
          fips-manifest-revoke fetch-publisher-key

all: $(TARGETS)

fips-manifest-submit: fips-manifest-submit.c
	$(CC) $(CFLAGS) -o $@ $< $(POSTWOLF_LIBS) $(JSON_LIBS)

fips-manifest-verify: fips-manifest-verify.c $(READ_CONFIG_SRC) $(MQC_LIB)
	$(CC) $(CFLAGS) $(LIST_CFLAGS) -o $@ \
		fips-manifest-verify.c $(READ_CONFIG_SRC) $(MQC_LIB) \
		$(POSTWOLF_LIBS) $(JSON_LIBS) $(LIST_LIBS)

fips-manifest-list: fips-manifest-list.c $(READ_CONFIG_SRC) $(MQC_LIB)
	$(CC) $(CFLAGS) $(LIST_CFLAGS) -o $@ \
		fips-manifest-list.c $(READ_CONFIG_SRC) $(MQC_LIB) \
		$(POSTWOLF_LIBS) $(JSON_LIBS) $(LIST_LIBS)

# Same MQC + read-config wiring as fips-manifest-list.
fips-manifest-revoke: fips-manifest-revoke.c $(READ_CONFIG_SRC) $(MQC_LIB)
	$(CC) $(CFLAGS) $(LIST_CFLAGS) -o $@ \
		fips-manifest-revoke.c $(READ_CONFIG_SRC) $(MQC_LIB) \
		$(POSTWOLF_LIBS) $(JSON_LIBS) $(LIST_LIBS)

# Fetch a publisher's PEM authoritatively from the server (for
# verify-dir.sh's cross-publisher fallback).
fetch-publisher-key: fetch-publisher-key.c $(READ_CONFIG_SRC) $(MQC_LIB)
	$(CC) $(CFLAGS) $(LIST_CFLAGS) -o $@ \
		fetch-publisher-key.c $(READ_CONFIG_SRC) $(MQC_LIB) \
		$(POSTWOLF_LIBS) $(JSON_LIBS) $(LIST_LIBS)

clean:
	rm -f $(TARGETS)

install: all
	install -d /usr/local/bin
	install -m 755 fips-manifest-submit /usr/local/bin/fips-manifest-submit
	install -m 755 fips-manifest-verify /usr/local/bin/fips-manifest-verify
	install -m 755 fips-manifest-list   /usr/local/bin/fips-manifest-list
	install -m 755 fips-manifest-revoke /usr/local/bin/fips-manifest-revoke
	install -m 755 fetch-publisher-key  /usr/local/bin/fetch-publisher-key

.PHONY: all clean install
