# fips-framework/tools/c — C tools for the FIPS-manifest workflow.
# Built against the installed postWolf library via pkg-config.

CC      ?= gcc
CFLAGS  += -Wall -Wextra -Werror -O2
CFLAGS  += $(shell pkg-config --cflags postWolf) -DWOLFSSL_USE_OPTIONS_H
CFLAGS  += $(shell pkg-config --cflags json-c)
CFLAGS  += $(shell pkg-config --cflags libpq)

POSTWOLF_LIBS = $(shell pkg-config --libs postWolf)
JSON_LIBS     = $(shell pkg-config --libs json-c)
PQ_LIBS       = $(shell pkg-config --libs libpq)

TARGETS = fips-manifest-submit fips-manifest-verify fips-manifest-list

all: $(TARGETS)

fips-manifest-submit: fips-manifest-submit.c
	$(CC) $(CFLAGS) -o $@ $< $(POSTWOLF_LIBS) $(JSON_LIBS)

fips-manifest-verify: fips-manifest-verify.c
	$(CC) $(CFLAGS) -o $@ $< $(POSTWOLF_LIBS) $(JSON_LIBS)

fips-manifest-list: fips-manifest-list.c
	$(CC) $(CFLAGS) -o $@ $< $(JSON_LIBS) $(PQ_LIBS)

clean:
	rm -f $(TARGETS)

install: all
	install -d /usr/local/bin
	install -m 755 fips-manifest-submit /usr/local/bin/fips-manifest-submit
	install -m 755 fips-manifest-verify /usr/local/bin/fips-manifest-verify
	install -m 755 fips-manifest-list   /usr/local/bin/fips-manifest-list

.PHONY: all clean install
