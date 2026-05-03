# socket-level-wrapper-MQC Makefile
#
# Builds libmqc.a and example echo client/server.

CC      ?= gcc
CFLAGS  += -Wall -Wextra -O2
CFLAGS  += $(shell pkg-config --cflags postWolf) -DWOLFSSL_USE_OPTIONS_H
CFLAGS  += $(shell pkg-config --cflags json-c)
CFLAGS  += $(shell pkg-config --cflags augeas)
CFLAGS  += -I../mtc-keymaster/read-config
LDFLAGS += $(shell pkg-config --libs postWolf)
LDFLAGS += $(shell pkg-config --libs json-c)
LDFLAGS += $(shell pkg-config --libs augeas)
LDFLAGS += -lcurl -lhiredis

AR      ?= ar

LIB     = libmqc.a
OBJS    = mqc.o mqc_peer.o
TESTS   = tests/test_name_check
TARGETS = $(LIB) examples/echo_server examples/echo_client $(TESTS)

V ?= 0
ifeq ($(V),0)
  quiet = @printf "  %-7s %s\n" $(1) $(2);
else
  quiet =
endif

all: $(TARGETS)

$(LIB): $(OBJS)
	$(call quiet,AR,$@)$(AR) rcs $@ $^

mqc.o: mqc.c mqc.h mqc_peer.h
	$(call quiet,CC,$@)$(CC) $(CFLAGS) -c -o $@ mqc.c

mqc_peer.o: mqc_peer.c mqc_peer.h
	$(call quiet,CC,$@)$(CC) $(CFLAGS) -c -o $@ mqc_peer.c

examples/echo_server: examples/echo_server.c $(LIB) mqc.h
	$(call quiet,CCLD,$@)$(CC) $(CFLAGS) -I. -o $@ $< ../mtc-keymaster/read-config/read-config.c -L. -lmqc $(LDFLAGS)

examples/echo_client: examples/echo_client.c $(LIB) mqc.h
	$(call quiet,CCLD,$@)$(CC) $(CFLAGS) -I. -o $@ $< ../mtc-keymaster/read-config/read-config.c -L. -lmqc $(LDFLAGS)

tests/test_name_check: tests/test_name_check.c $(LIB) mqc.h mqc_peer.h
	$(call quiet,CCLD,$@)$(CC) $(CFLAGS) -I. -o $@ $< ../mtc-keymaster/read-config/read-config.c -L. -lmqc $(LDFLAGS)

# Run the negative-path regression test.  Requires a live MQC
# listener at factsorlie.com:8446 and a valid TPM at the path
# baked into test_name_check.c (override via --tpm / --server).
test: tests/test_name_check
	@./tests/test_name_check

clean:
	@rm -f $(OBJS) $(LIB) examples/echo_server examples/echo_client $(TESTS)

.PHONY: all clean test
