# socket-level-wrapper-MQC Makefile
#
# Builds libmqc.a and example echo client/server.

CC      ?= gcc
CFLAGS  += -Wall -Wextra -O2
CFLAGS  += $(shell pkg-config --cflags wolfGuard) -DWOLFSSL_USE_OPTIONS_H
CFLAGS  += $(shell pkg-config --cflags json-c)
LDFLAGS += $(shell pkg-config --libs wolfGuard)
LDFLAGS += $(shell pkg-config --libs json-c)
LDFLAGS += -lcurl -lhiredis

AR      ?= ar

LIB     = libmqc.a
OBJS    = mqc.o mqc_peer.o
TARGETS = $(LIB) examples/echo_server examples/echo_client

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
	$(call quiet,CCLD,$@)$(CC) $(CFLAGS) -I. -o $@ $< -L. -lmqc $(LDFLAGS)

examples/echo_client: examples/echo_client.c $(LIB) mqc.h
	$(call quiet,CCLD,$@)$(CC) $(CFLAGS) -I. -o $@ $< -L. -lmqc $(LDFLAGS)

clean:
	@rm -f $(OBJS) $(LIB) examples/echo_server examples/echo_client

.PHONY: all clean
