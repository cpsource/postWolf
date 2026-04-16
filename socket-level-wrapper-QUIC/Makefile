# socket-level-wrapper-QUIC Makefile
#
# Builds libudp.a, libmqcp.a, and example echo client/server.

CC      ?= gcc
CFLAGS  += -Wall -Wextra -O2
CFLAGS  += $(shell pkg-config --cflags wolfGuard) -DWOLFSSL_USE_OPTIONS_H
CFLAGS  += -I. -Ilibudp/include

LDFLAGS += $(shell pkg-config --libs wolfGuard)
LDFLAGS += -Llibudp -ludp

AR      ?= ar

LIB     = libmqcp.a
OBJS    = mqcp_timer.o mqcp_crypto.o mqcp_packet.o mqcp_peer.o \
          mqcp_handshake.o mqcp_reliability.o mqcp_cc.o mqcp_stream.o mqcp_conn.o
TARGETS = $(LIB) examples/echo_server examples/echo_client

V ?= 0
ifeq ($(V),0)
  quiet = @printf "  %-7s %s\n" $(1) $(2);
else
  quiet =
endif

all: libudp/libudp.a $(TARGETS)

libudp/libudp.a:
	$(call quiet,MAKE,libudp)$(MAKE) -C libudp

$(LIB): $(OBJS)
	$(call quiet,AR,$@)$(AR) rcs $@ $^

%.o: %.c
	$(call quiet,CC,$@)$(CC) $(CFLAGS) -c -o $@ $<

examples/echo_server: examples/echo_server.c $(LIB) libudp/libudp.a
	$(call quiet,CCLD,$@)$(CC) $(CFLAGS) -o $@ $< -L. -lmqcp $(LDFLAGS)

examples/echo_client: examples/echo_client.c $(LIB) libudp/libudp.a
	$(call quiet,CCLD,$@)$(CC) $(CFLAGS) -o $@ $< -L. -lmqcp $(LDFLAGS)

clean:
	@rm -f $(OBJS) $(LIB) examples/echo_server examples/echo_client
	@$(MAKE) -C libudp clean

.PHONY: all clean libudp/libudp.a
