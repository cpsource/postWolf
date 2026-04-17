CC       ?= cc
CFLAGS   ?= -Wall -Wextra -Wpedantic -std=c11 -O2
AR       ?= ar

INCLUDES = -Iinclude

SRCS     = src/udp_addr.c src/udp_sock.c src/udp_send.c src/udp_recv.c

# Include netlink module on Linux
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  SRCS += src/udp_netlink.c
endif

OBJS     = $(SRCS:.c=.o)
LIB      = libudp.a

all: $(LIB) examples/echo_server examples/echo_client

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

src/%.o: src/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

examples/echo_server: examples/echo_server.c $(LIB)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L. -ludp -o $@

examples/echo_client: examples/echo_client.c $(LIB)
	$(CC) $(CFLAGS) $(INCLUDES) $< -L. -ludp -o $@

clean:
	rm -f $(OBJS) $(LIB) examples/echo_server examples/echo_client

.PHONY: all clean
