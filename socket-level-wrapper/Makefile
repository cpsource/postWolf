# socket-level-wrapper Makefile
#
# Builds libslc.a and example echo client/server.
# Requires wolfssl-new built in the parent directory.
#
# wolfSSL stores its feature flags (HAVE_ECH, WOLFSSL_TLS13, HAVE_MTC, etc.)
# in AM_CFLAGS in the Makefile, not in wolfssl/options.h. We extract them
# so our code sees the same feature macros as the library was compiled with.

WOLFSSL_DIR = ..
WOLFSSL_INC = $(WOLFSSL_DIR)
WOLFSSL_LIB = $(WOLFSSL_DIR)/src/.libs

# Extract wolfSSL's AM_CFLAGS (feature macros + include paths),
# filtering out the $(EXTRA_CFLAGS) make variable reference.
WOLFSSL_CFLAGS := $(filter-out $$(EXTRA_CFLAGS),$(shell sed -n 's/^AM_CFLAGS = //p' $(WOLFSSL_DIR)/Makefile))

CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2
CFLAGS  += -I$(WOLFSSL_INC) $(WOLFSSL_CFLAGS)
LDFLAGS += -L$(WOLFSSL_LIB) -lwolfssl -lm -lpthread

AR      ?= ar

LIB     = libslc.a
TARGETS = $(LIB) examples/echo_server examples/echo_client

# Quiet output matching autotools style: "  CC   slc.o"
# Use V=1 to see full commands.
V ?= 0
ifeq ($(V),0)
  quiet = @printf "  %-7s %s\n" $(1) $(2);
else
  quiet =
endif

all: $(TARGETS)

$(LIB): slc.o
	$(call quiet,AR,$@)$(AR) rcs $@ $<

slc.o: slc.c slc.h
	$(call quiet,CC,$@)$(CC) $(CFLAGS) -c -o $@ slc.c

examples/echo_server: examples/echo_server.c $(LIB) slc.h
	$(call quiet,CCLD,$@)$(CC) $(CFLAGS) -I. -o $@ $< -L. -lslc $(LDFLAGS)

examples/echo_client: examples/echo_client.c $(LIB) slc.h
	$(call quiet,CCLD,$@)$(CC) $(CFLAGS) -I. -o $@ $< -L. -lslc $(LDFLAGS)

clean:
	@rm -f slc.o $(LIB) examples/echo_server examples/echo_client

.PHONY: all clean
