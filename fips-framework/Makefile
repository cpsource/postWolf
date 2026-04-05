# fips-framework Makefile
#
# Builds fips-manifest-submit and fips-manifest-verify against wolfCrypt.
# Assumes wolfssl-new has been configured and built in the parent directory.

WOLFSSL_DIR = ..
WOLFSSL_INC = $(WOLFSSL_DIR)
WOLFSSL_LIB = $(WOLFSSL_DIR)/src/.libs

CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2
CFLAGS  += -I$(WOLFSSL_INC)
LDFLAGS += -L$(WOLFSSL_LIB) -lwolfssl -lm

TARGETS = fips-manifest-submit fips-manifest-verify

all: $(TARGETS)

fips-manifest-submit: fips-manifest-submit.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

fips-manifest-verify: fips-manifest-verify.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

.PHONY: all clean
