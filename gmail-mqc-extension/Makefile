# gmail-mqc-extension kit builder.
#
#   make build-kit   — pack host/ + extension/ + top README into
#                      postWolf-gmail-mqc-ext-<ver>.tar.gz
#   make clean       — remove built tarballs
#
# No compile step — these are pure source (Python, JS, JSON, PS1).

SHELL := /usr/bin/env bash

.PHONY: all build-kit clean

all: build-kit

build-kit:
	bash ./make-extension-kit.sh

clean:
	rm -f ./postWolf-gmail-mqc-ext-*.tar.gz
