# CA-operator-kit builder.
#
#   make build-kit   — stage payload + produce postWolf-ca-kit-<ver>.tar.gz
#   make clean       — remove the staging dir and any built tarballs
#
# Assumes the full repo tree is built (libpostWolf.so, libmqc.a, the
# six CA-side tools) — run ./make-all.sh from the repo root first.

SHELL := /usr/bin/env bash

.PHONY: all build-kit clean

all: build-kit

build-kit:
	bash ./make-ca-kit.sh

clean:
	rm -rf ./payload
	rm -f  ./postWolf-ca-kit-*.tar.gz
