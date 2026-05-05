# MTC-server-kit builder.
#
#   make build-kit   — stage payload + produce postWolf-server-kit-<ver>.tar.gz
#   make clean       — remove the staging dir and any built tarballs
#
# Assumes the full repo tree is built (libpostWolf.so, mtc_server, the
# server-side ops tools) — run ./make-all.sh from the repo root first.

SHELL := /usr/bin/env bash

.PHONY: all build-kit clean

all: build-kit

build-kit:
	bash ./make-server-kit.sh

clean:
	rm -rf ./payload
	rm -f  ./postWolf-server-kit-*.tar.gz
