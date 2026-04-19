# Leaf-kit builder.
#
#   make build-kit   — stage payload + produce postWolf-leaf-kit-<ver>.tar.gz
#   make clean       — remove the staging dir and any built tarballs
#
# Assumes the full repo tree (libpostWolf.so, libmqc.a, the leaf tools)
# is already built — run ./make-all.sh from the repo root first.

SHELL := /usr/bin/env bash

.PHONY: all build-kit clean

all: build-kit

build-kit:
	bash ./make-leaf-kit.sh

clean:
	rm -rf ./payload
	rm -f  ./postWolf-leaf-kit-*.tar.gz
