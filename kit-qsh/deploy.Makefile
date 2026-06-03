# deploy-qsh — install qsh and its identity on a fresh host.
#
# Layout inside the extracted tarball:
#   ./qsh                 -> /usr/local/bin/qsh                       (system-wide)
#   ./postWolf.config     -> /etc/postWolf/config                     (system-wide)
#   ./myconf.aug          -> /usr/local/share/augeas/lenses/myconf.aug (system-wide)
#   ./TPM/<identity>/...  -> ~/.TPM/<identity>/...                    (per-user)
#   ./check-qsh-deps.py   stays here (audit tool)
#
# The Augeas lens is what lets qsh parse /etc/postWolf/config; without
# it, read_config_url returns NULL and qsh falls back to localhost.
#
# The TPM identity ships private key material — `make install-tpm`
# copies it to the running user's $HOME and tightens permissions.
# DO NOT run that target under sudo unless you really mean root to
# own the identity (qsh resolves --tpm-path against $HOME).
#
# Targets:
#   make                - show this help (default)
#   make check          - audit runtime library deps against ./qsh
#   make install        - check + install-bin + install-config + install-tpm
#   make install-bin    - sudo install qsh into /usr/local/bin
#   make install-config - sudo install postWolf.config into /etc/postWolf/
#   make install-tpm    - copy TPM/<identity> into ~/.TPM/<identity>
#   make uninstall      - remove qsh + config + ~/.TPM/<identity>
#   make run            - quick smoke: qsh against $HOST using bundled identity

IDENTITY ?= factsorlie.com
HOST     ?= factsorlie.com
PREFIX   ?= /usr/local
BIN_DIR  ?= $(PREFIX)/bin
LENS_DIR ?= $(PREFIX)/share/augeas/lenses
ETC_DIR  ?= /etc/postWolf
TPM_HOME ?= $(HOME)/.TPM
MQC_BIN  ?= /usr/local/bin/mqc
BYPASS_PW ?= $(HOME)/.mqc-master-password
INSTALL  ?= install
SUDO     ?= sudo

.PHONY: help check install install-bin install-config install-tpm install-bypass uninstall run

help:
	@echo "deploy-qsh — qsh client install kit"
	@echo
	@echo "Targets:"
	@echo "  make check           audit runtime library deps against ./qsh"
	@echo "  make install         check + install-bin + install-config + install-tpm"
	@echo "  make install-bin     $(SUDO) install qsh into $(BIN_DIR)"
	@echo "  make install-config  $(SUDO) install postWolf.config + myconf.aug"
	@echo "  make install-tpm     copy TPM/$(IDENTITY) -> $(TPM_HOME)/$(IDENTITY)"
	@echo "  make install-bypass  decode mqc-master-password.enc -> $(BYPASS_PW) (0600)"
	@echo "  make uninstall       remove qsh + $(ETC_DIR)/config + $(TPM_HOME)/$(IDENTITY)"
	@echo "  make run             qsh --host=$(HOST) --tpm-path=$(TPM_HOME)/$(IDENTITY)"
	@echo
	@echo "Overridable: IDENTITY=$(IDENTITY) HOST=$(HOST) PREFIX=$(PREFIX) ETC_DIR=$(ETC_DIR) TPM_HOME=$(TPM_HOME)"

check:
	@test -x ./check-qsh-deps.py || { echo "missing ./check-qsh-deps.py"; exit 1; }
	@test -x ./qsh               || chmod +x ./qsh
	@./check-qsh-deps.py --binary ./qsh

install: check install-bin install-config install-tpm
	@echo
	@echo "Installed.  Try:  qsh --host=$(HOST) --tpm-path=$(TPM_HOME)/$(IDENTITY)"

install-bin:
	@test -f ./qsh || { echo "missing ./qsh in kit"; exit 1; }
	$(SUDO) $(INSTALL) -m 755 ./qsh $(BIN_DIR)/qsh
	@echo "installed $(BIN_DIR)/qsh"

# System-wide config used by qsh to find the MTC log server and
# the qshd port.  Without it, qsh falls back to localhost:8444 and
# the cosigner-pubkey fetch fails.  Refuses to overwrite a
# pre-existing /etc/postWolf/config (operator may have local edits).
#
# Also installs the Augeas Myconf lens that lets the read-config
# helper parse the file — the system libaugeas doesn't ship it.
# The lens is small and identical across installs; we just clobber
# any existing copy.
install-config:
	@test -f ./postWolf.config || { echo "missing ./postWolf.config in kit"; exit 1; }
	@test -f ./myconf.aug      || { echo "missing ./myconf.aug in kit"; exit 1; }
	@if [ -f $(ETC_DIR)/config ]; then \
	    echo "REFUSING: $(ETC_DIR)/config already exists."; \
	    echo "Inspect it; if it's safe to replace, run 'make uninstall' first or"; \
	    echo "merge the contents of ./postWolf.config in by hand."; \
	    exit 1; \
	fi
	$(SUDO) $(INSTALL) -d -m 755 $(ETC_DIR)
	$(SUDO) $(INSTALL) -m 644 ./postWolf.config $(ETC_DIR)/config
	$(SUDO) $(INSTALL) -d -m 755 $(LENS_DIR)
	$(SUDO) $(INSTALL) -m 644 ./myconf.aug $(LENS_DIR)/myconf.aug
	@echo "installed $(ETC_DIR)/config and $(LENS_DIR)/myconf.aug"

# Per-user identity install.  Refuses to overwrite an existing
# identity dir — back it up or `make uninstall` first.
install-tpm:
	@test -d ./TPM/$(IDENTITY) || { echo "missing ./TPM/$(IDENTITY)/ in kit"; exit 1; }
	@if [ -d $(TPM_HOME)/$(IDENTITY) ]; then \
	    echo "REFUSING: $(TPM_HOME)/$(IDENTITY) already exists."; \
	    echo "Back it up or run 'make uninstall' first."; \
	    exit 1; \
	fi
	@mkdir -p $(TPM_HOME)
	@chmod 700 $(TPM_HOME)
	@cp -a ./TPM/$(IDENTITY) $(TPM_HOME)/$(IDENTITY)
	@chmod 700 $(TPM_HOME)/$(IDENTITY)
	@chmod 600 $(TPM_HOME)/$(IDENTITY)/private_key.pem
	@echo "installed $(TPM_HOME)/$(IDENTITY)/"

# Decode the bundled mqc(1) envelope into ~/.mqc-master-password so
# qsh --bypass-src-ip can build MQCBYPASS tokens locally.  Optional;
# requires the same shared mqc(1) password cached on this host as on
# the kit-build host.  Refuses to overwrite an existing password file.
install-bypass:
	@test -f ./mqc-master-password.enc || { \
	    echo "missing ./mqc-master-password.enc — the kit was built without it"; \
	    echo "(server's /etc/postWolf/config-secret unreadable at build time, or mqc(1) absent)"; \
	    exit 1; \
	}
	@test -x $(MQC_BIN) || { echo "ERROR: mqc(1) not installed at $(MQC_BIN)"; exit 1; }
	@if [ -f $(BYPASS_PW) ]; then \
	    echo "REFUSING: $(BYPASS_PW) already exists.  Inspect / back up first."; \
	    exit 1; \
	fi
	@$(MQC_BIN) --decode --file ./mqc-master-password.enc --out $(BYPASS_PW)
	@chmod 600 $(BYPASS_PW)
	@echo "installed $(BYPASS_PW) (mode 0600)"

uninstall:
	-$(SUDO) rm -f $(BIN_DIR)/qsh $(ETC_DIR)/config $(LENS_DIR)/myconf.aug
	-$(SUDO) rmdir --ignore-fail-on-non-empty $(ETC_DIR) 2>/dev/null || true
	-rm -rf $(TPM_HOME)/$(IDENTITY)
	@echo "removed $(BIN_DIR)/qsh, $(ETC_DIR)/config, $(LENS_DIR)/myconf.aug, and $(TPM_HOME)/$(IDENTITY)/"
	@echo "(install-bypass artefact $(BYPASS_PW) is NOT removed; rm by hand if desired)"

run:
	qsh --host=$(HOST) --tpm-path=$(TPM_HOME)/$(IDENTITY)
