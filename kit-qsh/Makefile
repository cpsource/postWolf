# kit-qsh — build a self-contained qsh deployment tarball.
#
# `make` produces deploy-qsh.tar.gz containing:
#
#   deploy-qsh/
#     Makefile              — recipient install/uninstall/run targets
#     README.md             — recipient-facing install + run guide
#     check-qsh-deps.py     — runtime-library audit script
#     qsh                   — qsh client binary (current build)
#     postWolf.config       — minimal /etc/postWolf/config template
#     myconf.aug            — Augeas lens that parses postWolf.config
#     TPM/factsorlie.com/   — bundled MTC identity (PEM keys + cert)
#
# WARNING: the bundled TPM directory contains the private key that
# authenticates as factsorlie.com.  Whoever holds this tarball can
# open MQC sessions as factsorlie.com.  Treat it accordingly.
#
# Build inputs (override on the command line if needed):
#   QSH_BIN    — qsh client binary to bundle      (default: /usr/local/bin/qsh)
#   TPM_DIR    — TPM identity dir to bundle       (default: $HOME/.TPM/factsorlie.com)
#   IDENTITY   — basename of TPM_DIR inside kit   (default: factsorlie.com)
#   DEPS_PY    — path to check-qsh-deps.py        (default: ../qsh/check-qsh-deps.py)
#   STAGING    — temporary staging directory      (default: deploy-qsh)
#   TARBALL    — output tarball filename          (default: deploy-qsh.tar.gz)

QSH_BIN  ?= /usr/local/bin/qsh
TPM_DIR  ?= $(HOME)/.TPM/factsorlie.com
IDENTITY ?= factsorlie.com
DEPS_PY  ?= ../qsh/check-qsh-deps.py
LENS_SRC ?= ../mtc-keymaster/read-config/myconf.aug
STAGING  ?= deploy-qsh
TARBALL  ?= deploy-qsh.tar.gz

.PHONY: all clean check-inputs

all: $(TARBALL)

check-inputs:
	@test -x "$(QSH_BIN)"     || { echo "ERROR: qsh binary not found at $(QSH_BIN) — build + install postWolf first"; exit 1; }
	@test -d "$(TPM_DIR)"     || { echo "ERROR: TPM dir not found at $(TPM_DIR)"; exit 1; }
	@test -f "$(DEPS_PY)"     || { echo "ERROR: check-qsh-deps.py not found at $(DEPS_PY)"; exit 1; }
	@test -f README.md        || { echo "ERROR: kit-qsh/README.md missing"; exit 1; }
	@test -f deploy.Makefile  || { echo "ERROR: kit-qsh/deploy.Makefile missing"; exit 1; }
	@test -f deploy-postWolf.config || { echo "ERROR: kit-qsh/deploy-postWolf.config missing"; exit 1; }
	@test -f "$(LENS_SRC)"    || { echo "ERROR: myconf.aug not found at $(LENS_SRC)"; exit 1; }

# Stage the kit contents, then tar.  The fips-receipts subdir under
# the TPM identity is for fips-manifest workflows, unrelated to qsh,
# so we exclude it to keep the tarball lean and to avoid leaking
# operational receipts to the recipient.
$(TARBALL): check-inputs
	@rm -rf $(STAGING) $(TARBALL)
	@mkdir -p $(STAGING)/TPM/$(IDENTITY)
	@cp README.md            $(STAGING)/README.md
	@cp deploy.Makefile      $(STAGING)/Makefile
	@cp deploy-postWolf.config $(STAGING)/postWolf.config
	@cp $(LENS_SRC)          $(STAGING)/myconf.aug
	@cp $(DEPS_PY)           $(STAGING)/check-qsh-deps.py
	@cp $(QSH_BIN)           $(STAGING)/qsh
	@cp $(TPM_DIR)/certificate.json $(STAGING)/TPM/$(IDENTITY)/certificate.json
	@cp $(TPM_DIR)/index            $(STAGING)/TPM/$(IDENTITY)/index
	@cp $(TPM_DIR)/private_key.pem  $(STAGING)/TPM/$(IDENTITY)/private_key.pem
	@cp $(TPM_DIR)/public_key.pem   $(STAGING)/TPM/$(IDENTITY)/public_key.pem
	@chmod 700 $(STAGING)/TPM/$(IDENTITY)
	@chmod 600 $(STAGING)/TPM/$(IDENTITY)/private_key.pem
	@chmod 755 $(STAGING)/qsh $(STAGING)/check-qsh-deps.py
	@tar -czf $(TARBALL) $(STAGING)
	@rm -rf $(STAGING)
	@printf "\nBuilt %s (%s) — bundled identity: %s\n" \
	  "$(TARBALL)" "$$(du -h $(TARBALL) | cut -f1)" "$(IDENTITY)"
	@tar -tzf $(TARBALL) | sed 's/^/  /'

clean:
	@rm -rf $(STAGING) $(TARBALL)
