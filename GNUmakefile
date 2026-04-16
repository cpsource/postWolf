# GNUmakefile — top-level build for wolfGuard tools
#
# Builds the socket-level wrappers (SLC, MQC) and MTC keymaster
# tools (server, show-tpm, bootstrap_ca, bootstrap_leaf).
#
# The wolfGuard library itself is built separately via autotools:
#   ./configure.sh && make -f Makefile && sudo make -f Makefile install && sudo ldconfig
#
# Usage:
#   make                 Build SLC, MQC, and all MTC tools
#   sudo make install    Install tools to /usr/local/bin and run ldconfig
#   make clean           Clean all build artifacts

SLC_DIR = socket-level-wrapper
MQC_DIR = socket-level-wrapper-MQC
MTC_DIR = mtc-keymaster/server/c

.PHONY: all install clean slc mqc mtc install-lib

all: slc mqc mtc

# Socket-level wrapper (TLS)
slc:
	$(MAKE) -C $(SLC_DIR)

# Socket-level wrapper (MQC / post-quantum)
mqc:
	$(MAKE) -C $(MQC_DIR)

# MTC keymaster (server + tools) — depends on slc + mqc libraries
mtc: slc mqc
	$(MAKE) -C $(MTC_DIR)

# Install wolfGuard library (autotools) + ldconfig
install-lib:
	$(MAKE) -f Makefile install
	ldconfig

# Install tools to /usr/local/bin + refresh ldconfig
install: all
	ldconfig
	$(MAKE) -C $(MTC_DIR) install

clean:
	$(MAKE) -C $(SLC_DIR) clean
	$(MAKE) -C $(MQC_DIR) clean
	$(MAKE) -C $(MTC_DIR) clean
