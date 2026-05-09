/*
 * fips-framework/tools/c/config.h — last-resort defaults for the FIPS
 * client tools.
 *
 * Per the project's "no hardcoded ports anywhere" rule, every port the
 * tools talk to comes from /etc/postWolf/config (url-server,
 * url-bootstrap, url-local).  The constants below are *only* consulted
 * when that config file is unreadable AND no -s / --server override is
 * supplied — i.e. broken-environment fallback, not normal operation.
 *
 * The #ifndef guards mean these never override values pulled in from
 * socket-level-wrapper-MQC/config.h, which is the canonical source for
 * MQC defaults.  The duplication exists so this directory's tools have
 * a sensible default even if a future build path doesn't transitively
 * pick up the MQC header.
 */

#ifndef FIPS_TOOLS_CONFIG_H
#define FIPS_TOOLS_CONFIG_H

#ifndef MQC_DEFAULT_SERVER_PORT
#define MQC_DEFAULT_SERVER_PORT 8446
#endif

#ifndef MQC_DEFAULT_SERVER_HOST
#define MQC_DEFAULT_SERVER_HOST "factsorlie.com"
#endif

#endif /* FIPS_TOOLS_CONFIG_H */
