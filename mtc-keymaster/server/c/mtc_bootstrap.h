/**
 * @file mtc_bootstrap.h
 * @brief DH bootstrap port for pre-TLS leaf enrollment.
 *
 * @details
 * Provides a separate TCP listener that performs X25519 key exchange
 * followed by AES-encrypted JSON enrollment.  This solves the
 * chicken-and-egg problem where a new client has no certificate to
 * connect via TLS.
 *
 * @date 2026-04-14
 */

#ifndef MTC_BOOTSTRAP_H
#define MTC_BOOTSTRAP_H

#include "mtc_store.h"

/**
 * @brief  Start the bootstrap listener on a background thread.
 *
 * @param[in] host   Bind address (NULL = "0.0.0.0").
 * @param[in] port   TCP port for the DH bootstrap listener.
 * @param[in] store  Initialised MTC store.  Must outlive the thread.
 *
 * @return  0 on success, -1 on failure (socket or thread creation).
 */
int mtc_bootstrap_start(const char *host, int port, MtcStore *store);

#endif /* MTC_BOOTSTRAP_H */
