/* mtc_http.h — Minimal HTTP-over-TLS server for MTC CA */

#ifndef MTC_HTTP_H
#define MTC_HTTP_H

#include "mtc_store.h"
#include "slc.h"

/* TLS configuration for the server */
typedef struct {
    const char *cert_file;       /* PEM server certificate */
    const char *key_file;        /* PEM server private key */
    const char *ca_file;         /* CA cert for client verification (optional) */
    const char *ech_public_name; /* ECH public name (e.g., "factsorlie.com"),
                                  * NULL to disable ECH */
} mtc_tls_cfg_t;

/* Start the HTTP-over-TLS server. Blocks until shutdown.
 * If tls_cfg is NULL, runs without TLS (plain HTTP, for testing only).
 * Returns 0 on clean exit, -1 on error. */
int mtc_http_serve(const char *host, int port, MtcStore *store,
                   const mtc_tls_cfg_t *tls_cfg);

#endif
