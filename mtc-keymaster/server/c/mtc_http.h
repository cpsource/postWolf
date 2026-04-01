/* mtc_http.h — Minimal HTTP server for MTC CA */

#ifndef MTC_HTTP_H
#define MTC_HTTP_H

#include "mtc_store.h"

/* Start the HTTP server. Blocks until shutdown.
 * Returns 0 on clean exit, -1 on error. */
int mtc_http_serve(const char *host, int port, MtcStore *store);

#endif
