/******************************************************************************
 * File:        mqc_encrypted.c
 * Purpose:     Encrypted-identity-mode handshake bodies for MQC.
 *
 * Description:
 *   Status as of Phase 7 commit 1: STUBS.  Both entry points return
 *   NULL with a clear MQC_SECURITY log line.  No production caller in
 *   the postWolf tree currently exercises encrypted mode; every MQC
 *   client uses mqc_connect (clear).
 *
 *   Phase 7 commit 2 will replace these stubs with the 4-frame
 *   encrypted-identity handshake (spec §7), restoring derive_early_keys
 *   from git history (commit 6b4c380b6 era) and porting the bodies to
 *   the post-Phase-1 transcript / HKDF-Extract+Expand / Finished /
 *   AAD architecture.
 *
 *   The dispatcher in mqc.c routes mqc_connect / mqc_accept here when
 *   ctx->encrypt_identity != 0.
 *
 * Created:     2026-05-03  (split out of mqc.c during Phase 7 commit 1)
 ******************************************************************************/

#include "mqc_internal.h"

#include <stdio.h>

mqc_conn_t *mqc_connect_encrypted(mqc_ctx_t *ctx, const char *host, int port)
{
    (void)ctx; (void)host; (void)port;
    MQC_SECURITY("mqc_connect_encrypted is not implemented; "
                 "Phase 7 commit 2 restores it.  Use mqc_connect "
                 "(clear mode) for now.");
    return NULL;
}

mqc_conn_t *mqc_accept_encrypted(mqc_ctx_t *ctx, int listen_fd)
{
    (void)ctx; (void)listen_fd;
    MQC_SECURITY("mqc_accept_encrypted is not implemented; "
                 "Phase 7 commit 2 restores it.  Use mqc_accept "
                 "(clear mode) for now.");
    return NULL;
}
