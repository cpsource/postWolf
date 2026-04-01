/* mtc_store.h — File-based persistence for MTC CA server */

#ifndef MTC_STORE_H
#define MTC_STORE_H

#include "mtc_merkle.h"
#include <json-c/json.h>

/* Maximum certificates and landmarks */
#define MTC_MAX_CERTS      10000
#define MTC_MAX_LANDMARKS  1000
#define MTC_LANDMARK_INTERVAL 16

typedef struct {
    char             data_dir[512];

    /* CA identity */
    char             ca_name[64];
    char             log_id[64];
    char             cosigner_id[64];

    /* Ed25519 CA key (DER) */
    uint8_t          ca_priv_key[128];
    int              ca_priv_key_sz;
    uint8_t          ca_pub_key[32];
    int              ca_pub_key_sz;

    /* Merkle tree */
    MtcMerkleTree    tree;

    /* Issued certificates (JSON strings, indexed by log index) */
    struct json_object **certificates;
    int              cert_count;
    int              cert_capacity;

    /* Checkpoints */
    struct json_object **checkpoints;
    int              checkpoint_count;

    /* Landmarks (tree sizes) */
    int              landmarks[MTC_MAX_LANDMARKS];
    int              landmark_count;
} MtcStore;

int  mtc_store_init(MtcStore *store, const char *data_dir,
                    const char *ca_name, const char *log_id);
void mtc_store_free(MtcStore *store);

/* Persist current state to data_dir */
int  mtc_store_save(MtcStore *store);

/* Load state from data_dir */
int  mtc_store_load(MtcStore *store);

/* Add a certificate entry to the log, return index */
int  mtc_store_add_entry(MtcStore *store, const uint8_t *entry, int entrySz);

/* Create a checkpoint */
struct json_object *mtc_store_checkpoint(MtcStore *store);

/* Cosign a subtree range with Ed25519 */
int  mtc_store_cosign(MtcStore *store, int start, int end,
                      uint8_t *sig_out, int *sig_sz);

/* Get CA public key PEM */
int  mtc_store_get_public_key_pem(MtcStore *store, char *out, int maxSz);

#endif
