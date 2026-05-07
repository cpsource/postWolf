/**
 * @file mtc_tile.h
 * @brief Tile constants for the tiled Merkle tree (TODO #74 phase 3).
 *
 * @details
 * The Merkle tree is stored in fixed-height tiles in DB; only the top K
 * levels of inner-node hashes live in RAM.  This header pins the tile
 * geometry and the in-RAM cap.
 *
 * Tile coordinate system (Go `tlog` / CT v2 convention):
 *   A tile at (level, tile_index) covers the consecutive node range
 *     [tile_index * 2^TILE_HEIGHT, (tile_index + 1) * 2^TILE_HEIGHT)
 *   at that level.  Partial tiles (the rightmost incomplete tile at any
 *   level) store only `node_count` hashes in their `hashes` BYTEA.
 *
 * Sizing rationale:
 *   - TILE_HEIGHT = 8  → 256 nodes per tile, ~8 KB per tile-blob.
 *   - TOP_K_LEVELS = 12 → ~4096 inner nodes resident at any tree size,
 *     ~128 KB RAM regardless of N.
 *   - TILE_CACHE_DEFAULT_CAP = 1024 → ~8 MB LRU on the read path.
 *   Total Merkle-state RAM is bounded sub-30 MB at any tree size.
 *
 * @date 2026-05-07
 */

#ifndef MTC_TILE_H
#define MTC_TILE_H

#define MTC_TILE_HEIGHT          8
#define MTC_TILE_LEAF_COUNT      (1 << MTC_TILE_HEIGHT)   /* 256 */
#define MTC_TILE_HASH_SIZE       32
#define MTC_TILE_BYTES           (MTC_TILE_LEAF_COUNT * MTC_TILE_HASH_SIZE)

#define MTC_TOP_K_LEVELS         12
#define MTC_TOP_K_MAX_NODES      ((1 << MTC_TOP_K_LEVELS) - 1) /* 4095 */

#define MTC_TILE_CACHE_DEFAULT_CAP 1024

#endif
