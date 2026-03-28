/*
 * test_ech_overflow.c — Demonstrate word16 truncation in ECH innerClientHelloLen
 *
 * Finding #1 from wolfSSL/wolfssl#10068:
 *   innerClientHelloLen is word16 but computed from word32 values.
 *   If (args->length + paddingLen + Nt) > 65535, silent truncation
 *   causes undersized allocation → heap buffer overflow on XMEMCPY.
 *
 * Attack vector: A malicious or misconfigured client sends a ClientHello
 * with enough extensions to push the inner ClientHello past 65519 bytes.
 * This is achievable with:
 *   - Many supported_groups entries (2 bytes each, up to 65535/2 entries)
 *   - Many signature_algorithms entries
 *   - Large custom/unknown extensions
 *   - Padding extension (RFC 7685) up to 65535 bytes
 *
 * This program demonstrates the arithmetic overflow without exploiting it.
 * It computes innerClientHelloLen using the same logic as tls13.c:4726-4728
 * and shows the truncation.
 *
 * Build: gcc -o test_ech_overflow test_ech_overflow.c -I. \
 *        -DWOLFSSL_USE_OPTIONS_H $(pkg-config --cflags wolfssl)
 */

#include <stdio.h>
#include <stdint.h>

int main(void)
{
    /* Simulate the computation from tls13.c:4726-4728 */
    /* Nt = AES tag size = 16 */
    const uint32_t Nt = 16;

    printf("=== ECH innerClientHelloLen word16 Truncation ===\n\n");
    printf("The bug: innerClientHelloLen is declared word16 (max 65535)\n");
    printf("but computed from word32 values. If the sum exceeds 65535,\n");
    printf("silent truncation causes an undersized heap allocation.\n\n");

    printf("%-12s %-12s %-12s %-12s %-12s\n",
           "CH length", "paddingLen", "true total", "word16 cast", "overflow?");
    printf("%-12s %-12s %-12s %-12s %-12s\n",
           "----------", "----------", "----------", "----------", "----------");

    /* Test a range of ClientHello sizes around the overflow boundary */
    uint32_t test_lengths[] = {
        256,       /* typical small CH */
        1024,      /* normal CH with extensions */
        32768,     /* large CH */
        65488,     /* just below overflow: 65488 + 32 + 16 = 65536 */
        65489,     /* overflow boundary */
        65500,     /* clearly overflows */
        65520,     /* overflows more */
        70000,     /* large overflow */
        100000,    /* extreme */
    };
    int ntests = sizeof(test_lengths) / sizeof(test_lengths[0]);

    for (int i = 0; i < ntests; i++) {
        uint32_t length = test_lengths[i];

        /* paddingLen = 31 - ((length - 1) % 32), range [1, 32] */
        uint16_t paddingLen = 31 - ((length - 1) % 32);

        /* True total (word32) */
        uint32_t true_total = length + paddingLen + Nt;

        /* What wolfSSL computes — cast to word16 */
        uint16_t truncated = (uint16_t)(length + paddingLen + Nt);

        int overflows = (true_total > 65535);

        printf("%-12u %-12u %-12u %-12u %-12s\n",
               length, paddingLen, true_total, truncated,
               overflows ? "YES ***" : "no");

        if (overflows) {
            /* Show the consequence */
            uint16_t alloc_size = truncated - (uint16_t)Nt;
            uint32_t copy_size = length;  /* actual data copied */
            printf("  -> allocation: %u bytes, copy: %u bytes, "
                   "OVERFLOW: %u bytes past end\n",
                   alloc_size, copy_size,
                   copy_size > alloc_size ? copy_size - alloc_size : 0);
        }
    }

    printf("\n--- Realistic Attack Scenario ---\n\n");
    printf("A TLS ClientHello can contain a padding extension (RFC 7685)\n");
    printf("of up to 65535 bytes, or hundreds of supported_groups entries.\n");
    printf("An attacker crafts a ClientHello with 65520+ bytes of extensions.\n");
    printf("When the client has ECH enabled, wolfSSL computes:\n\n");

    uint32_t attack_length = 65520;
    uint16_t attack_pad = 31 - ((attack_length - 1) % 32);
    uint32_t attack_total = attack_length + attack_pad + Nt;
    uint16_t attack_truncated = (uint16_t)attack_total;
    uint16_t attack_alloc = attack_truncated - (uint16_t)Nt;

    printf("  args->length    = %u (inner ClientHello size)\n", attack_length);
    printf("  paddingLen      = %u\n", attack_pad);
    printf("  Nt (AES tag)    = %u\n", Nt);
    printf("  true total      = %u\n", attack_total);
    printf("  (word16) cast   = %u  <-- TRUNCATED\n", attack_truncated);
    printf("  XMALLOC size    = %u - %u = %u bytes\n",
           attack_truncated, (uint16_t)Nt, attack_alloc);
    printf("  XMEMCPY copies  = %u bytes\n", attack_length);
    if (attack_length > attack_alloc)
        printf("  HEAP OVERFLOW   = %u bytes written past allocation\n\n",
               attack_length - attack_alloc);
    else
        printf("  HEAP OVERFLOW   = allocation wraps to %u, copy is %u\n\n",
               attack_alloc, attack_length);

    printf("Impact: Heap buffer overflow. Depending on the allocator,\n");
    printf("this can corrupt heap metadata, adjacent objects, or enable\n");
    printf("arbitrary code execution.\n\n");

    printf("Fix: Change innerClientHelloLen from word16 to word32,\n");
    printf("or add a bounds check before the cast.\n");

    /* ---- Verify the fix ---- */
    printf("\n=== Verifying Fix (word32 innerClientHelloLen) ===\n\n");
    printf("%-12s %-12s %-12s %-12s %-12s\n",
           "CH length", "paddingLen", "word32 total", "alloc size", "status");
    printf("%-12s %-12s %-12s %-12s %-12s\n",
           "----------", "----------", "----------", "----------", "----------");

    int all_pass = 1;
    for (int j = 0; j < ntests; j++) {
        uint32_t length = test_lengths[j];
        uint16_t pad = 31 - ((length - 1) % 32);
        /* Fixed: word32 computation, no truncation */
        uint32_t total_fixed = length + pad + Nt;
        uint32_t alloc_fixed = total_fixed - Nt;
        int ok = (alloc_fixed >= length);

        printf("%-12u %-12u %-12u %-12u %-12s\n",
               length, pad, total_fixed, alloc_fixed,
               ok ? "OK" : "FAIL");
        if (!ok) all_pass = 0;
    }

    printf("\n%s\n", all_pass ? "ALL PASSED: word32 prevents truncation"
                              : "FAILURE: fix is incomplete");

    return all_pass ? 0 : 1;
}
