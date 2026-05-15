I reviewed the uploaded `tls13.c`. Not a full certification audit, but I **would not call this professional-security-ready yet**. Main findings: 

**High-risk issues**

1. **Null deref risk before checks**
   `Tls13_Exporter()` dereferences `ssl->options` before checking `ssl != NULL`. Several HKDF/ECH paths also assume `ssl->hsHashes`, `ssl->hsHashesEch`, `ssl->arrays`, or `ssl->ctx` exist.

2. **ECH acceptance bounds are weak**
   `EchCheckAcceptance()` uses:

   ```c
   input + acceptOffset
   ```

   without clearly proving `acceptOffset >= 0` and `acceptOffset + 8 <= helloSz + headerSz`. A malformed ServerHello/HRR could push this into out-of-bounds read territory.

3. **ECH length arithmetic can underflow**
   In `EchCalcAcceptance()`:

   ```c
   helloSz + headerSz - (acceptOffset + ECH_ACCEPT_CONFIRMATION_SZ)
   ```

   If `acceptOffset` is bad, this becomes negative, then may be passed into APIs expecting unsigned sizes.

4. **ECH write path can write out of bounds**
   `EchWriteAcceptance()` writes to:

   ```c
   output + acceptOffset
   ```

   with no local validation that `acceptOffset` points inside the ServerHello/HRR confirmation field.

5. **Exporter API missing lower-bound/null validation**
   `Tls13_Exporter()` checks upper bounds but not:

   ```c
   ssl == NULL
   out == NULL when outLen > 0
   label == NULL when labelLen > 0
   context == NULL when contextLen > 0
   ssl->arrays->exporterSecret initialized
   ```

   That is a professional-audit finding.

6. **Negative-to-unsigned casts**
   `DeriveKeyMsg()` casts `msgLen` and `outputLen` to `word32`. Today callers often pass `NULL, 0` or `-1`, but the function itself does not enforce:

   ```c
   msgLen >= 0
   outputLen == -1 || outputLen >= 0
   ```

   That is fragile.

7. **Certificate chain work is mostly delegated**
   `DoTls13Certificate()` calls `ProcessPeerCerts()`, so the full-chain review cannot be completed from this file alone. The important questions are inside `ProcessPeerCerts`: hostname/SAN validation, EKU, KU, CA basic constraints, path length, time validity, revocation policy, trust anchor selection, and whether ECH inner SNI is what gets authenticated.

**ECH-specific concern**

Your ECH transcript swapping is clever, but risky. The code temporarily swaps `ssl->hsHashes` with `ssl->hsHashesEch`, frees one transcript, and sometimes promotes the ECH transcript. That needs very tight invariant checks. Add assertions/guards before every swap:

```c
if (ssl == NULL || ssl->arrays == NULL ||
    ssl->hsHashes == NULL || ssl->hsHashesEch == NULL ||
    input == NULL || acceptExpanded == NULL)
    return BAD_FUNC_ARG;

if (helloSz < 0 || acceptOffset < 0)
    return BUFFER_ERROR;

if ((word32)acceptOffset + ECH_ACCEPT_CONFIRMATION_SZ >
        (word32)helloSz + (word32)headerSz)
    return BUFFER_ERROR;
```

**Bottom line:** promising, but I would first harden null checks, ECH offset/length validation, and signed arithmetic before exposing this to hostile network input.

