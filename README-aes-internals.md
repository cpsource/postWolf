# AES Internals

Reference notes on how AES actually works under the hood — the
finite field it lives in, the S-box construction, the four round
operations, and why the designers picked the constants they did.
Companion to `README-keys-etc.md` (which is a more informal
running commentary on cipher topics) and `README-ml-kem.md`
(post-quantum key exchange).

## The field: GF(2^8)

AES does all its byte-level arithmetic in the **Galois field** with
256 elements, denoted **GF(2^8)**. Addition is bitwise XOR;
multiplication is polynomial multiplication modulo an irreducible
polynomial of degree 8:

```
m(x) = x^8 + x^4 + x^3 + x + 1
```

- Hex: **`0x11B`** (9-bit value `1 0001 1011`).
- Often written as **`0x1B`** with the leading bit implicit — the
  reduction step only consults bit 8 during carry-out.
- Called the **Rijndael polynomial**, after AES's pre-NIST name.

Why `m(x)` specifically:

1. **Irreducible.** Can't be factored over GF(2), so `GF(2)[x] / m(x)`
   is an actual field (every nonzero element has a multiplicative
   inverse).
2. **Sparse.** Only five nonzero terms → shift-XOR reduction after
   multiplication is cheap.
3. **Good bit-mixing.** The specific coefficients yield S-box
   outputs with strong diffusion and small bit-correlation across
   inputs.

The same field is used by:
- The S-box's multiplicative-inverse step (below)
- **MixColumns** (byte-level matrix multiply in GF(2^8))
- The **key schedule** (RotWord + SubWord + Rcon)

One polynomial is the arithmetic foundation of the whole cipher.

## The S-box — two polynomials in sequence

AES's S-box is not a random lookup table. It's a composition of
two explicitly-chosen algebraic operations:

### Step 1: multiplicative inverse in GF(2^8)

```
s(x) = x^(-1)  in GF(2^8)     (with 0 → 0 by convention)
```

This is the nonlinear piece. Pure inversion would leave two fixed
points (0 and 1 both invert to themselves), and that's cryptographically
poor — step 2 kills those.

### Step 2: affine transformation over GF(2)

Each byte is treated as a bit-vector and transformed by:

```
y(x) = a(x) · s(x) mod (x^8 + 1)   XOR   c
```

where:

| Quantity | Value | Hex |
|---|---|---|
| `a(x)` | `x^4 + x^3 + x^2 + x + 1` | `0x1F` |
| `c`    | `01100011₂` | `0x63` |

Note the reduction polynomial here is `x^8 + 1`, **different from**
the field polynomial `x^8 + x^4 + x^3 + x + 1`:

- `x^8 + 1` factors as `(x + 1)^8` over GF(2) — it's **reducible**,
  so this step is *not* in a field; it's a linear operation over
  the vector space GF(2)^8.
- Equivalently, multiplication by `a(x) mod (x^8 + 1)` is a fixed
  8×8 binary matrix applied to the bit-vector.

The matrix form (each row is a rotation of the pattern
`1 0 0 0 1 1 1 1`):

```
          ⎡ 1 0 0 0 1 1 1 1 ⎤
          ⎢ 1 1 0 0 0 1 1 1 ⎥
          ⎢ 1 1 1 0 0 0 1 1 ⎥
A   =     ⎢ 1 1 1 1 0 0 0 1 ⎥    b = 0x63
          ⎢ 1 1 1 1 1 0 0 0 ⎥
          ⎢ 0 1 1 1 1 1 0 0 ⎥
          ⎢ 0 0 1 1 1 1 1 0 ⎥
          ⎣ 0 0 0 1 1 1 1 1 ⎦
```

### Why the constants `0x1F` and `0x63`

- **Kill fixed points.** After step 1 alone, `S(0) = 0` and
  `S(1) = 1`. The affine step shifts every output so that no
  byte `x` satisfies `S(x) = x` AND no byte satisfies
  `S(x) XOR x = 0xFF` (the "opposite fixed point" property).
- **Maximise algebraic complexity.** Expressing the S-box
  as a polynomial over GF(2^8) requires nine nonzero terms
  (degree 254); the affine step is what produces that
  high-degree expression. Without it the S-box would be
  linear-like in the field, which is crypto-fatal.

## The four round operations

Each AES round is a fixed sequence:

```
state ← SubBytes(state)        -- byte-level nonlinear step (the S-box)
state ← ShiftRows(state)       -- row-level byte permutation
state ← MixColumns(state)      -- column-level linear diffusion (omit in final round)
state ← AddRoundKey(state, K)  -- XOR with the round key
```

### SubBytes

Apply the S-box to each of the 16 bytes independently. This is
where GF(2^8) inversion happens.

### ShiftRows

Cyclic left-shift of each row in the 4×4 state:
- Row 0: no shift
- Row 1: shift by 1
- Row 2: shift by 2
- Row 3: shift by 3

Purely a permutation — no arithmetic. Its job is to spread
adjacent-byte correlation across columns before MixColumns.

### MixColumns

Treat each column as a degree-3 polynomial over GF(2^8) and
multiply by:

```
c(x) = 3x^3 + x^2 + x + 2      mod (x^4 + 1)
```

(Reduction is `x^4 + 1`, a length-4 analogue of the S-box's
`x^8 + 1` — again reducible, a linear operation, not a field
operation.)

In byte-matrix form per column:

```
⎡ 02 03 01 01 ⎤   ⎡ s0 ⎤
⎢ 01 02 03 01 ⎥ · ⎢ s1 ⎥
⎢ 01 01 02 03 ⎥   ⎢ s2 ⎥
⎣ 03 01 01 02 ⎦   ⎣ s3 ⎦
```

Multiplication by `02` is a 1-bit left shift plus conditional XOR
with `0x1B` on overflow — the carry of `m(x) = 0x11B`.
Multiplication by `03` is `02` XOR the identity.

This operation is **MDS (Maximum Distance Separable)**: any single
byte change affects all four output bytes, maximising diffusion.

### AddRoundKey

XOR the state with the 128-bit round key. No field arithmetic.

## The key schedule

For AES-128 the 128-bit key is expanded into 11 round keys
(one initial `AddRoundKey` before round 1, plus one after each
of the 10 rounds). The schedule uses:

1. **RotWord** — cyclic byte rotation on a 4-byte word.
2. **SubWord** — apply the S-box to each byte.
3. **Rcon** — XOR with the round constant `2^(i-1) mod m(x)` for
   round `i`:

```
Rcon[1] = 0x01
Rcon[2] = 0x02
Rcon[3] = 0x04
…
Rcon[9] = 0x1B     (where the reduction polynomial kicks in)
Rcon[10] = 0x36
```

The same GF(2^8) field carries through — `Rcon[9]` is exactly the
low 8 bits of `m(x)` minus the leading `x^8` term.

## Round counts per key size

| Cipher | Key bits | Rounds | Round keys generated |
|---|---|---|---|
| AES-128 | 128 | 10 | 11 |
| AES-192 | 192 | 12 | 13 |
| AES-256 | 256 | 14 | 15 |

Each round = 4 operations × 16 bytes on the state. One 16-byte
block through AES-128 does **160 S-box lookups** (10 × 16) plus
roughly 40 more during key-schedule SubWord — all with the same
table, which is why S-box precomputation is so fast.

## How this shows up in postWolf

- `mtc-keymaster/server2/c/mtc_crypt.c` uses `wc_AesCbcEncrypt`,
  which is full 10-round AES-128 (160 S-box lookups per block).
  No single-round experiments live in this tree.
- `socket-level-wrapper-MQC/mqc.c` uses `wc_AesGcmEncrypt` with
  AES-256, so 14-round AES (224 S-box lookups per block).
- None of the code touches the field polynomial or affine matrix
  directly — those live in wolfCrypt's `wolfcrypt/src/aes.c`, which
  implements the tables (or AES-NI intrinsics on supported CPUs).

## Further reading

- FIPS 197 (the AES standard): the canonical reference.
- Daemen & Rijmen, *The Design of Rijndael* (Springer, 2002):
  the designers' own book, explains why `m(x)` and the affine
  constants were chosen.
- `wolfcrypt/src/aes.c`: tables at top of file, the round function
  at `AesEncrypt_C()`.
