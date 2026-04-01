#!/usr/bin/env python3
"""
mtc_cert_gen.py — Generate an X.509 certificate with MTC proof signature.

Fetches an MTC certificate from the CA/Log server, generates a fresh EC-P256
key pair, and wraps everything into an X.509 DER/PEM certificate with:
  - signatureAlgorithm = id-alg-mtcProof (OID 1.3.6.1.4.1.44363.47.0)
  - signatureValue = serialized MtcProof (start, end, pathCount, path, subtreeHash)

The resulting cert + key can be loaded by wolfSSL for TLS handshakes where
the peer verifies via Merkle inclusion proof instead of CA chain.

Usage:
    python3 mtc_cert_gen.py [options]

    --ca-url URL       MTC CA server (default: http://localhost:8443)
    --index N          Certificate index to wrap (default: 1)
    --out-cert FILE    Output certificate PEM (default: mtc-cert.pem)
    --out-key FILE     Output private key PEM (default: mtc-key.pem)
    --out-ca FILE      Output dummy CA cert PEM (default: mtc-ca.pem)
"""

import argparse
import json
import struct
import sys
import urllib.request
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ObjectIdentifier
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption, PublicFormat
)

# MTC Proof OID: 1.3.6.1.4.1.44363.47.0 (experimental)
MTC_PROOF_OID = ObjectIdentifier("1.3.6.1.4.1.44363.47.0")


def fetch_json(url):
    """Fetch JSON from a URL."""
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode())


def serialize_mtc_proof(cert_json):
    """Serialize MTC proof data into the wire format that wolfSSL expects.

    Wire format (matches wc_MtcParseProof):
        start:          8 bytes (big-endian uint64)
        end:            8 bytes (big-endian uint64)
        pathCount:      2 bytes (big-endian uint16)
        inclusionPath:  pathCount * 32 bytes
        subtreeHash:    32 bytes
    """
    sc = cert_json["standalone_certificate"]

    start = sc["subtree_start"]
    end = sc["subtree_end"]
    proof_hashes = sc["inclusion_proof"]  # list of hex strings
    subtree_hash = sc["subtree_hash"]     # hex string

    path_count = len(proof_hashes)

    cert_index = sc["index"]

    buf = struct.pack(">Q", cert_index)   # cert index (8 bytes)
    buf += struct.pack(">QQ", start, end)
    buf += struct.pack(">H", path_count)
    for h in proof_hashes:
        buf += bytes.fromhex(h)
    buf += bytes.fromhex(subtree_hash)

    return buf


def build_x509_with_mtc_proof(subject_name, key, mtc_proof_bytes,
                               not_before_ts, not_after_ts):
    """Build an X.509 certificate with MTC proof as the signature.

    Since the cryptography library won't let us set a custom signature
    algorithm OID directly, we build the DER manually:
      TBSCertificate || signatureAlgorithm(mtcProof) || signatureValue(proof)
    """
    from cryptography.x509 import CertificateBuilder, Name, NameAttribute
    from cryptography.x509.oid import NameOID

    # Build a self-signed cert first to get valid TBS DER structure,
    # then replace the signature parts.
    not_before = datetime.fromtimestamp(not_before_ts, tz=timezone.utc)
    not_after = datetime.fromtimestamp(not_after_ts, tz=timezone.utc)

    builder = (
        CertificateBuilder()
        .subject_name(Name([
            NameAttribute(NameOID.COMMON_NAME, subject_name),
        ]))
        .issuer_name(Name([
            NameAttribute(NameOID.COMMON_NAME, "MTC Proof Issuer"),
        ]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    # Sign with ECDSA to get a valid structure, then we'll patch the DER
    temp_cert = builder.sign(key, hashes.SHA256(), default_backend())
    temp_der = temp_cert.public_bytes(Encoding.DER)

    # Now build the real DER with MTC proof OID and signature
    patched_der = patch_cert_signature(temp_der, mtc_proof_bytes)
    return patched_der


def encode_oid(oid_str):
    """Encode an OID string to DER bytes (just the value, no tag/length)."""
    parts = [int(x) for x in oid_str.split(".")]
    result = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        if p < 128:
            result += bytes([p])
        else:
            # Base-128 encoding
            enc = []
            val = p
            enc.append(val & 0x7f)
            val >>= 7
            while val > 0:
                enc.append((val & 0x7f) | 0x80)
                val >>= 7
            result += bytes(reversed(enc))
    return result


def der_length(length):
    """Encode a DER length field."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xff, length & 0xff])
    else:
        return bytes([0x83, (length >> 16) & 0xff,
                      (length >> 8) & 0xff, length & 0xff])


def extract_tbs(cert_der):
    """Extract the TBSCertificate from a DER-encoded certificate.

    Certificate ::= SEQUENCE {
        tbsCertificate       TBSCertificate,      -- SEQUENCE
        signatureAlgorithm   AlgorithmIdentifier,  -- SEQUENCE
        signatureValue       BIT STRING
    }
    """
    # Skip outer SEQUENCE tag + length
    idx = 0
    assert cert_der[idx] == 0x30  # SEQUENCE
    idx += 1
    if cert_der[idx] & 0x80:
        num_len_bytes = cert_der[idx] & 0x7f
        idx += 1 + num_len_bytes
    else:
        idx += 1

    # Now at TBSCertificate (a SEQUENCE)
    tbs_start = idx
    assert cert_der[idx] == 0x30
    idx += 1
    if cert_der[idx] & 0x80:
        num_len_bytes = cert_der[idx] & 0x7f
        tbs_len_bytes = cert_der[idx:idx + 1 + num_len_bytes]
        tbs_len = int.from_bytes(cert_der[idx + 1:idx + 1 + num_len_bytes], 'big')
        idx += 1 + num_len_bytes
    else:
        tbs_len = cert_der[idx]
        idx += 1

    tbs_end = idx + tbs_len
    tbs_der = cert_der[tbs_start:tbs_end]
    return tbs_der


def patch_tbs_sig_alg(tbs_der):
    """Replace the signatureAlgorithm inside TBSCertificate with MTC proof OID.

    TBSCertificate ::= SEQUENCE {
        version          [0] EXPLICIT ...,
        serialNumber     INTEGER,
        signature        AlgorithmIdentifier,  <-- this one
        issuer           ...
        ...
    }
    """
    # Parse into the TBS SEQUENCE to find the signature AlgorithmIdentifier
    # It's the 3rd field: version [0], serialNumber, signature
    idx = 0
    assert tbs_der[idx] == 0x30  # SEQUENCE
    idx += 1
    # Skip length
    if tbs_der[idx] & 0x80:
        n = tbs_der[idx] & 0x7f
        idx += 1 + n
    else:
        idx += 1

    # Skip version [0] EXPLICIT
    if tbs_der[idx] == 0xa0:
        idx += 1
        vlen = tbs_der[idx]; idx += 1
        idx += vlen

    # Skip serialNumber (INTEGER)
    assert tbs_der[idx] == 0x02
    idx += 1
    if tbs_der[idx] & 0x80:
        n = tbs_der[idx] & 0x7f
        slen = int.from_bytes(tbs_der[idx+1:idx+1+n], 'big')
        idx += 1 + n
    else:
        slen = tbs_der[idx]; idx += 1
    idx += slen

    # Now at signatureAlgorithm (SEQUENCE)
    sig_alg_start = idx
    assert tbs_der[idx] == 0x30
    idx += 1
    if tbs_der[idx] & 0x80:
        n = tbs_der[idx] & 0x7f
        alen = int.from_bytes(tbs_der[idx+1:idx+1+n], 'big')
        idx += 1 + n
    else:
        alen = tbs_der[idx]; idx += 1
    sig_alg_end = idx + alen

    # Build replacement: SEQUENCE { OID(mtcProof) }
    oid_bytes = encode_oid("1.3.6.1.4.1.44363.47.0")
    new_alg = bytes([0x06]) + der_length(len(oid_bytes)) + oid_bytes
    new_alg_seq = bytes([0x30]) + der_length(len(new_alg)) + new_alg

    # Splice it in
    patched = tbs_der[:sig_alg_start] + new_alg_seq + tbs_der[sig_alg_end:]

    # Fix the outer SEQUENCE length
    inner = patched[1:]
    # Skip old length encoding
    if patched[1] & 0x80:
        n = patched[1] & 0x7f
        inner = patched[2 + n:]
    else:
        inner = patched[2:]

    patched = bytes([0x30]) + der_length(len(inner)) + inner
    return patched


def patch_cert_signature(cert_der, mtc_proof_bytes):
    """Replace the signature algorithm and value in a DER certificate.

    Patches BOTH the TBS inner signatureAlgorithm AND the outer one.
    Rebuilds: SEQUENCE { tbs(patched), sigAlg(mtcProof), sigVal(proof) }
    """
    tbs_der = extract_tbs(cert_der)

    # Patch the TBS signatureAlgorithm too
    tbs_der = patch_tbs_sig_alg(tbs_der)

    # Build signatureAlgorithm: SEQUENCE { OID }
    oid_bytes = encode_oid("1.3.6.1.4.1.44363.47.0")
    sig_alg = (bytes([0x06]) + der_length(len(oid_bytes)) + oid_bytes)
    sig_alg_seq = bytes([0x30]) + der_length(len(sig_alg)) + sig_alg

    # Build signatureValue: BIT STRING (0x03) with 0 unused bits
    sig_bits = bytes([0x00]) + mtc_proof_bytes  # 0 unused bits prefix
    sig_val = bytes([0x03]) + der_length(len(sig_bits)) + sig_bits

    # Rebuild outer SEQUENCE
    inner = tbs_der + sig_alg_seq + sig_val
    cert_new = bytes([0x30]) + der_length(len(inner)) + inner

    return cert_new


def main():
    parser = argparse.ArgumentParser(
        description="Generate X.509 certificate with MTC proof signature")
    parser.add_argument("--ca-url", default="http://localhost:8443",
                        help="MTC CA server URL")
    parser.add_argument("--index", type=int, default=1,
                        help="Certificate index to wrap")
    parser.add_argument("--out-cert", default="mtc-cert.pem",
                        help="Output certificate PEM file")
    parser.add_argument("--out-key", default="mtc-key.pem",
                        help="Output private key PEM file")
    parser.add_argument("--out-ca", default="mtc-ca.pem",
                        help="Output dummy CA cert PEM (for client trust)")
    args = parser.parse_args()

    # 1. Fetch MTC certificate from CA
    print(f"Fetching MTC certificate index={args.index} from {args.ca_url} ...")
    try:
        cert_json = fetch_json(f"{args.ca_url}/certificate/{args.index}")
    except Exception as e:
        print(f"Error fetching certificate: {e}", file=sys.stderr)
        return 1

    sc = cert_json.get("standalone_certificate")
    if not sc:
        print(f"No standalone_certificate in response", file=sys.stderr)
        return 1

    tbs = sc["tbs_entry"]
    subject = tbs["subject"]
    not_before = tbs["not_before"]
    not_after = tbs["not_after"]

    print(f"  Subject:    {subject}")
    print(f"  Not before: {datetime.fromtimestamp(not_before, tz=timezone.utc)}")
    print(f"  Not after:  {datetime.fromtimestamp(not_after, tz=timezone.utc)}")
    print(f"  Proof path: {len(sc['inclusion_proof'])} hashes")
    print(f"  Subtree:    [{sc['subtree_start']}, {sc['subtree_end']})")
    print(f"  Cosigs:     {len(sc.get('cosignatures', []))}")

    # 2. Serialize MTC proof
    print("\nSerializing MTC proof ...")
    mtc_proof = serialize_mtc_proof(cert_json)
    print(f"  Proof size: {len(mtc_proof)} bytes")

    # 3. Generate fresh EC-P256 key pair
    print("Generating EC-P256 key pair ...")
    key = ec.generate_private_key(ec.SECP256R1(), default_backend())

    # 4. Build X.509 certificate with MTC proof signature
    print("Building X.509 certificate with MTC proof OID ...")
    cert_der = build_x509_with_mtc_proof(subject, key, mtc_proof,
                                          not_before, not_after)

    # 5. Convert to PEM
    import base64
    cert_b64 = base64.encodebytes(cert_der).decode()
    cert_pem = f"-----BEGIN CERTIFICATE-----\n{cert_b64}-----END CERTIFICATE-----\n"

    # 6. Write output files
    with open(args.out_cert, "w") as f:
        f.write(cert_pem)
    print(f"  Wrote certificate: {args.out_cert}")

    key_pem = key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL,
                                 NoEncryption())
    with open(args.out_key, "wb") as f:
        f.write(key_pem)
    print(f"  Wrote private key: {args.out_key}")

    # 7. Write a dummy "CA" cert — actually the same cert, since wolfSSL
    #    client needs a CA file for verify. With MTC, the proof IS the trust,
    #    so the CA cert is just a placeholder.
    with open(args.out_ca, "w") as f:
        f.write(cert_pem)
    print(f"  Wrote CA cert:     {args.out_ca}")

    print(f"\nDone. Use with QUIC+MTC server:")
    print(f"  ./quic_mtc_server -c {args.out_cert} -k {args.out_key}")
    print(f"  ./quic_mtc_client -A {args.out_ca}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
