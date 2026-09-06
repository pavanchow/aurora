#!/usr/bin/env bash
#
# Regenerate the deterministic ECDSA P-256 test PKI used by the Aurora TLS
# authentication gate. The two ROOT CA private keys (root.key, uroot.key) are
# committed next to this script so the trusted root's public key is stable and
# can be embedded in the kernel trust store (kernel/src/trust_store.rs). Every
# other cert (intermediates, leaves) is generated fresh from those roots here.
#
# Produces, into the output directory given as $1:
#   trusted chain : root CA -> int CA -> leaf (CN=aurora.local, SAN DNS + IP 10.0.2.2)
#   wrong-name    : trusted int CA -> leaf (SAN DNS:wrong.example only, no IP match)
#   untrusted     : uroot CA -> uint CA -> uleaf (valid chain, root NOT in the store)
#   broken        : the trusted leaf with one signature byte flipped (bad signature)
#
# The server sends leaf+intermediate (never the root); Aurora anchors the top
# presented cert to the embedded root by verifying its signature with the root
# key. No wall-clock is available in Aurora, so -days is set far out and expiry
# is not enforced on the target (documented in DESIGN.md).

set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:?usage: gen-testchain.sh <output-dir>}"
mkdir -p "$OUT"

ROOT_KEY="$HERE/tls-testchain/root.key"
UROOT_KEY="$HERE/tls-testchain/uroot.key"
[ -f "$ROOT_KEY" ] || { echo "missing committed $ROOT_KEY" >&2; exit 2; }
[ -f "$UROOT_KEY" ] || { echo "missing committed $UROOT_KEY" >&2; exit 2; }

DAYS=36500
gen_key() { openssl ecparam -name prime256v1 -genkey -noout -out "$1" 2>/dev/null; }

ca_ext() { printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n'; }
leaf_ext() { printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nsubjectAltName=%s\n' "$1"; }

# --- self-signed roots (from the committed keys) ---
openssl req -x509 -new -key "$ROOT_KEY" -sha256 -days "$DAYS" \
    -subj "/CN=Aurora Test Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$OUT/root.crt" 2>/dev/null
openssl req -x509 -new -key "$UROOT_KEY" -sha256 -days "$DAYS" \
    -subj "/CN=Aurora Untrusted Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$OUT/uroot.crt" 2>/dev/null

sign() { # csr ca_crt ca_key extfile out
    openssl x509 -req -in "$1" -CA "$2" -CAkey "$3" -CAcreateserial \
        -days "$DAYS" -sha256 -extfile "$4" -out "$5" 2>/dev/null
}

# --- trusted intermediate + leaf ---
gen_key "$OUT/int.key"
openssl req -new -key "$OUT/int.key" -subj "/CN=Aurora Test Intermediate CA" -out "$OUT/int.csr" 2>/dev/null
ca_ext > "$OUT/int.ext"; sign "$OUT/int.csr" "$OUT/root.crt" "$ROOT_KEY" "$OUT/int.ext" "$OUT/int.crt"

gen_key "$OUT/leaf.key"
openssl req -new -key "$OUT/leaf.key" -subj "/CN=aurora.local" -out "$OUT/leaf.csr" 2>/dev/null
leaf_ext "DNS:aurora.local,IP:10.0.2.2" > "$OUT/leaf.ext"
sign "$OUT/leaf.csr" "$OUT/int.crt" "$OUT/int.key" "$OUT/leaf.ext" "$OUT/leaf.crt"

# --- wrong-name leaf (trusted issuer, SAN does not match aurora.local or the IP) ---
gen_key "$OUT/leafwrong.key"
openssl req -new -key "$OUT/leafwrong.key" -subj "/CN=wrong.example" -out "$OUT/leafwrong.csr" 2>/dev/null
leaf_ext "DNS:wrong.example" > "$OUT/leafwrong.ext"
sign "$OUT/leafwrong.csr" "$OUT/int.crt" "$OUT/int.key" "$OUT/leafwrong.ext" "$OUT/leafwrong.crt"

# --- untrusted chain (independent root, otherwise valid, name matches) ---
gen_key "$OUT/uint.key"
openssl req -new -key "$OUT/uint.key" -subj "/CN=Aurora Untrusted Intermediate CA" -out "$OUT/uint.csr" 2>/dev/null
ca_ext > "$OUT/uint.ext"; sign "$OUT/uint.csr" "$OUT/uroot.crt" "$UROOT_KEY" "$OUT/uint.ext" "$OUT/uint.crt"

gen_key "$OUT/uleaf.key"
openssl req -new -key "$OUT/uleaf.key" -subj "/CN=aurora.local" -out "$OUT/uleaf.csr" 2>/dev/null
leaf_ext "DNS:aurora.local,IP:10.0.2.2" > "$OUT/uleaf.ext"
sign "$OUT/uleaf.csr" "$OUT/uint.crt" "$OUT/uint.key" "$OUT/uleaf.ext" "$OUT/uleaf.crt"

# --- broken chain: flip one byte inside the trusted leaf's signature ---
python3 - "$OUT/leaf.crt" "$OUT/brokenleaf.crt" <<'PY'
import sys, base64
src, dst = sys.argv[1], sys.argv[2]
pem = open(src).read()
b64 = "".join(l for l in pem.splitlines() if "-----" not in l)
der = bytearray(base64.b64decode(b64))
# The ECDSA signatureValue is the tail of the certificate; flip a byte a few
# positions from the end so it lands inside the signature BIT STRING, not the
# length header. This keeps the DER length identical (still parses) but makes the
# leaf signature fail verification under the intermediate's key.
der[-6] ^= 0x01
out = base64.encodebytes(bytes(der)).decode().replace("\n", "")
lines = "\n".join(out[i:i+64] for i in range(0, len(out), 64))
open(dst, "w").write("-----BEGIN CERTIFICATE-----\n" + lines + "\n-----END CERTIFICATE-----\n")
PY

# --- assemble the chain files the server presents (leaf THEN intermediate) ---
cat "$OUT/leaf.crt"       "$OUT/int.crt"  > "$OUT/chain.trusted.crt"
cat "$OUT/leafwrong.crt"  "$OUT/int.crt"  > "$OUT/chain.wrongname.crt"
cat "$OUT/uleaf.crt"      "$OUT/uint.crt" > "$OUT/chain.untrusted.crt"
cat "$OUT/brokenleaf.crt" "$OUT/int.crt"  > "$OUT/chain.broken.crt"

echo "test chain generated in $OUT"
