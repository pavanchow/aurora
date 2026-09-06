#![allow(dead_code)]
//! X.509 certificate-chain verification for TLS 1.3 server authentication.
//!
//! Pure `core`, no `alloc`, no external crates. Given the certificates a server
//! presents in its TLS 1.3 Certificate message (leaf first, then intermediates),
//! this walks from the leaf up, verifying each certificate's signature under its
//! issuer's public key, until it reaches a certificate signed by an embedded
//! trust anchor (`trust_store`). Issuers are matched by exact DER Subject/Issuer
//! Name equality and must assert `basicConstraints cA = TRUE`. Any break in that
//! path (no issuer found, issuer not a CA, bad signature, unsupported algorithm)
//! is a hard rejection: there is no "fall back to trusting the leaf".
//!
//! Supported signature algorithms for chain links: ECDSA-P256-SHA256 and Ed25519
//! (both from the in-tree from-scratch verifiers). RSA PKCS#1 v1.5 chain links are
//! not verified here and are reported as unsupported.

use crate::ecdsa_p256;
use crate::ed25519;
use crate::sha2;
use crate::trust_store::{self, TrustedRoot};
use crate::x509::{self, Cert, SigAlg, SpkiAlg};

/// The maximum number of certificates accepted in a presented chain. A real leaf
/// plus a handful of intermediates never approaches this; the bound stops a peer
/// from forcing unbounded work with a giant certificate list.
pub const MAX_CHAIN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainError {
    /// The Certificate message or a certificate in it did not parse.
    BadEncoding,
    /// No certificates were presented.
    Empty,
    /// More than `MAX_CHAIN` certificates were presented.
    TooLong,
    /// Walked the whole presented chain without reaching an embedded trust anchor.
    UntrustedRoot,
    /// A certificate's signature did not verify under its issuer's key.
    BadSignature,
    /// A certificate used as an issuer did not assert `cA = TRUE`.
    IssuerNotCa,
    /// A chain link used a signature algorithm Aurora cannot verify.
    UnsupportedSig,
}

impl ChainError {
    pub fn as_str(self) -> &'static str {
        match self {
            ChainError::BadEncoding => "certificate chain did not parse",
            ChainError::Empty => "server presented no certificate",
            ChainError::TooLong => "certificate chain too long",
            ChainError::UntrustedRoot => "no path to an embedded trusted root",
            ChainError::BadSignature => "a chain signature did not verify",
            ChainError::IssuerNotCa => "an issuer certificate is not a CA",
            ChainError::UnsupportedSig => "unsupported chain signature algorithm",
        }
    }
}

/// Verify the certificate chain presented in a TLS 1.3 Certificate handshake
/// message (`msg` includes the 4-byte handshake header) against the embedded
/// trust store. Returns the leaf certificate DER on success so the caller can
/// bind the CertificateVerify signature and check the host name against it.
pub fn verify_message(msg: &[u8]) -> Result<&[u8], ChainError> {
    let mut ders: [&[u8]; MAX_CHAIN] = [&[]; MAX_CHAIN];
    let (count, overflow) = split_certs(msg, &mut ders).ok_or(ChainError::BadEncoding)?;
    if count == 0 {
        return Err(ChainError::Empty);
    }
    if overflow {
        return Err(ChainError::TooLong);
    }
    verify_ders(&ders[..count], trust_store::roots())?;
    Ok(ders[0])
}

/// Verify an already-split chain (`ders[0]` = leaf, then intermediates) against
/// `roots`. The core routine, exercised directly by the host known-answer tests.
pub fn verify_ders(ders: &[&[u8]], roots: &[TrustedRoot]) -> Result<(), ChainError> {
    if ders.is_empty() {
        return Err(ChainError::Empty);
    }
    if ders.len() > MAX_CHAIN {
        return Err(ChainError::TooLong);
    }
    let mut certs: [Option<Cert>; MAX_CHAIN] = core::array::from_fn(|_| None);
    for (i, d) in ders.iter().enumerate() {
        certs[i] = Some(x509::parse_certificate(d).ok_or(ChainError::BadEncoding)?);
    }
    let n = ders.len();

    // Walk from the leaf up. At each step, prefer anchoring to an embedded root
    // (issuer Name matches a trust anchor); otherwise the issuer must be another
    // presented certificate that is a CA. A cycle cannot outlast `n` steps.
    let mut cur = 0usize;
    for _ in 0..n {
        let cert = certs[cur].as_ref().ok_or(ChainError::BadEncoding)?;

        if let Some(root) = roots.iter().find(|r| r.subject == cert.issuer) {
            if verify_cert_sig(cert, root.spki_alg, root.key) {
                return Ok(());
            }
            return Err(ChainError::BadSignature);
        }

        // Find a presented issuer by exact Subject == Issuer DER match.
        let mut issuer_idx = None;
        for (j, c) in certs.iter().enumerate().take(n) {
            if j == cur {
                continue;
            }
            if let Some(cj) = c {
                if cj.subject_raw == cert.issuer {
                    issuer_idx = Some(j);
                    break;
                }
            }
        }
        let j = issuer_idx.ok_or(ChainError::UntrustedRoot)?;
        let issuer = certs[j].as_ref().ok_or(ChainError::BadEncoding)?;
        if !issuer.is_ca() {
            return Err(ChainError::IssuerNotCa);
        }
        if !verify_cert_sig(cert, issuer.spki_alg, issuer.spki_key) {
            return Err(ChainError::BadSignature);
        }
        cur = j;
    }

    // Ran out of presented certificates without reaching a trust anchor.
    Err(ChainError::UntrustedRoot)
}

/// Verify `cert`'s signature over its TBSCertificate using an issuer public key
/// given as `(algorithm, key bytes)`. The key bytes are the issuer's raw
/// subjectPublicKey contents: a 65-byte SEC1 point for EC P-256, 32 bytes for
/// Ed25519.
fn verify_cert_sig(cert: &Cert, issuer_alg: SpkiAlg, issuer_key: &[u8]) -> bool {
    match cert.sig_alg {
        SigAlg::EcdsaP256Sha256 => {
            if issuer_alg != SpkiAlg::EcP256 || issuer_key.len() != 65 || issuer_key[0] != 0x04 {
                return false;
            }
            let digest = sha2::sha256(cert.tbs);
            ecdsa_p256::verify_der(issuer_key, &digest, cert.signature)
        }
        SigAlg::Ed25519 => {
            if issuer_alg != SpkiAlg::Ed25519 || issuer_key.len() != 32 || cert.signature.len() != 64
            {
                return false;
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(issuer_key);
            let mut sig = [0u8; 64];
            sig.copy_from_slice(cert.signature);
            ed25519::verify(&key, cert.tbs, &sig)
        }
        // RSA PKCS#1 v1.5 chain links are not verified here.
        _ => false,
    }
}

/// Split the CertificateEntry DERs out of a TLS 1.3 Certificate handshake message
/// (`msg` includes the 4-byte handshake header) into `out`, preserving the
/// message's lifetime. Returns `(count, overflow)`: `count` is the number of
/// entries actually stored (capped at `out.len()`), and `overflow` is true if the
/// message held more entries than `out` could hold. Returns `None` on malformed
/// framing. Certificate extensions per entry are skipped.
pub fn split_certs<'a>(msg: &'a [u8], out: &mut [&'a [u8]]) -> Option<(usize, bool)> {
    if msg.len() < 4 || msg[0] != crate::tls::HS_CERTIFICATE {
        return None;
    }
    let body_len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    let end = 4usize.checked_add(body_len)?;
    let body = msg.get(4..end)?;
    let mut p = 0usize;
    // certificate_request_context: 1-byte length + bytes.
    let ctx_len = *body.get(p)? as usize;
    p += 1 + ctx_len;
    // certificate_list: 3-byte length.
    let list_len = ((*body.get(p)? as usize) << 16)
        | ((*body.get(p + 1)? as usize) << 8)
        | *body.get(p + 2)? as usize;
    p += 3;
    let list_end = p.checked_add(list_len)?;
    if list_end > body.len() {
        return None;
    }
    let mut count = 0usize;
    let mut overflow = false;
    while p + 3 <= list_end {
        let cert_len =
            ((body[p] as usize) << 16) | ((body[p + 1] as usize) << 8) | body[p + 2] as usize;
        p += 3;
        let cend = p.checked_add(cert_len)?;
        if cend > list_end {
            return None;
        }
        let der = body.get(p..cend)?;
        if count < out.len() {
            out[count] = der;
        } else {
            overflow = true;
        }
        count += 1;
        p = cend;
        // per-entry extensions: 2-byte length + bytes.
        if p + 2 > list_end {
            break;
        }
        let ext_len = ((body[p] as usize) << 8) | body[p + 1] as usize;
        p += 2 + ext_len;
    }
    Some((core::cmp::min(count, out.len()), overflow))
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEAF: &[u8] = include_bytes!("../../logic/testdata/leaf.der");
    const INT: &[u8] = include_bytes!("../../logic/testdata/int.der");
    const ULEAF: &[u8] = include_bytes!("../../logic/testdata/uleaf.der");
    const UINT: &[u8] = include_bytes!("../../logic/testdata/uint.der");
    const BROKENLEAF: &[u8] = include_bytes!("../../logic/testdata/brokenleaf.der");
    const LEAFWRONG: &[u8] = include_bytes!("../../logic/testdata/leafwrong.der");

    #[test]
    fn trusted_chain_accepts() {
        // leaf -> intermediate -> (issuer is the embedded test root): accepted.
        assert_eq!(verify_ders(&[LEAF, INT], trust_store::roots()), Ok(()));
    }

    #[test]
    fn untrusted_root_rejected() {
        // A structurally valid chain whose root is not embedded must be rejected.
        assert_eq!(
            verify_ders(&[ULEAF, UINT], trust_store::roots()),
            Err(ChainError::UntrustedRoot)
        );
    }

    #[test]
    fn broken_signature_rejected() {
        // The trusted intermediate signs the leaf, but the leaf signature bytes
        // were tampered: the intermediate->leaf link must fail to verify.
        assert_eq!(
            verify_ders(&[BROKENLEAF, INT], trust_store::roots()),
            Err(ChainError::BadSignature)
        );
    }

    #[test]
    fn leaf_alone_is_untrusted() {
        // The leaf's issuer (the intermediate) is neither presented nor a root.
        assert_eq!(verify_ders(&[LEAF], trust_store::roots()), Err(ChainError::UntrustedRoot));
    }

    #[test]
    fn wrong_name_leaf_still_chains() {
        // The wrong-name leaf is a valid chain link (name matching is a separate
        // check the TLS layer performs); the chain itself must verify.
        assert_eq!(verify_ders(&[LEAFWRONG, INT], trust_store::roots()), Ok(()));
    }
}
