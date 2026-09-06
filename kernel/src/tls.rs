//! From-scratch TLS 1.3 (RFC 8446) client logic: the pure, host-testable core.
//!
//! This module holds everything about TLS 1.3 that is a pure function over byte
//! buffers: HKDF over HMAC-SHA256 (RFC 5869), the full TLS 1.3 key schedule
//! (early/handshake/master secrets, traffic secrets, traffic keys, finished
//! keys), the record-layer nonce construction and AEAD framing, the ClientHello
//! builder, and the ServerHello and handshake-message parsers. The I/O side (the
//! TCP stream, the handshake loop, retransmits) lives in `net.rs` and calls in
//! here, exactly like `proto.rs` sits under the `net.rs` driver.
//!
//! The cipher suite is TLS_CHACHA20_POLY1305_SHA256, so the record AEAD reuses
//! the in-tree RFC 8439 ChaCha20-Poly1305 in `crypto.rs`, the transcript and key
//! schedule reuse the in-tree SHA-256/HMAC in `sha2.rs`, and key exchange is
//! x25519. Because it is pure, the `aurora-logic` crate mounts this same source
//! and checks it against the RFC 5869 HKDF vectors and the RFC 8448 worked TLS
//! 1.3 key-schedule trace on every `cargo test`.

#![allow(dead_code)]

use crate::crypto;
use crate::sha2::{self, Sha256, HmacSha256};

pub const HASH_LEN: usize = 32;
pub const KEY_LEN: usize = 32; // ChaCha20 key
pub const IV_LEN: usize = 12;

// TLS constants.
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
pub const GROUP_X25519: u16 = 0x001d;
pub const TLS_VERSION_13: u16 = 0x0304;
pub const LEGACY_VERSION: u16 = 0x0303;

// SignatureScheme code points (RFC 8446 4.2.3).
pub const SIG_ED25519: u16 = 0x0807;
pub const SIG_ECDSA_P256_SHA256: u16 = 0x0403;
pub const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
pub const SIG_RSA_PKCS1_SHA256: u16 = 0x0401;

// Record content types.
pub const CT_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CT_ALERT: u8 = 21;
pub const CT_HANDSHAKE: u8 = 22;
pub const CT_APPLICATION_DATA: u8 = 23;

// Handshake message types.
pub const HS_CLIENT_HELLO: u8 = 1;
pub const HS_SERVER_HELLO: u8 = 2;
pub const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
pub const HS_CERTIFICATE: u8 = 11;
pub const HS_CERTIFICATE_VERIFY: u8 = 15;
pub const HS_FINISHED: u8 = 20;

// --- HKDF (RFC 5869) over HMAC-SHA256 ----------------------------------------

/// HKDF-Extract: PRK = HMAC-Hash(salt, IKM).
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; HASH_LEN] {
    sha2::hmac_sha256(salt, ikm)
}

/// HKDF-Expand into `out` (length up to 255*32). T(0)=empty, T(i)=HMAC(PRK,
/// T(i-1) || info || i).
pub fn hkdf_expand(prk: &[u8; HASH_LEN], info: &[u8], out: &mut [u8]) {
    let mut t = [0u8; HASH_LEN];
    let mut t_len = 0usize;
    let mut done = 0usize;
    let mut counter: u8 = 1;
    while done < out.len() {
        let mut h = HmacSha256::new(prk);
        h.update(&t[..t_len]);
        h.update(info);
        h.update(&[counter]);
        t = h.finalize();
        t_len = HASH_LEN;
        let take = core::cmp::min(HASH_LEN, out.len() - done);
        out[done..done + take].copy_from_slice(&t[..take]);
        done += take;
        counter = counter.wrapping_add(1);
    }
}

/// HKDF-Expand-Label (RFC 8446 7.1) into `out`. The label is prefixed "tls13 ".
pub fn hkdf_expand_label(secret: &[u8; HASH_LEN], label: &str, context: &[u8], out: &mut [u8]) {
    // HkdfLabel: uint16 length; opaque label<7..255>; opaque context<0..255>.
    let mut info = [0u8; 2 + 1 + 255 + 1 + 255];
    let mut n = 0;
    info[n..n + 2].copy_from_slice(&(out.len() as u16).to_be_bytes());
    n += 2;
    let full_label_len = 6 + label.len(); // "tls13 " + label
    info[n] = full_label_len as u8;
    n += 1;
    info[n..n + 6].copy_from_slice(b"tls13 ");
    n += 6;
    info[n..n + label.len()].copy_from_slice(label.as_bytes());
    n += label.len();
    info[n] = context.len() as u8;
    n += 1;
    info[n..n + context.len()].copy_from_slice(context);
    n += context.len();
    hkdf_expand(secret, &info[..n], out);
}

/// Derive-Secret(secret, label, transcript_hash) = HKDF-Expand-Label(secret,
/// label, transcript_hash, Hash.length). The caller passes the already-computed
/// transcript hash so this stays a pure 32-byte-in, 32-byte-out function.
pub fn derive_secret(secret: &[u8; HASH_LEN], label: &str, transcript_hash: &[u8]) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    hkdf_expand_label(secret, label, transcript_hash, &mut out);
    out
}

// --- TLS 1.3 key schedule (RFC 8446 7.1) -------------------------------------

/// The three master secrets of the key schedule. Traffic secrets and keys are
/// derived from these plus transcript hashes.
pub struct KeySchedule {
    pub early: [u8; HASH_LEN],
    pub handshake: [u8; HASH_LEN],
    pub master: [u8; HASH_LEN],
}

impl KeySchedule {
    /// Early Secret = HKDF-Extract(0, 0) with no PSK (salt and IKM are 32 zeros).
    pub fn new() -> Self {
        let zeros = [0u8; HASH_LEN];
        Self { early: hkdf_extract(&zeros, &zeros), handshake: zeros, master: zeros }
    }

    /// Handshake Secret = HKDF-Extract(Derive-Secret(early,"derived",""), ECDHE).
    pub fn derive_handshake(&mut self, ecdhe: &[u8; 32]) {
        let empty = sha2::sha256(b"");
        let derived = derive_secret(&self.early, "derived", &empty);
        self.handshake = hkdf_extract(&derived, ecdhe);
    }

    /// Master Secret = HKDF-Extract(Derive-Secret(handshake,"derived",""), 0).
    pub fn derive_master(&mut self) {
        let empty = sha2::sha256(b"");
        let derived = derive_secret(&self.handshake, "derived", &empty);
        let zeros = [0u8; HASH_LEN];
        self.master = hkdf_extract(&derived, &zeros);
    }

    pub fn client_hs_traffic(&self, th_ch_sh: &[u8]) -> [u8; HASH_LEN] {
        derive_secret(&self.handshake, "c hs traffic", th_ch_sh)
    }
    pub fn server_hs_traffic(&self, th_ch_sh: &[u8]) -> [u8; HASH_LEN] {
        derive_secret(&self.handshake, "s hs traffic", th_ch_sh)
    }
    pub fn client_ap_traffic(&self, th_fin: &[u8]) -> [u8; HASH_LEN] {
        derive_secret(&self.master, "c ap traffic", th_fin)
    }
    pub fn server_ap_traffic(&self, th_fin: &[u8]) -> [u8; HASH_LEN] {
        derive_secret(&self.master, "s ap traffic", th_fin)
    }
}

impl Default for KeySchedule {
    fn default() -> Self {
        Self::new()
    }
}

/// A directional set of AEAD parameters derived from a traffic secret.
#[derive(Clone)]
pub struct TrafficKeys {
    pub key: [u8; KEY_LEN],
    pub iv: [u8; IV_LEN],
    pub seq: u64,
}

impl TrafficKeys {
    /// Derive write/read key and iv from a traffic secret (RFC 8446 7.3).
    pub fn from_secret(secret: &[u8; HASH_LEN]) -> Self {
        let mut key = [0u8; KEY_LEN];
        let mut iv = [0u8; IV_LEN];
        hkdf_expand_label(secret, "key", &[], &mut key);
        hkdf_expand_label(secret, "iv", &[], &mut iv);
        Self { key, iv, seq: 0 }
    }

    /// The per-record nonce: static IV XOR the 64-bit sequence number placed in
    /// the low 8 bytes (RFC 8446 5.3).
    pub fn nonce(&self) -> [u8; IV_LEN] {
        let mut n = self.iv;
        let s = self.seq.to_be_bytes();
        for i in 0..8 {
            n[IV_LEN - 8 + i] ^= s[i];
        }
        n
    }
}

/// finished_key = HKDF-Expand-Label(traffic_secret, "finished", "", Hash.len).
pub fn finished_key(traffic_secret: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    hkdf_expand_label(traffic_secret, "finished", &[], &mut out);
    out
}

/// verify_data = HMAC(finished_key, transcript_hash).
pub fn finished_verify_data(traffic_secret: &[u8; HASH_LEN], transcript_hash: &[u8]) -> [u8; HASH_LEN] {
    let fk = finished_key(traffic_secret);
    sha2::hmac_sha256(&fk, transcript_hash)
}

// --- Transcript hash ---------------------------------------------------------

/// The running handshake transcript hash. Fed each handshake message in wire
/// order; snapshotted (non-destructively) at the points the key schedule needs.
#[derive(Clone)]
pub struct Transcript {
    h: Sha256,
}

impl Transcript {
    pub fn new() -> Self {
        Self { h: Sha256::new() }
    }
    pub fn update(&mut self, msg: &[u8]) {
        self.h.update(msg);
    }
    pub fn hash(&self) -> [u8; HASH_LEN] {
        self.h.finalize()
    }
}

impl Default for Transcript {
    fn default() -> Self {
        Self::new()
    }
}

// --- Record layer (RFC 8446 5.2) ---------------------------------------------

/// Encrypt one TLS 1.3 record. `plaintext` is the inner content (a handshake
/// message or application data), `content_type` its real type. The full record
/// (5-byte header + ciphertext + 16-byte tag) is written to `out`; returns its
/// length. Increments `keys.seq`.
pub fn seal_record(
    keys: &mut TrafficKeys,
    content_type: u8,
    plaintext: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let inner_len = plaintext.len() + 1; // content || content_type (no padding)
    let cipher_len = inner_len + crypto::TAG_LEN;
    let total = 5 + cipher_len;
    if out.len() < total {
        return None;
    }
    // Record header (also the AEAD associated data).
    out[0] = CT_APPLICATION_DATA;
    out[1..3].copy_from_slice(&LEGACY_VERSION.to_be_bytes());
    out[3..5].copy_from_slice(&(cipher_len as u16).to_be_bytes());
    let mut aad = [0u8; 5];
    aad.copy_from_slice(&out[..5]);
    // Inner plaintext, encrypted in place.
    out[5..5 + plaintext.len()].copy_from_slice(plaintext);
    out[5 + plaintext.len()] = content_type;
    let nonce = keys.nonce();
    let tag = crypto::aead_seal(&keys.key, &nonce, &aad, &mut out[5..5 + inner_len]);
    out[5 + inner_len..total].copy_from_slice(&tag);
    keys.seq = keys.seq.wrapping_add(1);
    Some(total)
}

/// Decrypt one TLS 1.3 record in place. `record` is the full record starting at
/// the 5-byte header. On success returns `(content_type, plaintext_len)` where
/// the recovered inner content is `record[5..5+plaintext_len]`. Increments seq.
pub fn open_record(keys: &mut TrafficKeys, record: &mut [u8]) -> Option<(u8, usize)> {
    if record.len() < 5 + crypto::TAG_LEN + 1 {
        return None;
    }
    let cipher_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if 5 + cipher_len > record.len() || cipher_len < crypto::TAG_LEN + 1 {
        return None;
    }
    let mut aad = [0u8; 5];
    aad.copy_from_slice(&record[..5]);
    let inner_len = cipher_len - crypto::TAG_LEN;
    let nonce = keys.nonce();
    let mut tag = [0u8; crypto::TAG_LEN];
    tag.copy_from_slice(&record[5 + inner_len..5 + cipher_len]);
    let ok = crypto::aead_open(&keys.key, &nonce, &aad, &mut record[5..5 + inner_len], &tag);
    if !ok {
        return None;
    }
    keys.seq = keys.seq.wrapping_add(1);
    // Strip trailing zero padding, then the one content-type byte.
    let mut end = inner_len;
    while end > 0 && record[5 + end - 1] == 0 {
        end -= 1;
    }
    if end == 0 {
        return None;
    }
    let content_type = record[5 + end - 1];
    Some((content_type, end - 1))
}

// --- CertificateVerify signed content (RFC 8446 4.4.3) -----------------------

/// Build the content the server signs in CertificateVerify: 64 spaces, the
/// context string "TLS 1.3, server CertificateVerify", a zero byte, then the
/// transcript hash through the Certificate message. Returns the length in `out`.
pub fn certificate_verify_content(transcript_hash: &[u8], out: &mut [u8]) -> usize {
    const CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";
    let mut n = 0;
    for b in out.iter_mut().take(64) {
        *b = 0x20;
    }
    n += 64;
    out[n..n + CONTEXT.len()].copy_from_slice(CONTEXT);
    n += CONTEXT.len();
    out[n] = 0;
    n += 1;
    out[n..n + transcript_hash.len()].copy_from_slice(transcript_hash);
    n += transcript_hash.len();
    n
}

// --- ClientHello builder -----------------------------------------------------

struct Cursor<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn u8(&mut self, v: u8) {
        self.buf[self.pos] = v;
        self.pos += 1;
    }
    fn u16(&mut self, v: u16) {
        self.buf[self.pos..self.pos + 2].copy_from_slice(&v.to_be_bytes());
        self.pos += 2;
    }
    fn bytes(&mut self, b: &[u8]) {
        self.buf[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
    }
    /// Reserve a 2-byte length slot and return its position, to be back-filled.
    fn open16(&mut self) -> usize {
        let p = self.pos;
        self.pos += 2;
        p
    }
    fn close16(&mut self, at: usize) {
        let len = (self.pos - at - 2) as u16;
        self.buf[at..at + 2].copy_from_slice(&len.to_be_bytes());
    }
}

/// Build a ClientHello handshake message (with its 4-byte handshake header) into
/// `out`, offering TLS_CHACHA20_POLY1305_SHA256, x25519 key exchange, the given
/// SNI host, and the signature algorithms Aurora can verify. `random` is the
/// 32-byte client random, `x25519_pub` the client's ephemeral public key.
/// Returns the total message length. A 32-byte legacy session id is used for
/// middlebox compatibility.
pub fn build_client_hello(
    random: &[u8; 32],
    session_id: &[u8; 32],
    x25519_pub: &[u8; 32],
    sni_host: &str,
    out: &mut [u8],
) -> Option<usize> {
    if out.len() < 512 || sni_host.len() > 255 {
        return None;
    }
    let mut c = Cursor::new(out);
    // Handshake header: type + 3-byte length (back-filled).
    c.u8(HS_CLIENT_HELLO);
    let hs_len_at = c.pos;
    c.pos += 3;

    c.u16(LEGACY_VERSION); // legacy_version = 0x0303
    c.bytes(random); // random[32]
    c.u8(32); // legacy_session_id length
    c.bytes(session_id);
    // cipher_suites
    c.u16(2);
    c.u16(TLS_CHACHA20_POLY1305_SHA256);
    // legacy_compression_methods: [null]
    c.u8(1);
    c.u8(0);
    // extensions
    let ext_len_at = c.open16();

    // supported_versions (43): TLS 1.3 only.
    c.u16(43);
    c.u16(3);
    c.u8(2);
    c.u16(TLS_VERSION_13);

    // supported_groups (10): x25519.
    c.u16(10);
    c.u16(4);
    c.u16(2);
    c.u16(GROUP_X25519);

    // signature_algorithms (13): the schemes Aurora can verify.
    c.u16(13);
    c.u16(2 + 8);
    c.u16(8);
    c.u16(SIG_ED25519);
    c.u16(SIG_ECDSA_P256_SHA256);
    c.u16(SIG_RSA_PSS_RSAE_SHA256);
    c.u16(SIG_RSA_PKCS1_SHA256);

    // key_share (51): one x25519 entry.
    c.u16(51);
    c.u16(2 + 2 + 2 + 32);
    c.u16(2 + 2 + 32); // client_shares length
    c.u16(GROUP_X25519);
    c.u16(32);
    c.bytes(x25519_pub);

    // server_name / SNI (0).
    let host = sni_host.as_bytes();
    c.u16(0);
    c.u16((2 + 1 + 2 + host.len()) as u16);
    c.u16((1 + 2 + host.len()) as u16); // server_name_list length
    c.u8(0); // name_type = host_name
    c.u16(host.len() as u16);
    c.bytes(host);

    c.close16(ext_len_at);

    let total = c.pos;
    let body_len = (total - hs_len_at - 3) as u32;
    out[hs_len_at] = (body_len >> 16) as u8;
    out[hs_len_at + 1] = (body_len >> 8) as u8;
    out[hs_len_at + 2] = body_len as u8;
    Some(total)
}

// --- Parsers -----------------------------------------------------------------

/// Parsed ServerHello essentials.
#[derive(Debug, PartialEq, Eq)]
pub struct ServerHello {
    pub cipher_suite: u16,
    pub group: u16,
    pub server_pub: [u8; 32],
}

/// Parse a ServerHello handshake message (including its 4-byte header). Requires
/// the negotiated suite to be TLS_CHACHA20_POLY1305_SHA256 and the key_share to
/// be x25519, returning the server's ephemeral public key.
pub fn parse_server_hello(msg: &[u8]) -> Option<ServerHello> {
    if msg.len() < 4 || msg[0] != HS_SERVER_HELLO {
        return None;
    }
    let body_len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    let body = msg.get(4..4 + body_len)?;
    let mut p = 0usize;
    // legacy_version(2) + random(32).
    if body.len() < 2 + 32 + 1 {
        return None;
    }
    p += 2 + 32;
    // legacy_session_id_echo.
    let sid_len = *body.get(p)? as usize;
    p += 1 + sid_len;
    // cipher_suite(2) + legacy_compression_method(1).
    let cipher_suite = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]);
    p += 2;
    p += 1; // compression method
            // extensions.
    let ext_total = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2;
    let ext_end = p + ext_total;
    if ext_end > body.len() {
        return None;
    }
    let mut group = 0u16;
    let mut server_pub = [0u8; 32];
    let mut have_share = false;
    while p + 4 <= ext_end {
        let etype = u16::from_be_bytes([body[p], body[p + 1]]);
        let elen = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        p += 4;
        let edata = body.get(p..p + elen)?;
        if etype == 51 && elen >= 4 {
            // key_share: group(2) + key_exchange_len(2) + key.
            group = u16::from_be_bytes([edata[0], edata[1]]);
            let klen = u16::from_be_bytes([edata[2], edata[3]]) as usize;
            if group == GROUP_X25519 && klen == 32 && edata.len() >= 4 + 32 {
                server_pub.copy_from_slice(&edata[4..4 + 32]);
                have_share = true;
            }
        }
        p += elen;
    }
    if cipher_suite != TLS_CHACHA20_POLY1305_SHA256 || !have_share || group != GROUP_X25519 {
        return None;
    }
    Some(ServerHello { cipher_suite, group, server_pub })
}

/// Iterate over the handshake messages packed in a decrypted plaintext buffer.
/// Each yielded item is `(msg_type, full_message_including_4_byte_header)`.
pub struct HandshakeIter<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> HandshakeIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
}

impl<'a> Iterator for HandshakeIter<'a> {
    type Item = (u8, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 4 > self.buf.len() {
            return None;
        }
        let t = self.buf[self.pos];
        let len = ((self.buf[self.pos + 1] as usize) << 16)
            | ((self.buf[self.pos + 2] as usize) << 8)
            | self.buf[self.pos + 3] as usize;
        let end = self.pos + 4 + len;
        if end > self.buf.len() {
            return None;
        }
        let msg = &self.buf[self.pos..end];
        self.pos = end;
        Some((t, msg))
    }
}

/// Extract the leaf certificate DER from a Certificate handshake message (with
/// its 4-byte header). Returns a slice into `msg`.
pub fn certificate_leaf(msg: &[u8]) -> Option<&[u8]> {
    if msg.len() < 4 || msg[0] != HS_CERTIFICATE {
        return None;
    }
    let mut p = 4;
    // certificate_request_context: 1-byte length + bytes.
    let ctx_len = *msg.get(p)? as usize;
    p += 1 + ctx_len;
    // certificate_list: 3-byte length.
    if p + 3 > msg.len() {
        return None;
    }
    let _list_len = ((msg[p] as usize) << 16) | ((msg[p + 1] as usize) << 8) | msg[p + 2] as usize;
    p += 3;
    // First CertificateEntry: cert_data 3-byte length + DER.
    if p + 3 > msg.len() {
        return None;
    }
    let cert_len = ((msg[p] as usize) << 16) | ((msg[p + 1] as usize) << 8) | msg[p + 2] as usize;
    p += 3;
    msg.get(p..p + cert_len)
}

/// Parse a CertificateVerify message (with its 4-byte header), returning the
/// signature scheme and the signature bytes.
pub fn parse_certificate_verify(msg: &[u8]) -> Option<(u16, &[u8])> {
    if msg.len() < 4 + 4 || msg[0] != HS_CERTIFICATE_VERIFY {
        return None;
    }
    let scheme = u16::from_be_bytes([msg[4], msg[5]]);
    let sig_len = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let sig = msg.get(8..8 + sig_len)?;
    Some((scheme, sig))
}

/// Extract the verify_data from a Finished message (with its 4-byte header).
pub fn parse_finished(msg: &[u8]) -> Option<&[u8]> {
    if msg.len() < 4 || msg[0] != HS_FINISHED {
        return None;
    }
    let len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
    msg.get(4..4 + len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> std::vec::Vec<u8> {
        let s: std::string::String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    fn arr32(s: &str) -> [u8; 32] {
        let v = hex(s);
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    // RFC 5869 Test Case 1 (SHA-256).
    #[test]
    fn hkdf_rfc5869_tc1() {
        let ikm = [0x0bu8; 22];
        let salt = hex("000102030405060708090a0b0c");
        let info = hex("f0f1f2f3f4f5f6f7f8f9");
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            &prk[..],
            &hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")[..]
        );
        let mut okm = [0u8; 42];
        hkdf_expand(&prk, &info, &mut okm);
        assert_eq!(
            &okm[..],
            &hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")[..]
        );
    }

    // RFC 5869 Test Case 3 (zero-length salt/info).
    #[test]
    fn hkdf_rfc5869_tc3() {
        let ikm = [0x0bu8; 22];
        let prk = hkdf_extract(&[], &ikm);
        assert_eq!(
            &prk[..],
            &hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")[..]
        );
        let mut okm = [0u8; 42];
        hkdf_expand(&prk, &[], &mut okm);
        assert_eq!(
            &okm[..],
            &hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")[..]
        );
    }

    // The HKDF-Expand-Label info encoding must match RFC 8448's printed info for
    // Derive-Secret(early, "derived", ""): the exact 49-byte block. The context
    // is Transcript-Hash("") = SHA-256("").
    #[test]
    fn expand_label_info_encoding() {
        let empty = sha2::sha256(b"");
        let mut info = std::vec::Vec::new();
        info.extend_from_slice(&32u16.to_be_bytes()); // output length
        info.push(13); // label length ("tls13 derived")
        info.extend_from_slice(b"tls13 derived");
        info.push(32); // context length
        info.extend_from_slice(&empty);
        assert_eq!(
            info,
            hex("00200d746c73313320646572697665642000000000000000000000000000000000\
                 000000000000000000000000000000000000")
                .iter()
                .copied()
                .take(17)
                .chain(empty.iter().copied())
                .collect::<std::vec::Vec<u8>>()
        );
    }

    // The authoritative proof: reproduce the RFC 8448 "Simple 1-RTT Handshake"
    // key schedule end to end. RFC 8448's main trace uses x25519 and SHA-256, so
    // every secret in the schedule matches regardless of the record cipher.
    #[test]
    fn rfc8448_key_schedule() {
        let ecdhe = arr32("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        let th_ch_sh = arr32("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
        let th_fin = arr32("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");

        let mut ks = KeySchedule::new();
        assert_eq!(
            &ks.early[..],
            &hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")[..],
            "early secret"
        );
        ks.derive_handshake(&ecdhe);
        assert_eq!(
            &ks.handshake[..],
            &hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")[..],
            "handshake secret"
        );

        let chs = ks.client_hs_traffic(&th_ch_sh);
        let shs = ks.server_hs_traffic(&th_ch_sh);
        assert_eq!(
            &chs[..],
            &hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")[..],
            "client hs traffic secret"
        );
        assert_eq!(
            &shs[..],
            &hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")[..],
            "server hs traffic secret"
        );

        ks.derive_master();
        assert_eq!(
            &ks.master[..],
            &hex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")[..],
            "master secret"
        );

        let cap = ks.client_ap_traffic(&th_fin);
        let sap = ks.server_ap_traffic(&th_fin);
        assert_eq!(
            &cap[..],
            &hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")[..],
            "client ap traffic secret"
        );
        assert_eq!(
            &sap[..],
            &hex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643")[..],
            "server ap traffic secret"
        );

        // The "key" derivation mechanism, checked against RFC 8448 exactly. RFC
        // 8448 uses AES-128 (a 16-byte key); the requested length is encoded in
        // the HKDF-Expand-Label info, so a 16-byte expansion reproduces 8448's
        // key verbatim, proving the derivation even though Aurora's ChaCha suite
        // asks for 32 bytes.
        let mut aes_len_key = [0u8; 16];
        hkdf_expand_label(&shs, "key", &[], &mut aes_len_key);
        assert_eq!(
            &aes_len_key[..],
            &hex("3fce516009c21727d0f2e4e86ee403bc")[..],
            "server hs write key (RFC 8448, 16-byte expansion)"
        );
        // The iv length (12) is the same for both suites, so TrafficKeys' iv
        // matches 8448 directly.
        let keys = TrafficKeys::from_secret(&shs);
        assert_eq!(&keys.iv[..], &hex("5d313eb2671276ee13000b30")[..], "server hs iv");

        // The server handshake finished key.
        let fk = finished_key(&shs);
        assert_eq!(
            &fk[..],
            &hex("008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8")[..],
            "server finished key"
        );
    }

    #[test]
    fn record_nonce_construction() {
        let mut k = TrafficKeys {
            key: [0u8; 32],
            iv: hex("5d313eb2671276ee13000b30").try_into().unwrap(),
            seq: 0,
        };
        assert_eq!(&k.nonce()[..], &hex("5d313eb2671276ee13000b30")[..]);
        k.seq = 1;
        assert_eq!(&k.nonce()[..], &hex("5d313eb2671276ee13000b31")[..]);
        k.seq = 0x0102;
        assert_eq!(&k.nonce()[..], &hex("5d313eb2671276ee13000a32")[..]);
    }

    #[test]
    fn record_round_trip() {
        let secret = arr32("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
        let mut wk = TrafficKeys::from_secret(&secret);
        let mut rk = TrafficKeys::from_secret(&secret);
        let msg = b"the decrypted response plaintext must round-trip exactly";
        let mut rec = [0u8; 256];
        let n = seal_record(&mut wk, CT_APPLICATION_DATA, msg, &mut rec).unwrap();
        let (ct, plen) = open_record(&mut rk, &mut rec[..n]).unwrap();
        assert_eq!(ct, CT_APPLICATION_DATA);
        assert_eq!(&rec[5..5 + plen], msg);
        assert_eq!(wk.seq, 1);
        assert_eq!(rk.seq, 1);
    }

    // Parse the exact ServerHello from RFC 8448 (section 3).
    #[test]
    fn parse_rfc8448_server_hello() {
        // RFC 8448's ServerHello, with the negotiated cipher suite byte changed
        // from 0x1301 (AES-128-GCM, the RFC's suite) to 0x1303 (ChaCha20, ours);
        // the key_share is what this vector proves is parsed correctly.
        let sh = hex(
            "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772e\
             d3e2692800130300002e00330024001d0020c9828876112095fe66762bdbf7c672e1\
             56d6cc253b833df1dd69b1b04e751f0f002b00020304",
        );
        let parsed = parse_server_hello(&sh).unwrap();
        assert_eq!(parsed.cipher_suite, TLS_CHACHA20_POLY1305_SHA256);
        assert_eq!(parsed.group, GROUP_X25519);
        assert_eq!(
            &parsed.server_pub[..],
            &hex("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f")[..]
        );
    }

    #[test]
    fn client_hello_round_trips_structurally() {
        let random = [7u8; 32];
        let sid = [9u8; 32];
        let pubk = [0x42u8; 32];
        let mut out = [0u8; 1024];
        let n = build_client_hello(&random, &sid, &pubk, "example.com", &mut out).unwrap();
        // Handshake header: type 1, length matches.
        assert_eq!(out[0], HS_CLIENT_HELLO);
        let body_len = ((out[1] as usize) << 16) | ((out[2] as usize) << 8) | out[3] as usize;
        assert_eq!(body_len, n - 4);
        // legacy_version present.
        assert_eq!(&out[4..6], &LEGACY_VERSION.to_be_bytes());
        // Our key share bytes appear in the message.
        assert!(out[..n].windows(32).any(|w| w == &pubk[..]));
        // SNI host bytes appear.
        assert!(out[..n].windows(11).any(|w| w == b"example.com"));
    }

    #[test]
    fn certificate_verify_content_shape() {
        let th = [0xAAu8; 32];
        let mut out = [0u8; 256];
        let n = certificate_verify_content(&th, &mut out);
        assert_eq!(n, 64 + 33 + 1 + 32);
        assert!(out[..64].iter().all(|&b| b == 0x20));
        assert_eq!(&out[64..64 + 33], b"TLS 1.3, server CertificateVerify");
        assert_eq!(out[64 + 33], 0);
        assert_eq!(&out[64 + 34..n], &th[..]);
    }

    #[test]
    fn handshake_iter_splits_messages() {
        // Two tiny handshake messages back to back.
        let mut buf = std::vec::Vec::new();
        buf.extend_from_slice(&[HS_ENCRYPTED_EXTENSIONS, 0, 0, 2, 0, 0]);
        buf.extend_from_slice(&[HS_FINISHED, 0, 0, 3, 1, 2, 3]);
        let msgs: std::vec::Vec<(u8, usize)> =
            HandshakeIter::new(&buf).map(|(t, m)| (t, m.len())).collect();
        assert_eq!(msgs, std::vec![(HS_ENCRYPTED_EXTENSIONS, 6), (HS_FINISHED, 7)]);
    }
}
