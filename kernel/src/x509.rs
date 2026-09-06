#![allow(dead_code)]

//! Minimal DER / X.509 certificate parser for TLS 1.3 server authentication.
//! Pure `core`, no `std`, no `alloc`, no external crates. Never panics on bad
//! input: every access goes through checked slicing and returns `None` instead.

// ---- DER tags -------------------------------------------------------------
const TAG_INTEGER: u8 = 0x02;
const TAG_BITSTRING: u8 = 0x03;
const TAG_OCTETSTRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_BOOLEAN: u8 = 0x01;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_UTCTIME: u8 = 0x17;
const TAG_GENTIME: u8 = 0x18;
const TAG_CTX_0: u8 = 0xA0; // [0] explicit (version)
const TAG_CTX_3: u8 = 0xA3; // [3] explicit (extensions)
const TAG_SAN_DNS: u8 = 0x82; // [2] IA5String dNSName inside GeneralName
const TAG_SAN_IP: u8 = 0x87; // [7] OCTET STRING iPAddress inside GeneralName

// ---- Object identifiers (DER contents, no tag/len) ------------------------
const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];
const OID_EC_PUBKEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_SHA256_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
const OID_RSA_PSS: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];
const OID_CN: &[u8] = &[0x55, 0x04, 0x03]; // 2.5.4.3 commonName
const OID_SAN: &[u8] = &[0x55, 0x1D, 0x11]; // 2.5.29.17 subjectAltName
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13]; // 2.5.29.19 basicConstraints

// ---- Public API -----------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpkiAlg {
    Ed25519,
    EcP256,
    Rsa,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAlg {
    Ed25519,
    EcdsaP256Sha256,
    RsaPkcs1Sha256,
    RsaPssSha256,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub min: u8,
    pub sec: u8,
}

pub struct Cert<'a> {
    pub raw: &'a [u8],
    /// Raw DER of the TBSCertificate, including its own tag+length header.
    /// These are the exact bytes the CA signed.
    pub tbs: &'a [u8],
    pub spki_alg: SpkiAlg,
    /// Ed25519: raw 32-byte public key. EC P-256: uncompressed point 0x04||X||Y.
    /// RSA: the DER of the RSAPublicKey SEQUENCE { modulus, publicExponent }.
    /// In every case this is the subjectPublicKey BIT STRING contents with the
    /// leading unused-bits byte stripped. Use `rsa_n_e()` to split RSA into n/e.
    pub spki_key: &'a [u8],
    pub not_before: DateTime,
    pub not_after: DateTime,
    pub sig_alg: SigAlg,
    /// signatureValue BIT STRING contents, unused-bits byte stripped.
    pub signature: &'a [u8],

    /// Raw DER of the issuer Name, the full TLV (tag+len+contents). These are the
    /// exact bytes that must equal a candidate issuer certificate's subject Name
    /// for the two to chain, so the comparison is a byte-for-byte DER match.
    pub issuer: &'a [u8],
    /// Raw DER of the subject Name, the full TLV. Compared against a child
    /// certificate's `issuer` when walking a chain.
    pub subject_raw: &'a [u8],

    // Internal borrowed regions kept for lazy field access.
    subject: &'a [u8],           // RDNSequence contents (inside the SEQUENCE)
    extensions: Option<&'a [u8]>, // Extensions SEQUENCE contents
}

/// Parse a single DER-encoded X.509 certificate. Returns `None` on any
/// malformed, short, or structurally inconsistent input.
pub fn parse_certificate(der: &[u8]) -> Option<Cert<'_>> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (tag, body, _) = read_tlv(der)?;
    if tag != TAG_SEQUENCE {
        return None;
    }

    // tbsCertificate (capture full TLV including header).
    let (t_tbs, tbs_body, tbs_len) = read_tlv(body)?;
    if t_tbs != TAG_SEQUENCE {
        return None;
    }
    let tbs_full = body.get(..tbs_len)?;
    let after_tbs = body.get(tbs_len..)?;

    // signatureAlgorithm
    let (t_sa, sa_body, sa_len) = read_tlv(after_tbs)?;
    if t_sa != TAG_SEQUENCE {
        return None;
    }
    let after_sa = after_tbs.get(sa_len..)?;

    // signatureValue BIT STRING
    let (t_sv, sv_body, _) = read_tlv(after_sa)?;
    if t_sv != TAG_BITSTRING {
        return None;
    }
    let signature = bitstring_contents(sv_body)?;
    let sig_alg = parse_alg_oid_sig(sa_body);

    // ---- Walk TBSCertificate fields in order ----
    let mut rest = tbs_body;

    // [0] version (optional, explicit)
    if let Some((t, _, c)) = read_tlv(rest) {
        if t == TAG_CTX_0 {
            rest = rest.get(c..)?;
        }
    }
    // serialNumber INTEGER
    rest = skip_one(rest)?;
    // signature AlgorithmIdentifier
    rest = skip_one(rest)?;
    // issuer Name (capture the full TLV for chain matching)
    let (t_iss, _, iss_len) = read_tlv(rest)?;
    if t_iss != TAG_SEQUENCE {
        return None;
    }
    let issuer = rest.get(..iss_len)?;
    rest = rest.get(iss_len..)?;

    // validity SEQUENCE { notBefore, notAfter }
    let (t_val, val_body, val_len) = read_tlv(rest)?;
    if t_val != TAG_SEQUENCE {
        return None;
    }
    let (t_nb, nb, nb_len) = read_tlv(val_body)?;
    let not_before = parse_time(t_nb, nb)?;
    let (t_na, na, _) = read_tlv(val_body.get(nb_len..)?)?;
    let not_after = parse_time(t_na, na)?;
    rest = rest.get(val_len..)?;

    // subject Name (RDNSequence)
    let (t_sub, subject, sub_len) = read_tlv(rest)?;
    if t_sub != TAG_SEQUENCE {
        return None;
    }
    let subject_raw = rest.get(..sub_len)?;
    rest = rest.get(sub_len..)?;

    // subjectPublicKeyInfo SEQUENCE { algorithm, subjectPublicKey }
    let (t_spki, spki_body, spki_len) = read_tlv(rest)?;
    if t_spki != TAG_SEQUENCE {
        return None;
    }
    let (t_alg, alg_body, alg_len) = read_tlv(spki_body)?;
    if t_alg != TAG_SEQUENCE {
        return None;
    }
    let (t_key, key_bits, _) = read_tlv(spki_body.get(alg_len..)?)?;
    if t_key != TAG_BITSTRING {
        return None;
    }
    let spki_key = bitstring_contents(key_bits)?;
    let spki_alg = parse_spki_alg(alg_body);
    rest = rest.get(spki_len..)?;

    // Optional [1] issuerUID, [2] subjectUID, [3] extensions.
    let mut extensions = None;
    let mut r = rest;
    while let Some((tag, content, consumed)) = read_tlv(r) {
        if tag == TAG_CTX_3 {
            // [3] explicit wraps a SEQUENCE OF Extension.
            if let Some((te, ext_seq, _)) = read_tlv(content) {
                if te == TAG_SEQUENCE {
                    extensions = Some(ext_seq);
                }
            }
        }
        r = match r.get(consumed..) {
            Some(x) => x,
            None => break,
        };
    }

    Some(Cert {
        raw: der,
        tbs: tbs_full,
        spki_alg,
        spki_key,
        not_before,
        not_after,
        sig_alg,
        signature,
        issuer,
        subject_raw,
        subject,
        extensions,
    })
}

impl<'a> Cert<'a> {
    /// The commonName attribute value from the Subject RDNSequence, if present.
    pub fn subject_cn(&self) -> Option<&'a [u8]> {
        let mut r = self.subject;
        while let Some((tag, set_body, consumed)) = read_tlv(r) {
            if tag == TAG_SET {
                let mut a = set_body;
                while let Some((t_atv, atv, c_atv)) = read_tlv(a) {
                    if t_atv == TAG_SEQUENCE {
                        if let Some((t_oid, oid, oid_len)) = read_tlv(atv) {
                            if t_oid == TAG_OID && oid == OID_CN {
                                if let Some((_, val, _)) = read_tlv(atv.get(oid_len..)?) {
                                    return Some(val);
                                }
                            }
                        }
                    }
                    a = a.get(c_atv..)?;
                }
            }
            r = r.get(consumed..)?;
        }
        None
    }

    /// Invoke `f` with each dNSName in the SubjectAltName extension.
    pub fn for_each_san_dns(&self, f: impl FnMut(&[u8])) {
        self.for_each_san(TAG_SAN_DNS, f);
    }

    /// Invoke `f` with each SubjectAltName GeneralName whose context tag is
    /// `want_tag` (e.g. [2] dNSName = 0x82, [7] iPAddress = 0x87).
    fn for_each_san(&self, want_tag: u8, mut f: impl FnMut(&[u8])) {
        let exts = match self.extensions {
            Some(e) => e,
            None => return,
        };
        let mut r = exts;
        while let Some((tag, ext, consumed)) = read_tlv(r) {
            if tag == TAG_SEQUENCE {
                if let Some((t_oid, oid, oid_len)) = read_tlv(ext) {
                    if t_oid == TAG_OID && oid == OID_SAN {
                        if let Some(after) = ext.get(oid_len..) {
                            emit_san(after, want_tag, &mut f);
                        }
                    }
                }
            }
            r = match r.get(consumed..) {
                Some(x) => x,
                None => break,
            };
        }
    }

    /// True if `ip` (4-byte IPv4) matches an iPAddress SubjectAltName.
    pub fn matches_ip(&self, ip: &[u8; 4]) -> bool {
        let mut matched = false;
        self.for_each_san(TAG_SAN_IP, |name| {
            if name == ip {
                matched = true;
            }
        });
        matched
    }

    /// True if `host` matches a SAN dNSName (single leading `*.` wildcard
    /// matches exactly one label), or the subject CN if no SAN dNSName exists.
    /// Case-insensitive.
    pub fn matches_dns(&self, host: &str) -> bool {
        let host = host.as_bytes();
        let mut found = false;
        let mut matched = false;
        self.for_each_san_dns(|name| {
            found = true;
            if dns_match(name, host) {
                matched = true;
            }
        });
        if found {
            return matched;
        }
        match self.subject_cn() {
            Some(cn) => dns_match(cn, host),
            None => false,
        }
    }

    /// For an RSA key, split `spki_key` (the RSAPublicKey SEQUENCE) into the
    /// raw modulus and exponent INTEGER contents. Leading 0x00 sign padding on
    /// the modulus is stripped. Returns `None` for non-RSA keys or bad DER.
    pub fn rsa_n_e(&self) -> Option<(&'a [u8], &'a [u8])> {
        if self.spki_alg != SpkiAlg::Rsa {
            return None;
        }
        let (t, seq, _) = read_tlv(self.spki_key)?;
        if t != TAG_SEQUENCE {
            return None;
        }
        let (t_n, n, n_len) = read_tlv(seq)?;
        if t_n != TAG_INTEGER {
            return None;
        }
        let (t_e, e, _) = read_tlv(seq.get(n_len..)?)?;
        if t_e != TAG_INTEGER {
            return None;
        }
        let n = if n.first() == Some(&0x00) { n.get(1..)? } else { n };
        Some((n, e))
    }

    /// The basicConstraints CA flag. True only when the extension is present with
    /// `cA = TRUE`. A missing extension, or `cA = FALSE`, is false, so a leaf can
    /// never stand in as a chain issuer.
    pub fn is_ca(&self) -> bool {
        let exts = match self.extensions {
            Some(e) => e,
            None => return false,
        };
        let mut r = exts;
        while let Some((tag, ext, consumed)) = read_tlv(r) {
            if tag == TAG_SEQUENCE {
                if let Some((t_oid, oid, oid_len)) = read_tlv(ext) {
                    if t_oid == TAG_OID && oid == OID_BASIC_CONSTRAINTS {
                        if let Some(after) = ext.get(oid_len..) {
                            return basic_constraints_ca(after);
                        }
                    }
                }
            }
            r = match r.get(consumed..) {
                Some(x) => x,
                None => break,
            };
        }
        false
    }

    /// The SEC1 uncompressed point (0x04 || X || Y, 65 bytes) for a P-256 key.
    pub fn ec_p256_point(&self) -> Option<&'a [u8]> {
        if self.spki_alg != SpkiAlg::EcP256 || self.spki_key.len() != 65 || self.spki_key[0] != 0x04
        {
            return None;
        }
        Some(self.spki_key)
    }

    /// The raw 32-byte public key for an Ed25519 certificate.
    pub fn ed25519_key(&self) -> Option<&'a [u8]> {
        if self.spki_alg != SpkiAlg::Ed25519 || self.spki_key.len() != 32 {
            return None;
        }
        Some(self.spki_key)
    }
}

// ---- SAN helper (kept out of the closure to satisfy the borrow checker) ----
fn emit_san(after_oid: &[u8], want_tag: u8, f: &mut impl FnMut(&[u8])) {
    let mut rest = after_oid;
    // optional critical BOOLEAN
    if let Some((tb, _, cb)) = read_tlv(rest) {
        if tb == TAG_BOOLEAN {
            rest = match rest.get(cb..) {
                Some(x) => x,
                None => return,
            };
        }
    }
    // extnValue OCTET STRING wrapping SEQUENCE OF GeneralName
    let octet = match read_tlv(rest) {
        Some((t, o, _)) if t == TAG_OCTETSTRING => o,
        _ => return,
    };
    let gnames = match read_tlv(octet) {
        Some((t, g, _)) if t == TAG_SEQUENCE => g,
        _ => return,
    };
    let mut g = gnames;
    while let Some((tg, name, cg)) = read_tlv(g) {
        if tg == want_tag {
            f(name);
        }
        g = match g.get(cg..) {
            Some(x) => x,
            None => break,
        };
    }
}

// ---- basicConstraints helper ----------------------------------------------
fn basic_constraints_ca(after_oid: &[u8]) -> bool {
    let mut rest = after_oid;
    // optional critical BOOLEAN
    if let Some((tb, _, cb)) = read_tlv(rest) {
        if tb == TAG_BOOLEAN {
            rest = match rest.get(cb..) {
                Some(x) => x,
                None => return false,
            };
        }
    }
    // extnValue OCTET STRING wrapping SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
    let octet = match read_tlv(rest) {
        Some((t, o, _)) if t == TAG_OCTETSTRING => o,
        _ => return false,
    };
    let seq = match read_tlv(octet) {
        Some((t, s, _)) if t == TAG_SEQUENCE => s,
        _ => return false,
    };
    // cA BOOLEAN (optional, DEFAULT FALSE): present and TRUE (0xFF) means a CA.
    match read_tlv(seq) {
        Some((t, v, _)) if t == TAG_BOOLEAN => v.first() == Some(&0xFF),
        _ => false,
    }
}

// ---- DER reader -----------------------------------------------------------

/// Read one definite-length TLV at the start of `input`.
/// Returns (tag, content, total_bytes_consumed). Rejects indefinite form and
/// lengths that overrun the buffer. Never panics.
fn read_tlv(input: &[u8]) -> Option<(u8, &[u8], usize)> {
    let tag = *input.first()?;
    let first = *input.get(1)?;
    let (len, hdr) = if first & 0x80 == 0 {
        (first as usize, 2)
    } else {
        let num = (first & 0x7f) as usize;
        if num == 0 || num > 4 {
            return None; // indefinite form or absurdly long
        }
        let mut l: usize = 0;
        for i in 0..num {
            l = (l << 8) | (*input.get(2 + i)? as usize);
        }
        (l, 2 + num)
    };
    let end = hdr.checked_add(len)?;
    let content = input.get(hdr..end)?;
    Some((tag, content, end))
}

/// Skip exactly one TLV, returning the remaining slice after it.
fn skip_one(input: &[u8]) -> Option<&[u8]> {
    let (_, _, consumed) = read_tlv(input)?;
    input.get(consumed..)
}

/// BIT STRING contents minus the leading unused-bits count byte.
fn bitstring_contents(bs: &[u8]) -> Option<&[u8]> {
    let (&unused, rest) = bs.split_first()?;
    if unused != 0 {
        return None; // keys and signatures are byte-aligned
    }
    Some(rest)
}

// ---- Algorithm mapping ----------------------------------------------------

fn parse_spki_alg(alg_body: &[u8]) -> SpkiAlg {
    let (t_oid, oid, oid_len) = match read_tlv(alg_body) {
        Some(v) => v,
        None => return SpkiAlg::Other,
    };
    if t_oid != TAG_OID {
        return SpkiAlg::Other;
    }
    if oid == OID_ED25519 {
        SpkiAlg::Ed25519
    } else if oid == OID_RSA {
        SpkiAlg::Rsa
    } else if oid == OID_EC_PUBKEY {
        match alg_body.get(oid_len..).and_then(read_tlv) {
            Some((t, curve, _)) if t == TAG_OID && curve == OID_P256 => SpkiAlg::EcP256,
            _ => SpkiAlg::Other,
        }
    } else {
        SpkiAlg::Other
    }
}

fn parse_alg_oid_sig(alg_body: &[u8]) -> SigAlg {
    match read_tlv(alg_body) {
        Some((t, oid, _)) if t == TAG_OID => {
            if oid == OID_ED25519 {
                SigAlg::Ed25519
            } else if oid == OID_ECDSA_SHA256 {
                SigAlg::EcdsaP256Sha256
            } else if oid == OID_SHA256_RSA {
                SigAlg::RsaPkcs1Sha256
            } else if oid == OID_RSA_PSS {
                SigAlg::RsaPssSha256
            } else {
                SigAlg::Other
            }
        }
        _ => SigAlg::Other,
    }
}

// ---- Time parsing ---------------------------------------------------------

fn two(b: &[u8], i: usize) -> Option<u16> {
    let hi = *b.get(i)?;
    let lo = *b.get(i + 1)?;
    if !hi.is_ascii_digit() || !lo.is_ascii_digit() {
        return None;
    }
    Some((hi - b'0') as u16 * 10 + (lo - b'0') as u16)
}

fn parse_time(tag: u8, s: &[u8]) -> Option<DateTime> {
    match tag {
        TAG_UTCTIME => {
            // YYMMDDHHMMSSZ
            if s.len() < 13 {
                return None;
            }
            let yy = two(s, 0)?;
            let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
            build_dt(year, s, 2)
        }
        TAG_GENTIME => {
            // YYYYMMDDHHMMSSZ
            if s.len() < 15 {
                return None;
            }
            let year = two(s, 0)? * 100 + two(s, 2)?;
            build_dt(year, s, 4)
        }
        _ => None,
    }
}

fn build_dt(year: u16, s: &[u8], off: usize) -> Option<DateTime> {
    Some(DateTime {
        year,
        month: two(s, off)? as u8,
        day: two(s, off + 2)? as u8,
        hour: two(s, off + 4)? as u8,
        min: two(s, off + 6)? as u8,
        sec: two(s, off + 8)? as u8,
    })
}

// ---- DNS name matching ----------------------------------------------------

fn eq_ci(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn dns_match(pattern: &[u8], host: &[u8]) -> bool {
    if let Some(suffix) = pattern.strip_prefix(b"*") {
        // suffix begins with '.', e.g. ".example.com"
        if suffix.first() != Some(&b'.') {
            return false;
        }
        let dot = match host.iter().position(|&c| c == b'.') {
            Some(d) => d,
            None => return false,
        };
        if dot == 0 {
            return false; // empty leading label
        }
        let rest = &host[dot..]; // includes the dot
        return eq_ci(rest, suffix);
    }
    eq_ci(pattern, host)
}
