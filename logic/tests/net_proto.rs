//! Known-answer and round-trip tests for the transport-and-resolver wire logic
//! the kernel runs: UDP, DNS (with name compression), TCP, and HTTP parsing, and
//! the Internet checksum. These exercise the exact `kernel/src/proto.rs` source.

use aurora_logic::proto::{
    self, build_dns_query, build_tcp, build_udp, ipv4_checksum, parse_dns_response,
    parse_http_response, parse_tcp, parse_udp, transport_checksum, DnsResult,
};

#[test]
fn ipv4_header_checksum_known_answer() {
    // The classic worked example: a 20-byte IPv4 header with the checksum field
    // zeroed must yield 0xb1e6.
    let hdr: [u8; 20] = [
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a,
        0x63, 0xac, 0x10, 0x0a, 0x0c,
    ];
    assert_eq!(ipv4_checksum(&hdr), 0xb1e6);
}

#[test]
fn udp_build_parse_and_checksum_verifies() {
    let src = [10, 0, 2, 15];
    let dst = [10, 0, 2, 3];
    let payload = b"hello udp";
    let mut out = [0u8; 64];
    let n = build_udp(src, dst, 0xC001, 53, payload, &mut out).unwrap();
    assert_eq!(n, 8 + payload.len());

    let (sp, dp, off, plen) = parse_udp(&out[..n]).unwrap();
    assert_eq!(sp, 0xC001);
    assert_eq!(dp, 53);
    assert_eq!(plen, payload.len());
    assert_eq!(&out[off..off + plen], payload);

    // Verifying the checksum over the datagram that already carries it yields 0
    // (or 0xffff, the UDP all-ones convention).
    let v = transport_checksum(src, dst, proto::IP_PROTO_UDP, &out[..n]);
    assert!(v == 0 || v == 0xffff, "udp checksum did not verify: {v:#06x}");
}

#[test]
fn dns_query_encoding_is_correct() {
    let mut out = [0u8; 512];
    let n = build_dns_query(0x1234, "example.com", &mut out).unwrap();
    // Header: id, flags(RD), qd=1, others 0.
    assert_eq!(&out[0..2], &[0x12, 0x34]);
    assert_eq!(&out[2..4], &[0x01, 0x00]);
    assert_eq!(&out[4..6], &[0x00, 0x01]);
    // Question labels: 7 example 3 com 0, then qtype=1 qclass=1.
    let q = b"\x07example\x03com\x00\x00\x01\x00\x01";
    assert_eq!(&out[12..n], q);
}

#[test]
fn dns_response_with_compression_pointer_parses() {
    // Response for example.com -> 93.184.216.34, answer name is a compression
    // pointer (0xC00C) back to the question name at offset 12.
    let msg: Vec<u8> = vec![
        0x12, 0x34, // id
        0x81, 0x80, // flags: response, RD, RA
        0x00, 0x01, // qdcount
        0x00, 0x01, // ancount
        0x00, 0x00, // nscount
        0x00, 0x00, // arcount
        // question: example.com A IN
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01,
        0x00, 0x01, // answer
        0xc0, 0x0c, // name pointer -> offset 12
        0x00, 0x01, // type A
        0x00, 0x01, // class IN
        0x00, 0x00, 0x01, 0x00, // ttl
        0x00, 0x04, // rdlength
        93, 184, 216, 34, // rdata
    ];
    assert_eq!(parse_dns_response(&msg, 0x1234), DnsResult::Ipv4([93, 184, 216, 34]));
    // A wrong transaction id is rejected.
    assert_eq!(parse_dns_response(&msg, 0x0001), DnsResult::Invalid);
}

#[test]
fn dns_response_cname_then_a_record() {
    // First answer is a CNAME (type 5), second is the A record. The parser must
    // skip the CNAME and its rdata (which itself contains a compressed name).
    let msg: Vec<u8> = vec![
        0xab, 0xcd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // header
        0x03, b'w', b'w', b'w', 0x03, b'a', b'b', b'c', 0x00, 0x00, 0x01, 0x00,
        0x01, // question www.abc A IN
        0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x02, 0xc0,
        0x10, // answer1 CNAME rdlen=2 -> pointer 0xC010
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x10, 0x00, 0x04, 1, 2, 3,
        4, // answer2 A -> 1.2.3.4
    ];
    assert_eq!(parse_dns_response(&msg, 0xabcd), DnsResult::Ipv4([1, 2, 3, 4]));
}

#[test]
fn tcp_build_parse_and_checksum_verifies() {
    let src = [10, 0, 2, 15];
    let dst = [10, 0, 2, 2];
    let payload = b"GET / HTTP/1.0\r\n\r\n";
    let mut out = [0u8; 128];
    let flags = proto::TCP_PSH | proto::TCP_ACK;
    let n = build_tcp(src, dst, 0xC123, 80, 0x1111_2222, 0x3333_4444, flags, 32768, payload, &mut out)
        .unwrap();
    assert_eq!(n, 20 + payload.len());

    let seg = parse_tcp(&out[..n]).unwrap();
    assert_eq!(seg.src_port, 0xC123);
    assert_eq!(seg.dst_port, 80);
    assert_eq!(seg.seq, 0x1111_2222);
    assert_eq!(seg.ack, 0x3333_4444);
    assert_eq!(seg.flags, flags);
    assert_eq!(seg.data_off, 20);
    assert_eq!(seg.data_len, payload.len());
    assert_eq!(&out[seg.data_off..seg.data_off + seg.data_len], payload);

    // A correct TCP checksum verifies to zero.
    assert_eq!(transport_checksum(src, dst, proto::IP_PROTO_TCP, &out[..n]), 0);
}

#[test]
fn tcp_flag_decoding() {
    let mut out = [0u8; 32];
    let n = build_tcp([1, 1, 1, 1], [2, 2, 2, 2], 5, 6, 7, 8, proto::TCP_SYN, 1024, &[], &mut out)
        .unwrap();
    let seg = parse_tcp(&out[..n]).unwrap();
    assert_eq!(seg.flags & proto::TCP_SYN, proto::TCP_SYN);
    assert_eq!(seg.flags & proto::TCP_ACK, 0);
    assert_eq!(seg.data_len, 0);
}

#[test]
fn http_response_parsing() {
    let resp = b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nHELLO";
    let (status, body_off) = parse_http_response(resp).unwrap();
    assert_eq!(status, 200);
    assert_eq!(&resp[body_off..], b"HELLO");

    let r404 = b"HTTP/1.1 404 Not Found\r\n\r\nnope";
    let (s, off) = parse_http_response(r404).unwrap();
    assert_eq!(s, 404);
    assert_eq!(&r404[off..], b"nope");

    // Not HTTP at all.
    assert!(parse_http_response(b"garbage").is_none());
}
