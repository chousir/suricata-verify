#!/usr/bin/env python3
"""Generate input.pcap for imap-append-fetch-concurrent.

The cross-direction-contamination guard: a FETCH response literal is left
half-delivered (literal_remaining > 0) while a complete, unrelated APPEND
request literal is sent and fully consumed on the same flow, before the
FETCH literal's remaining bytes arrive. Different sizes and content on
each side.

This is exactly the scenario `IMAPState.literal_remaining` (response) and
`IMAPState.request_literal_remaining` (request) being separate fields is
meant to protect: if they were ever collapsed into a single shared
counter, processing the interleaved APPEND would corrupt the in-progress
FETCH literal's state (or vice versa), and this test would fail --
producing a wrong-sized or missing fileinfo event on one side or the
other.
"""
from scapy.all import IP, TCP, Raw, wrpcap

CLIENT = ("10.0.0.1", 52000)
SERVER = ("10.0.0.2", 143)


def cli(flags, seq, ack, payload=b""):
    pkt = IP(src=CLIENT[0], dst=SERVER[0]) / TCP(
        sport=CLIENT[1], dport=SERVER[1], flags=flags, seq=seq, ack=ack, window=65535
    )
    return pkt / Raw(payload) if payload else pkt


def srv(flags, seq, ack, payload=b""):
    pkt = IP(src=SERVER[0], dst=CLIENT[0]) / TCP(
        sport=SERVER[1], dport=CLIENT[1], flags=flags, seq=seq, ack=ack, window=65535
    )
    return pkt / Raw(payload) if payload else pkt


pkts = []
c_seq = 1000
s_seq = 5000

pkts.append(cli("S", c_seq, 0))
c_seq += 1
pkts.append(srv("SA", s_seq, c_seq))
s_seq += 1
pkts.append(cli("A", c_seq, s_seq))

greeting = b"* OK IMAP4rev1 Service Ready\r\n"
pkts.append(srv("PA", s_seq, c_seq, greeting))
s_seq += len(greeting)
pkts.append(cli("A", c_seq, s_seq))

login = b"a1 LOGIN user pass\r\n"
pkts.append(cli("PA", c_seq, s_seq, login))
c_seq += len(login)
pkts.append(srv("A", s_seq, c_seq))

login_ok = b"a1 OK LOGIN completed\r\n"
pkts.append(srv("PA", s_seq, c_seq, login_ok))
s_seq += len(login_ok)
pkts.append(cli("A", c_seq, s_seq))

fetch_req = b"a2 FETCH 1 (RFC822)\r\n"
pkts.append(cli("PA", c_seq, s_seq, fetch_req))
c_seq += len(fetch_req)
pkts.append(srv("A", s_seq, c_seq))

# Server starts streaming the FETCH response but only delivers the header
# plus the first half of the literal -- leaving literal_remaining > 0.
literal_fetch = b"FETCH-RESPONSE-DATA"
header_fetch = ("* 1 FETCH (RFC822 {%d}\r\n" % len(literal_fetch)).encode()
full_fetch = header_fetch + literal_fetch
split_fetch = len(header_fetch) + 10
seg_fetch_a, seg_fetch_b = full_fetch[:split_fetch], full_fetch[split_fetch:]

pkts.append(srv("PA", s_seq, c_seq, seg_fetch_a))
s_seq += len(seg_fetch_a)
pkts.append(cli("A", c_seq, s_seq))

# Before the FETCH literal completes, the client sends a full, unrelated
# APPEND (different size, different content) on the same flow.
literal_append = b"UPLOADED"  # 8 bytes
header_append = ("a3 APPEND INBOX {%d}\r\n" % len(literal_append)).encode()
full_append = header_append + literal_append

pkts.append(cli("PA", c_seq, s_seq, full_append))
c_seq += len(full_append)
pkts.append(srv("A", s_seq, c_seq))

# Only now does the server finish delivering the FETCH literal's back half.
pkts.append(srv("PA", s_seq, c_seq, seg_fetch_b))
s_seq += len(seg_fetch_b)
pkts.append(cli("A", c_seq, s_seq))

pkts.append(cli("FA", c_seq, s_seq))
c_seq += 1
pkts.append(srv("FA", s_seq, c_seq))
s_seq += 1
pkts.append(cli("A", c_seq, s_seq))

wrpcap("input.pcap", pkts)
print("fetch literal size:", len(literal_fetch), "append literal size:", len(literal_append))
