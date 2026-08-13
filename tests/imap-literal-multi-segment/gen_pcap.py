#!/usr/bin/env python3
"""Generate input.pcap for imap-literal-multi-segment.

The FETCH literal body is split across two TCP segments at a byte
offset that does NOT land on a line boundary, exercising
IMAPState.literal_remaining persisting the declared byte count across
separate parse_response() calls.
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

fetch = b"a2 FETCH 1 (RFC822)\r\n"
pkts.append(cli("PA", c_seq, s_seq, fetch))
c_seq += len(fetch)
pkts.append(srv("A", s_seq, c_seq))

literal = b"Received: from\r\nHello world example message!\r\n"
header = ("* 1 FETCH (RFC822 {%d}\r\n" % len(literal)).encode()
tail = b")\r\na2 OK FETCH completed\r\n"
full = header + literal + tail

# Split strictly inside the literal body, not on a CRLF boundary.
split = len(header) + len(literal) // 2
seg_a, seg_b = full[:split], full[split:]

pkts.append(srv("PA", s_seq, c_seq, seg_a))
s_seq += len(seg_a)
pkts.append(cli("A", c_seq, s_seq))

pkts.append(srv("PA", s_seq, c_seq, seg_b))
s_seq += len(seg_b)
pkts.append(cli("A", c_seq, s_seq))

pkts.append(cli("FA", c_seq, s_seq))
c_seq += 1
pkts.append(srv("FA", s_seq, c_seq))
s_seq += 1
pkts.append(cli("A", c_seq, s_seq))

wrpcap("input.pcap", pkts)
print("literal size:", len(literal), "split at:", split, "segment lens:", len(seg_a), len(seg_b))
