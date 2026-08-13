#!/usr/bin/env python3
"""Generate input.pcap for imap-literal-embedded-terminator.

The core regression case for the literal byte-count fix: the FETCH
literal's content contains the exact byte sequence "\r\n)\r\n" partway
through - which is what the pre-fix parser used (wrongly) as its
terminator. A correct parser must consume exactly the declared {n}
octets and not truncate at the embedded sequence.
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

# The literal's own content embeds the old (wrong) terminator "\r\n)\r\n".
literal = b"A\r\n)\r\nB"
resp = ("* 1 FETCH (RFC822 {%d}\r\n" % len(literal)).encode() + literal
resp += b")\r\na2 OK FETCH completed\r\n"
pkts.append(srv("PA", s_seq, c_seq, resp))
s_seq += len(resp)
pkts.append(cli("A", c_seq, s_seq))

pkts.append(cli("FA", c_seq, s_seq))
c_seq += 1
pkts.append(srv("FA", s_seq, c_seq))
s_seq += 1
pkts.append(cli("A", c_seq, s_seq))

wrpcap("input.pcap", pkts)
print("literal size:", len(literal))
