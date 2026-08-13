#!/usr/bin/env python3
"""Generate input.pcap for imap-literal-multiple-fetch.

Two literal-bearing FETCH responses back to back in the same response
batch, proving IMAPState.literal_remaining resets cleanly after the
first literal completes rather than bleeding into the second.
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

fetch = b"a2 FETCH 1:2 (RFC822)\r\n"
pkts.append(cli("PA", c_seq, s_seq, fetch))
c_seq += len(fetch)
pkts.append(srv("A", s_seq, c_seq))

literal_a = b"0123456789"
literal_b = b"ABCDEFGHIJKL"
resp = ("* 1 FETCH (RFC822 {%d}\r\n" % len(literal_a)).encode() + literal_a + b")\r\n"
resp += ("* 2 FETCH (RFC822 {%d}\r\n" % len(literal_b)).encode() + literal_b + b")\r\n"
resp += b"a2 OK FETCH completed\r\n"
pkts.append(srv("PA", s_seq, c_seq, resp))
s_seq += len(resp)
pkts.append(cli("A", c_seq, s_seq))

pkts.append(cli("FA", c_seq, s_seq))
c_seq += 1
pkts.append(srv("FA", s_seq, c_seq))
s_seq += 1
pkts.append(cli("A", c_seq, s_seq))

wrpcap("input.pcap", pkts)
print("literal sizes:", len(literal_a), len(literal_b))
