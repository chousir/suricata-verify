#!/usr/bin/env python3
"""Generate input.pcap for imap-append-basic.

Client LOGINs then APPENDs a single message to a mailbox using a `{n}`
literal, entirely within one TCP segment per direction. Exercises the new
request-side (client->server) literal extraction path added for IMAP
APPEND, mirroring imap-literal-basic's FETCH-response coverage.
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

literal = b"Received: from\r\nHello world, uploaded via APPEND!\r\n"
header = ("a2 APPEND INBOX (\\Seen) {%d}\r\n" % len(literal)).encode()
full = header + literal
pkts.append(cli("PA", c_seq, s_seq, full))
c_seq += len(full)
pkts.append(srv("A", s_seq, c_seq))

append_ok = b"a2 OK APPEND completed\r\n"
pkts.append(srv("PA", s_seq, c_seq, append_ok))
s_seq += len(append_ok)
pkts.append(cli("A", c_seq, s_seq))

pkts.append(cli("FA", c_seq, s_seq))
c_seq += 1
pkts.append(srv("FA", s_seq, c_seq))
s_seq += 1
pkts.append(cli("A", c_seq, s_seq))

wrpcap("input.pcap", pkts)
print("literal size:", len(literal))
