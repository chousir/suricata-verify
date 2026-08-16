#!/usr/bin/env python3
"""Generate input.pcap for imap-append-async-oneside.

A one-sided (asynchronous) capture of an IMAP APPEND upload: only the
client->server direction is present, as with asymmetric routing or a
one-sided tap. Modeled on imap-append-basic/gen_pcap.py, but with every
server->client packet removed and the handshake replaced by a bare SYN
followed immediately by an ACK from the same host (acking a SYN-ACK that
was never captured) -- the same signature bug-8629-async-oneside/input.pcap
uses, which is how the stream engine detects an asynchronous stream.
"""
from scapy.all import IP, TCP, Raw, wrpcap

CLIENT = ("10.0.0.1", 52000)
SERVER = ("10.0.0.2", 143)


def cli(flags, seq, ack, payload=b""):
    pkt = IP(src=CLIENT[0], dst=SERVER[0]) / TCP(
        sport=CLIENT[1], dport=SERVER[1], flags=flags, seq=seq, ack=ack, window=65535
    )
    return pkt / Raw(payload) if payload else pkt


pkts = []
c_seq = 1000
# The server's ISN was never captured; ack is just made up, as it would be
# by a real client acking a SYN-ACK this capture never saw.
s_seq_guess = 5001

pkts.append(cli("S", c_seq, 0))
c_seq += 1
pkts.append(cli("A", c_seq, s_seq_guess))

login = b"a1 LOGIN user pass\r\n"
pkts.append(cli("PA", c_seq, s_seq_guess, login))
c_seq += len(login)

literal = b"Received: from\r\nHello world, uploaded via APPEND!\r\n"
header = ("a2 APPEND INBOX (\\Seen) {%d}\r\n" % len(literal)).encode()
full = header + literal
pkts.append(cli("PA", c_seq, s_seq_guess, full))
c_seq += len(full)

pkts.append(cli("RA", c_seq, s_seq_guess))

wrpcap("input.pcap", pkts)
print("literal size:", len(literal))
