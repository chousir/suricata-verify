#!/usr/bin/env python3
"""Generate input.pcap for imap-literal-midstream-toclient.

A partially one-sided capture: the connection's original SYN (and
anything that would have preceded it, e.g. a LOGIN) was missed entirely
(e.g. asymmetric routing / a tap that started mid-conversation); the
first packet ever observed is the server's bare SYN/ACK, picked up by
Suricata's stream.midstream handling (see the (TH_SYN|TH_ACK) branch of
StreamTcpPacketStateNone() in src/stream-tcp.c, which correctly learns
the server's real advertised window from that SYN/ACK). The only other
packets are a single client ACK completing the picked-up handshake and
the server's FETCH literal response - no IMAP request is ever captured,
proving FETCH literal parsing on the response side does not depend on
having observed any prior request.

Note: stream.async-oneside was tried first for this "toclient-only"
shape, but does not work here: that mechanism only learns a real window
for whichever side sent the original SYN, and unconditionally drops the
async relaxation the instant a packet from the *other* side appears -
so the first (and only) toclient data packet gets rejected as
out-of-window before app-layer ever sees it. stream.midstream, entered
via a bare SYN/ACK, properly learns the server's window up front, so it
is used here instead.
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
# The client's SYN was never captured; only its (fabricated, never-seen)
# ISN needs to be self-consistent with the SYN/ACK's ack field below.
c_isn = 1000
s_seq = 9000

# First packet ever observed: the server's bare SYN/ACK.
pkts.append(srv("SA", s_seq, c_isn + 1))
s_seq += 1

# A bare ACK from the client completes the picked-up handshake (the
# session moves to ESTABLISHED). This is the only toserver packet ever
# captured - no LOGIN or FETCH command is ever seen, only this control
# ACK - so the FETCH literal response that follows is parsed with no
# prior request context at all.
pkts.append(cli("A", c_isn + 1, s_seq))

# The server's FETCH literal response - the only packet carrying any
# application data in the whole capture.
literal = b"Received: from\r\n"
resp = ("* 1 FETCH (RFC822 {%d}\r\n" % len(literal)).encode() + literal
resp += b")\r\na2 OK FETCH completed\r\n"
pkts.append(srv("PA", s_seq, c_isn + 1, resp))

wrpcap("input.pcap", pkts)
print("literal size:", len(literal))
