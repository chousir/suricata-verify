#!/usr/bin/env python3
"""Generate input.pcap for imap-literal-gap-mid-literal.

Regression test for a data-corruption bug: on a TCP stream gap occurring
mid-FETCH-literal, IMAPState.literal_remaining used to survive the gap
uncleared, causing the parser to resume consuming the *next*, unrelated
FETCH response's leading bytes as if they were leftover literal content
of the gapped file -- silently corrupting the old file (falsely reported
CLOSED/gaps:false) while losing the new message's own extraction
entirely (no fileinfo event at all).

The first FETCH response's literal is split across two server segments;
the second segment's byte range is dropped entirely (not just held back
-- the packet is omitted from the pcap while sequence numbers still
advance across it), producing a genuine STREAM_GAP mid-literal. A
second, complete, in-sync FETCH follows immediately after.
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

fetch1 = b"a2 FETCH 1 (RFC822)\r\n"
pkts.append(cli("PA", c_seq, s_seq, fetch1))
c_seq += len(fetch1)
pkts.append(srv("A", s_seq, c_seq))

literal1 = b"Received: from\r\nHello world example message, gapped mid literal!\r\n"
header1 = ("* 1 FETCH (RFC822 {%d}\r\n" % len(literal1)).encode()
tail1 = b")\r\na2 OK FETCH completed\r\n"
full1 = header1 + literal1 + tail1
split1 = len(header1) + len(literal1) // 2
seg_a, seg_b = full1[:split1], full1[split1:]

# seg_a IS sent (this is what actually reaches the wire / suricata).
pkts.append(srv("PA", s_seq, c_seq, seg_a))
s_seq += len(seg_a)

# seg_b is DROPPED (never appended to pkts) -- sequence space still
# advances as if it had been sent, so the next real segment arrives at a
# higher, discontiguous offset, producing a genuine STREAM_GAP.
s_seq += len(seg_b)

pkts.append(cli("A", c_seq, s_seq))

# Second, complete, in-sync FETCH after the gap -- tests resync and that
# the new message's own extraction is not corrupted by gap leftovers.
fetch2 = b"a3 FETCH 2 (RFC822)\r\n"
pkts.append(cli("PA", c_seq, s_seq, fetch2))
c_seq += len(fetch2)
pkts.append(srv("A", s_seq, c_seq))

literal2 = b"Received: from\r\nSecond message, should parse cleanly after gap.\r\n"
header2 = ("* 2 FETCH (RFC822 {%d}\r\n" % len(literal2)).encode()
tail2 = b")\r\na3 OK FETCH completed\r\n"
full2 = header2 + literal2 + tail2

pkts.append(srv("PA", s_seq, c_seq, full2))
s_seq += len(full2)
pkts.append(cli("A", c_seq, s_seq))

pkts.append(cli("FA", c_seq, s_seq))
c_seq += 1
pkts.append(srv("FA", s_seq, c_seq))
s_seq += 1
pkts.append(cli("A", c_seq, s_seq))

wrpcap("input.pcap", pkts)
print(
    "literal1 size:", len(literal1),
    "bytes delivered before gap:", len(seg_a) - len(header1),
    "gap bytes dropped:", len(seg_b),
)
print("literal2 size:", len(literal2))
