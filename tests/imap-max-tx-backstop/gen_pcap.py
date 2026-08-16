#!/usr/bin/env python3
"""Generate input.pcap for imap-max-tx-backstop.

20 LOGIN commands packed into a single client->server TCP segment, none of
them ever getting a response. Regression coverage for the new_tx()
IMAP_MAX_TX backstop (rust/src/applayerimap/imap.rs): with
app-layer.protocols.imap.max-tx set low in test.yaml, this proves the
parser stops allocating new AUTH transactions once the cap is passed
(instead of letting one pathological segment drive an unbounded burst of
allocations before the next AppLayerParserTransactionsCleanup pass can
run), raises app-layer event `too_many_transactions`, and does not put the
flow's app-layer parser into an error state.
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

logins = b"".join(("a%d LOGIN user pass\r\n" % i).encode() for i in range(20))
pkts.append(cli("PA", c_seq, s_seq, logins))
c_seq += len(logins)
pkts.append(srv("A", s_seq, c_seq))

pkts.append(cli("FA", c_seq, s_seq))
c_seq += 1
pkts.append(srv("FA", s_seq, c_seq))
s_seq += 1
pkts.append(cli("A", c_seq, s_seq))

wrpcap("input.pcap", pkts)
print("logins:", 20)
