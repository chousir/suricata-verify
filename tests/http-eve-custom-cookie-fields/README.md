Test that every `Cookie` and `Set-Cookie` HTTP header in the pcap is
logged into `http.request_headers` / `http.response_headers` in eve.json
when listed under the `custom` option of the `http` eve-log logger, since
these two headers are not logged by default (not even with
`extended: yes`).

The expected counts (461 requests with `Cookie`, 61 responses with
`Set-Cookie`) are the number of HTTP transactions Suricata itself parses
out of the pcap; they were confirmed to be stable/reproducible across
runs. They were also cross-checked against an independent parse of the
same pcap with `tshark`, which found 460 requests with a `Cookie` header
(off by 1) and 51 responses with a `Set-Cookie` header (off by 10). This
is a real, messy ~2011 traffic capture with HTTP pipelining and some
out-of-order/incomplete streams (libhtp emits a handful of
`/libhtp::request_uri_not_seen` pseudo-transactions for responses it
couldn't match to a request), so it isn't surprising that two independent
HTTP implementations (libhtp vs. tshark's dissector) disagree at the
margins on exactly how many transactions those bytes represent. This
count should be read as "what Suricata currently and reproducibly parses
from this pcap", not as an independently-verified ground truth to the
last header.

Re-uses the pcap from the `http-sticky-server` test.

## PCAP origin

See `../http-sticky-server/`.
