Same as `../http-eve-custom-cookie-fields/`, but verify that a response
`Set-Cookie` header is still parsed and logged when only the
server->client side of the traffic is available (asymmetric routing /
one-sided capture), with `stream.async-oneside: true` enabled.

## PCAP origin

`input.pcap` is derived from `../http-sticky-server/http-sticky-server.pcap`
by keeping only a single TCP session (`tcp.stream==132`, a
`bs.serving-sys.com` request/response with a `Cookie`/`Set-Cookie` pair),
then keeping only the packets sent from the HTTP server port:

```
tshark -r http-sticky-server.pcap -Y "tcp.stream==132" -w session.pcap
tshark -r session.pcap -Y "tcp.srcport==80" -w input.pcap
```

This drops every client->server packet (SYN, request data), leaving only
the server's SYN-ACK/response-data packets for this one flow. Since
libhtp never sees a request, the response is logged as a
`/libhtp::request_uri_not_seen` pseudo-transaction. The response sets 4
separate `Set-Cookie` headers, which libhtp folds into a single
comma-joined `response_headers` entry.
