Same as `../http-eve-custom-cookie-fields/`, but verify that a request
`Cookie` header is still parsed and logged when only the client->server
side of the traffic is available (asymmetric routing / one-sided
capture), with `stream.async-oneside: true` enabled.

## PCAP origin

`input.pcap` is derived from `../http-sticky-server/http-sticky-server.pcap`
by keeping only a single TCP session (`tcp.stream==132`, a
`bs.serving-sys.com` request/response with a `Cookie`/`Set-Cookie` pair),
then keeping only the packets sent towards the HTTP server port:

```
tshark -r http-sticky-server.pcap -Y "tcp.stream==132" -w session.pcap
tshark -r session.pcap -Y "tcp.dstport==80" -w input.pcap
```

This drops every server->client packet (SYN-ACK, response data), leaving
only the client's SYN/ACK/request-data packets for this one flow.
