- HTTPS latency tests now measure the HTTP response after the TLS handshake
- Consistent latency measurement for manual tests and automatic URLTest groups
- Connection and TLS failures still obey the full test timeout
- Validated manual tests, provider URLTest and Forkop priority failover/recovery on OpenWrt 24 and 25

Based on sing-box 1.14.2. Existing XHTTP, uTLS and Clash API support is retained.
