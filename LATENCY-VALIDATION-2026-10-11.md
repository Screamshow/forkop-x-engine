# Post-handshake URLTest validation

HTTPS URLTest starts its reported request timer at `httptrace.GotConn`, after
the proxy connection and destination TLS handshake. The existing context and
client deadlines still cover setup. No additional request is introduced;
the upstream multiplex warm-up remains unchanged. API shape, URLTest selection,
tolerance and Forkop priority rules are unchanged. Plain HTTP uses the same
established-connection request timer. This is HTTP response latency, not ICMP RTT.

Validation on 2026-10-11:

- Targeted URLTest tests passed; race tests passed for URLTest and Clash API.
- Native static test binaries passed on existing OpenWrt 25 and 24 VMware VMs:
  150 ms dial + 350 ms TLS + 50 ms response reported only the response interval.
  A 100 ms deadline still failed during TLS; Connection: close worked.
- Real VLESS/REALITY nodes were imported by Forkop's normal subscription parser
  after download with the VM HWID. Manual node tests, provider group URLTest,
  positive history, manual selector updates and failed-node HTTP errors passed
  on both VMs.
- The actual Forkop priority worker passed fallback, recovery to the higher
  priority node, and failover after that node became unavailable on both VMs.
  Fastest-node selection within a level stayed enabled.
- VM25 baseline manual samples: 206/197/198 ms; candidate: 138/143/141 ms.
  VM24 baseline: 208/207/200 ms; candidate: 137/148/135 ms. Network samples
  fluctuate and are not a performance guarantee.

Candidates ran from `/tmp` on loopback ports without package installation.
Normal VM routing remained active for the successful network checks, so these
are integration checks, not isolated Internet benchmarks. Package inventories
were unchanged and normal Forkop remained healthy. Earlier stop/start trials
rewrote UCI serialization; those trials are not evidence of byte-identical UCI.
Subscription URLs, HWIDs, credentials and raw private logs are excluded here.
No release or package revision was published for this change.
