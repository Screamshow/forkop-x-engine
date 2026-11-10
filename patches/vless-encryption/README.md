# VLESS Encryption and REALITY validation

Original patches by FiyeroT from podkop-net/podkop-engine tag
`v1.14.4-r21`, commit `aaf75d5397aaaf56a65a35f9ccebf35d3cbd48f3`.
The manifest pins the original patch content (LF line endings).

- 0098/0113 provide the transport/flow context required by 0118.
- 0106 checks REALITY short ID length before hex decoding, for client and
  server. Its test-file hunk is omitted because X retains older fingerprint
  tests; `scripts/browser-update/chrome155_test.go` supplies the client regression.
- 0118 adds the Xray-compatible encrypted VLESS outbound, including Vision.
  `go.mod` is adapted separately to preserve X's existing module replacements.

The project patches are GPL-3.0-or-later. Encryption client/common/xor and
the test-only Xray server retain their original MPL-2.0 notices and attribution
to Xray-core v26.9.30. No Xray server implementation is compiled into X.
The pinned sing-vmess v0.2.8 dependency and X's Vision direct-reader patch are
preserved; the encryption layer registers its Vision buffers with that dependency.

No automatic retry of failed application requests or fingerprint fallback is
introduced. Empty/`none` encryption preserves the ordinary VLESS path.
