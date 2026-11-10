# Xray client compatibility update, 2026-11-11

Requested scope: update Sing-Box X client interoperability with newer Xray
servers and browser fingerprints. This is a source update, not a published
release or authorization to replace an installed core.

## Implementation

The upstream sing-box base remains pinned at 1.14.2, commit
`af6e64c3b69e6132ebaee0e1a3d24e93903f6709`. Changes are on the existing
Sing-Box X main checkout, whose starting commit was `c5f0134`.

- Add encrypted VLESS outbounds via podkop-engine `v1.14.4-r21` patches
  0098, 0113 and 0118. Supports the native/xorpub/random modes, 1rtt/0rtt,
  key/padding validation, handshake cancellation and Vision on the encrypted
  connection. The original Xray-derived files retain MPL-2.0 notices.
- Retain X's pinned sing-vmess dependency and existing direct-reader patch.
- Advertise `outbound.vless.encryption` in executable features. Existing Forkop
  Go-core generation already preserves the subscription's encryption field;
  no Forkop generator changes or Rust X changes are required.
- Update Chrome to the Chrome 155 specification from Xray's pinned uTLS
  `a13c59ffe98b`. Includes ML-DSA signature advertisements and trust anchors;
  the latter do not change the verifier's trusted roots. Firefox 148 and
  Safari 26.3 already match this Xray generation and are preserved.
- Retain browser hybrid key shares in REALITY. Validate short ID length
  before decoding (podkop patch 0106), avoiding a configuration-check panic.
- Keep the selected fingerprint; no automatic browser fallback, certificate
  verification bypass, new QUIC transport, or SRS/routing changes.

Preparation runs in `scripts/prepare-source.py`; imported patches and browser
assets have hash manifests. BSD uTLS attribution is included in LICENSE.utls
and in the corresponding-source archive. Builds run VLESS/encryption tests
alongside the existing TLS/XHTTP tests, including race checks.

## Verification

The independent peer is the official Xray 26.11.9, commit `676eaf6`, downloaded
from its GitHub release. Its archive SHA-256 matches the published .dgst:
`b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82`.

Reusable harnesses:

- `tests/vless-encryption-xray.py`: loopback-only Xray/server and X/client,
  generated test keys and a localhost trust anchor. Each positive case checks
  three 256 KiB + 37 byte bulk echoes and a 65,573-byte inner TLS echo. It
  supports plain VLESS, Vision, REALITY and explicit browser profiles, as well
  as encrypted TCP and packet-up/stream-up/stream-one XHTTP. Negative SNI,
  key and UUID controls and expired session-ticket recovery are included.
- `tests/fingerprint-xray.py`: capture actual first flights from both official
  Xray and X; compare cipher suites, normalized extension set, signatures,
  groups/key-share lengths, ALPN/ALPS and trust anchors. Random keys, GREASE,
  shuffled extension order and ECH GREASE contents are normalized. This is
  a structural comparison, not a timing or DPI-indistinguishability proof.

Final candidate verification passed:

| Test | Passed cases |
| --- | ---: |
| Xray 26.11.9, Encryption over TLS, with/without Vision | 48 |
| Xray 26.11.9, ordinary REALITY across Chrome/Firefox/Safari | 12 |
| Xray 26.11.9, ordinary REALITY/Vision across those profiles | 3 |
| Xray 26.11.9, Encryption over REALITY, with/without Vision | 48 |
| Xray 26.9.8, Encryption over TLS (backward compatibility) | 24 |
| Xray 26.11.9, encrypted application UDP, with/without Vision | 48 |

Total: 183 positive cases, 549 byte-checked bulk transfers, 183 inner TLS
transfers, and 144 application UDP datagrams (17/1300/4096 bytes). All
negative SNI/key/UUID controls and the included expired-ticket recovery
controls passed. The UDP cases cover TCP and all three XHTTP modes, all
three appearances, and both handshake modes under outer TLS.

Chrome, Firefox and Safari emitted ClientHello structure matched official
Xray 26.11.9 in the independent capture harness. Focused Go unit and race
tests passed for `./protocol/vless/...`, `./common/tls` and
`./transport/v2rayxhttp`. x86_64/ARM64 builds passed and their dependency
graphs retained Clash API/gRPC-lite and excluded QUIC, gVisor and native API.

Final results, peer metadata and effective source hashes are recorded in
`work/compat-verified-20261111/verification.json`. Candidate SHA-256:

- x86_64: `6538a0d0df6ff83c52ab441062939234011a3a9282a2623cc8bc07ed56d19b28`
- ARM64: `bc9b95b7609955b396efc54652b5c34f04fb92fcf30765d98f525539a2e28fa3`

## Limits

These tests do not establish support for every future Xray release, XDRIVE,
every ML-KEM static-key/relay chain, every UDP application or encrypted UDP
over outer REALITY, or universal outer camouflage. ARM64 cross-compilation
alone does not establish on-device
ARM performance. No packages were installed or services restarted on routers
or OpenWrt VMs; all network probes used local generated test configurations.
Version metadata and published packages are unchanged.
