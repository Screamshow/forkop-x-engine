#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
mkdir -p work dist
readarray -t cfg < <(python3 - <<'PY'
import json
c=json.load(open('build-config.json'))
for key in ('version','upstream_version','upstream_commit','go_version','upx_version','upx_linux_sha256'):
 print(c[key])
print(','.join(c['tags']))
PY
)
version=${cfg[0]}; upstream=${cfg[1]}; commit=${cfg[2]}; go_version=${cfg[3]}; upx_version=${cfg[4]}; upx_hash=${cfg[5]}; tags=${cfg[6]}
[[ ",$tags," != *,with_quic,* ]] || { echo 'XHTTP candidate must not enable QUIC' >&2; exit 1; }
[[ "$(go version)" == "go version go${go_version} linux/amd64" ]] || { echo 'Unexpected Go toolchain' >&2; exit 1; }
if [[ ! -d work/source/.git ]]; then
    git init work/source
    git -C work/source remote add origin https://github.com/SagerNet/sing-box.git
fi
git -C work/source fetch --depth 1 origin "$commit"
# Refuse accidental rebuilding of an already modified checkout.
if [[ -n "$(git -C work/source status --porcelain)" ]]; then
    echo 'Source checkout must be clean; use a fresh work directory' >&2; exit 1
fi
git -C work/source checkout --detach "$commit"
export SOURCE_DATE_EPOCH=$(git -C work/source show -s --format=%ct HEAD)
python3 scripts/prepare-source.py work/source
gofmt -w work/source/include/native_api*.go
gofmt -w work/source/adapter/inbound.go work/source/route/rule/*.go work/source/experimental/clashapi/connections*.go
test_packages=(. ./common/urltest ./common/listener ./route/... ./experimental/clashapi ./experimental/cachefile ./common/trafficcontrol ./common/sniff ./common/ja3 ./common/interrupt ./common/readwait ./common/tls ./log ./dns ./dns/transport ./dns/transport/fakeip ./transport/v2raygrpclite ./transport/v2rayhttp ./transport/v2raywebsocket ./transport/v2rayhttpupgrade ./transport/v2rayxhttp github.com/sagernet/sing-vmess/vless)
(cd work/source; CGO_ENABLED=0 go test -timeout 5m -ldflags=-checklinkname=0 -tags "$tags" "${test_packages[@]}")
(cd work/source; CGO_ENABLED=1 go test -race -timeout 5m -ldflags=-checklinkname=0 -tags "$tags" "${test_packages[@]}")
(cd work/source; CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go list -deps -tags "$tags" ./cmd/sing-box) > work/dependencies.txt
(cd work/source; CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go list -deps -tags "$tags" ./cmd/sing-box) > work/dependencies-arm64.txt
for graph in work/dependencies.txt work/dependencies-arm64.txt; do
    grep -Fxq github.com/sagernet/sing-box/transport/v2rayxhttp "$graph"
    if grep -Eq '^google.golang.org/grpc|^github.com/sagernet/(quic-go|sing-quic)(/|$)|^gvisor.dev/|^github.com/sagernet/sing-box/service/api$|^github.com/sagernet/sing-box/protocol/(hysteria2?|tuic)(/|$)' "$graph"; then
        echo "Unexpected excluded dependency in $graph" >&2; exit 1
    fi
done
grep -Fxq github.com/sagernet/sing-box/experimental/clashapi work/dependencies.txt
grep -Fxq github.com/sagernet/sing-box/transport/v2raygrpclite work/dependencies.txt
grep -Fxq github.com/sagernet/sing-box/transport/v2rayxhttp work/dependencies.txt
if grep -Eq '^google.golang.org/grpc|^github.com/sagernet/sing-box/service/api$' work/dependencies.txt; then
    echo 'Unexpected native management API dependency' >&2; exit 1
fi
if grep -Eq '^github.com/sagernet/(quic-go|sing-quic)(/|$)|^gvisor.dev/|^github.com/sagernet/sing-box/protocol/(hysteria2?|tuic)(/|$)' work/dependencies.txt; then
    echo 'Unexpected QUIC transport or gVisor dependency' >&2; exit 1
fi
if [[ ! -x work/upx/upx ]]; then
    curl -fL --retry 3 "https://github.com/upx/upx/releases/download/v${upx_version}/upx-${upx_version}-amd64_linux.tar.xz" -o work/upx.tar.xz
    echo "$upx_hash  work/upx.tar.xz" | sha256sum -c -
    mkdir -p work/upx
    tar -xJf work/upx.tar.xz --strip-components=1 -C work/upx
fi
[[ "$(work/upx/upx --version | head -1)" == "upx ${upx_version}"* ]]
for arch in arm64 amd64; do
    (cd work/source; CGO_ENABLED=0 GOOS=linux GOARCH=$arch GOAMD64=v1 go build -trimpath -buildvcs=false -tags "$tags" \
      -ldflags "-s -w -X github.com/sagernet/sing-box/constant.Version=${upstream}-x-${version} -X runtime.godebugDefault=multipathtcp=0,tlssha1=1 -checklinkname=0" \
      -o "$root/work/sing-box-$arch.plain" ./cmd/sing-box)
    cp "work/sing-box-$arch.plain" "work/sing-box-$arch"
    work/upx/upx -9 "work/sing-box-$arch"
    work/upx/upx -t "work/sing-box-$arch"
done
python3 scripts/package.py --apk-tool "${APK_TOOL:?Set APK_TOOL to OpenWrt SDK host apk}"
python3 scripts/check-packages.py
python3 scripts/archive-provenance.py work/source
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner --exclude=.git -czf "dist/sing-box-x-${version}-source.tar.gz" -C work source
python3 scripts/manifest.py
