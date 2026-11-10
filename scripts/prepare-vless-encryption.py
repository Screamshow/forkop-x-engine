#!/usr/bin/env python3
"""Apply pinned podkop/Xray VLESS Encryption after XHTTP and Vision preparation."""
import hashlib
import json
import subprocess
from pathlib import Path


def prepare(source: Path) -> None:
    patches = Path(__file__).resolve().parents[1] / 'patches/vless-encryption'
    manifest = json.loads((patches / 'manifest.json').read_text())
    manifest['adapter_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    marker = source / '.forkop-vless-encryption.json'
    if marker.exists():
        if json.loads(marker.read_text()) != manifest:
            raise ValueError('Encryption preparation changed; use fresh source')
        return
    for entry in manifest['patches']:
        patch = patches / entry['file']
        if hashlib.sha256(patch.read_bytes()).hexdigest() != entry['sha256']:
            raise ValueError(f'Encryption patch digest mismatch: {patch.name}')
        # XHTTP already promotes cpuid. Promote blake3 through go mod edit below
        # instead of depending on unrelated upstream go.mod line context.
        command = ['git', 'apply', '--exclude=go.mod']
        if patch.name.startswith('0106-'):
            # Our older fingerprint tests differ; keep the original patch intact
            # and cover this check in the browser-update regression instead.
            command += ['--exclude=common/tls/reality_fingerprint_test.go']
        subprocess.run(command + ['--check', str(patch)], cwd=source, check=True)
        subprocess.run(command + [str(patch)], cwd=source, check=True)
    subprocess.run(['go', 'mod', 'edit', '-require=lukechampine.com/blake3@v1.3.0'],
                   cwd=source, check=True)
    version = source / 'cmd/sing-box/cmd_version.go'
    text = version.read_text()
    old = 'Features: transport.xhttp,transport.xhttp.http1,transport.xhttp.http2'
    if text.count(old) != 1:
        raise ValueError('Feature output changed')
    version.write_text(text.replace(old, old + ',outbound.vless.encryption'), newline='\n')
    subprocess.run(['gofmt', '-w', 'option/vless.go', 'protocol/vless'], cwd=source, check=True)
    marker.write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    prepare(parser.parse_args().source.resolve())
