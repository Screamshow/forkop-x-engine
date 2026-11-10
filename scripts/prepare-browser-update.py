#!/usr/bin/env python3
"""Install the pinned Chrome 155 profile without changing TLS verification."""
import hashlib
import json
import shutil
from pathlib import Path


def prepare(source: Path) -> None:
    assets = Path(__file__).with_name('browser-update')
    manifest = json.loads((assets / 'manifest.json').read_text())
    manifest['adapter_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    marker = source / '.forkop-browser-update.json'
    if marker.exists():
        if json.loads(marker.read_text()) != manifest:
            raise ValueError('Browser preparation changed; prepare fresh source')
        return
    for name, digest in manifest['files'].items():
        if hashlib.sha256((assets / name).read_bytes()).hexdigest() != digest:
            raise ValueError('Browser asset digest mismatch: ' + name)
        shutil.copy2(assets / name, source / 'common/tls' / name)
    spec = source / 'common/tls/utls_spec.go'
    text = spec.read_text()
    old = '\tswitch {\n\tcase id == helloFirefox148:'
    if text.count(old) != 1:
        raise ValueError('Browser switch changed')
    text = text.replace(old, '\tswitch {\n\tcase id == helloChrome155:\n\t\tvar err error\n\t\tspec, err = chrome155Spec()\n\t\tif err != nil { return nil, err }\n\tcase id == helloFirefox148:')
    spec.write_text(text, newline='\n')
    client = source / 'common/tls/utls_client.go'
    text = client.read_text()
    if text.count('utls.HelloChrome_Auto') != 2:
        raise ValueError('Chrome profile mapping changed')
    client.write_text(text.replace('utls.HelloChrome_Auto', 'helloChrome155'), newline='\n')
    marker.write_text(json.dumps(manifest, indent=2) + '\n')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    prepare(parser.parse_args().source.resolve())
