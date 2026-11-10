#!/usr/bin/env python3
"""Bundle original patches and local adapters with corresponding source."""
import argparse
import shutil
from pathlib import Path


def bundle(source: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    target = source / '.forkop-provenance'
    target.mkdir(exist_ok=True)
    shutil.copy2(root / 'LICENSE.utls', source / 'LICENSE.utls')
    for name in ('patches', 'scripts', 'packaging', 'tests'):
        shutil.copytree(root / name, target / name, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    for name in ('build-config.json', 'LICENSE', 'LICENSE.utls', 'README.md',
                 'COMPATIBILITY-2026-11-11.md'):
        shutil.copy2(root / name, target / name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    bundle(parser.parse_args().source.resolve())
