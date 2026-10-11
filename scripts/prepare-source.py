#!/usr/bin/env python3
"""Add optional native-API exclusion to upstream sing-box (tested on 1.14.2).

Run on a dedicated source checkout, then build with without_native_api.
Clash API and its with_clash_api build tag are retained, with inline match
evidence added to connection snapshots. Default builds retain the original
native API. This does not remove transport gRPC support.
"""

import argparse
import re
import runpy
from pathlib import Path


def prepare(source: Path) -> None:
    registry = source / "include/registry.go"
    original = registry.read_text(encoding="utf-8")
    commands = sorted((source / "cmd/sing-box").glob("cmd_api*.go"))
    if "registerNativeAPIService(registry)" in original:
        helpers = [source / "include/native_api.go", source / "include/native_api_stub.go"]
        if not all(path.is_file() for path in helpers) or not commands:
            raise ValueError("incomplete existing native-API patch")
        if not all("!without_native_api" in path.read_text(encoding="utf-8") for path in commands):
            raise ValueError("incomplete existing CLI patch")
        print("Native API build tag already prepared")
        return

    api_import = '\t"github.com/sagernet/sing-box/service/api"\n'
    registration = "\tapi.RegisterService(registry)"
    if original.count(api_import) != 1 or original.count(registration) != 1:
        raise ValueError("upstream registry changed; review before patching")
    if not commands or not any(path.name == "cmd_api.go" for path in commands):
        raise ValueError("native API CLI sources not found")
    for name in ("native_api.go", "native_api_stub.go"):
        if (source / "include" / name).exists():
            raise ValueError(f"refusing to overwrite existing include/{name}")

    updates = {}
    for path in commands:
        content = path.read_text(encoding="utf-8")
        if "// +build" in content:
            raise ValueError(f"legacy build constraints require review: {path.name}")
        constraint = re.search(r"(?m)^//go:build (.+)$", content)
        if constraint:
            updates[path] = content[:constraint.start()] + (
                "//go:build !without_native_api && (" + constraint.group(1) + ")"
            ) + content[constraint.end():]
        else:
            updates[path] = "//go:build !without_native_api\n\n" + content

    updates[registry] = original.replace(api_import, "").replace(
        registration, "\tregisterNativeAPIService(registry)"
    )
    updates[source / "include/native_api.go"] = '''//go:build !without_native_api

package include

import (
    "github.com/sagernet/sing-box/adapter/service"
    "github.com/sagernet/sing-box/service/api"
)

func registerNativeAPIService(registry *service.Registry) {
    api.RegisterService(registry)
}
'''
    updates[source / "include/native_api_stub.go"] = '''//go:build without_native_api

package include

import "github.com/sagernet/sing-box/adapter/service"

func registerNativeAPIService(registry *service.Registry) {}
'''
    for path, content in updates.items():
        with path.open("w", encoding="utf-8", newline="\n") as output:
            output.write(content)
    print(f"Prepared without_native_api: {len(commands)} CLI files and service registration")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="dedicated upstream sing-box source directory")
    args = parser.parse_args()
    runpy.run_path(str(Path(__file__).with_name("prepare-hardening.py")))["prepare"](args.source.resolve())
    runpy.run_path(str(Path(__file__).with_name("prepare-tls-fingerprints.py")))["prepare"](args.source.resolve())
    runpy.run_path(str(Path(__file__).with_name("prepare-xhttp.py")))["prepare"](args.source.resolve())
    runpy.run_path(str(Path(__file__).with_name("prepare-vision.py")))["prepare"](args.source.resolve())
    runpy.run_path(str(Path(__file__).with_name("prepare-fakeip.py")))["prepare"](args.source.resolve())
    runpy.run_path(str(Path(__file__).with_name("prepare-dns-sniff.py")))["prepare"](args.source.resolve())
    runpy.run_path(str(Path(__file__).with_name("prepare-runtime-opt.py")))["prepare"](args.source.resolve())
    runpy.run_path(str(Path(__file__).with_name("prepare-latency.py")))["prepare"](args.source.resolve())
    prepare(args.source.resolve())
    runpy.run_path(str(Path(__file__).with_name("prepare-route-match.py")))["prepare"](args.source.resolve())
