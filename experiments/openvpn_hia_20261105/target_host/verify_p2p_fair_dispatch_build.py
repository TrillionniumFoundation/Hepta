#!/usr/bin/env python3
"""Fail-closed verification for the full application build with P2P fairness."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent


def load_verifier():
    spec = importlib.util.spec_from_file_location("verify_result", HERE / "verify_result.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    public = args.public.resolve()
    build = json.loads((public / "build.json").read_text())
    environment = json.loads((public / "build-env.json").read_text())
    if build.get("ok") is not True:
        raise ValueError("full OpenVPN/HIA application build did not complete")
    if build.get("hepta_commit") != args.expected_commit:
        raise ValueError("build receipt belongs to another Hepta commit")
    if build.get("expected_hepta_commit") != args.expected_commit:
        raise ValueError("build receipt did not bind the expected source HEAD")
    if build.get("official_source_freeze", {}).get("archive_sha256") != build.get(
            "official_source_after", {}).get("archive_sha256"):
        raise ValueError("pristine OpenVPN archive identity changed during build")
    verifier = load_verifier()
    dispatch = verifier.verify_p2p_fair_dispatch_build(build)
    if environment.get("p2p_fair_dispatch") != dispatch:
        raise ValueError("build environment and build receipt disagree on fairness patch")
    source = Path(environment["source"])
    build_source = Path(environment["build_source"])
    if not source.is_dir() or not build_source.is_dir() or source == build_source:
        raise ValueError("pristine and patched OpenVPN source trees are not isolated")
    if not source.name == "openvpn-2.7.8" or "p2p-fair-dispatch" not in build_source.name:
        raise ValueError("unexpected pristine/patched source directory identity")
    link = build.get("link", {})
    for key in ("c_binary_sha256", "hia_binary_sha256", "hia_trace_binary_sha256",
                "hia_object_sha256", "adapter_object_sha256", "config_h_sha256"):
        if re.fullmatch(r"[0-9a-f]{64}", str(link.get(key, ""))) is None:
            raise ValueError("missing or malformed compiled object identity: " + key)
    print(json.dumps({
        "status": "PASS",
        "hepta_commit": build["hepta_commit"],
        "openvpn_commit": dispatch["upstream_commit"],
        "patch_sha256": dispatch["patch_sha256"],
        "patched_files": dispatch["patched_files"],
        "c_binary_sha256": link["c_binary_sha256"],
        "hia_binary_sha256": link["hia_binary_sha256"],
        "hia_trace_binary_sha256": link["hia_trace_binary_sha256"],
        "runtime_acceptance": False,
        "target_matrix_executed": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"status": "FAIL", "error": repr(exc)}, sort_keys=True), file=sys.stderr)
        raise
