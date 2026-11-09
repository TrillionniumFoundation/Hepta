#!/usr/bin/env python3
"""Read-only discovery for HIA release, development and retained online entries."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]
SELECTIONS = {
    "current": ("releases/hia-current.json", "tools/hia_release.py",
                "9000d6eaa089f6bed92ea07a6561d91381a6f913263f0b1016d4f99e8789c1d3"),
    "v16": ("releases/hia-v16-6ecd802.json", "tools/hia_release_v16_6ecd802.py",
            "b3c3725e183d98bec2819155f2d4cd525c3f45305d04ec8fa686e13f454e50e0"),
}
def read_json(path):
    raw = Path(path).read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError("discovery input exceeds 1 MiB")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate discovery key: " + key)
            result[key] = value
        return result
    return raw, json.loads(raw, object_pairs_hook=unique)
def release(root, name):
    lock_path, entry, expected = SELECTIONS[name]
    raw, lock = read_json(root / lock_path)
    if sha256(raw).hexdigest() != expected:
        raise ValueError("original release lock differs: " + name)
    for actual, original in ((entry, "tools/hia_release.py"),
                             ("tools/hia_candidate_preflight.py", "tools/hia_candidate_preflight.py")):
        if sha256((root / actual).read_bytes()).hexdigest() != lock["files"]["hepta"][original]:
            raise ValueError("entry helper differs from selected source: " + actual)
    argv = ["python3", "-B", entry]
    if name != "current":
        argv += ["--lock", lock_path, "--lock-sha256", expected]
    return {"selection": name, "release_id": lock["release_id"],
        "lock": {"path": lock_path, "sha256": expected}, "entry_argv": argv,
        "sources": lock["sources"], "installation": lock["installation"],
        "target_abi": lock["target_abi"], "selfhost_profile": lock["selfhost"]["profile"],
        "qualification": lock["qualification"], "whole_language_selfhost": lock["selfhost"]["whole_language_selfhost"],
        "syntax": {"assembly": "hia-asm.v1", "primitive_core": "hepta.hia.program.v8",
                   "contract": "docs/HIA_AGENT_ASSEMBLY.md",
                   "sha256": lock["files"]["hepta"]["docs/HIA_AGENT_ASSEMBLY.md"]},
        "proof": {"service_profile": "hia.agent.safe-core.scalar-supplied-elf.x86_64.v1",
                  "contract": "docs/HIA_AGENT_PROOF_RESULTS.md",
                  "sha256": lock["files"]["hepta"]["docs/HIA_AGENT_PROOF_RESULTS.md"],
                  "compiler_buffer_independent_refinement": "unsupported",
                  "scope": "one unsigned scalar acyclic function; shared ELF; no borrowed or foreign entries",
                  "execution_authority_granted": False},
        "minimal_program": {"path": "examples/hia_safe_core/scalar_add.hia.json",
                            "sha256": lock["files"]["hepta"]["examples/hia_safe_core/scalar_add.hia.json"],
                            "function": "calculate", "arguments": [2, 3], "expected_values": [5],
                            "direct_build_flags": ["--backend", "native", "--kind", "shared", "--linker", "ld"]}}

def development(path):
    root = Path(path).resolve()
    def git(*args):
        return subprocess.run(["git", "-C", str(root), *args], check=True,
                              capture_output=True, text=True, timeout=10).stdout.strip()
    raw, support = read_json(root / "docs/HIA_SELFHOST_CORE_SUPPORT.json")
    return {"root": str(root), "commit": git("rev-parse", "HEAD"),
            "tree": git("rev-parse", "HEAD^{tree}"),
            "status": git("status", "--porcelain", "--untracked-files=all"),
            "selfhost_profile": support["profile"], "support_sha256": sha256(raw).hexdigest(),
            "release_lock_verified": False, "production_deployed": False}
def online(path, entries):
    raw, manifest = read_json(path)
    if type(manifest) is not dict:
        raise ValueError("online manifest must be an object")
    identity = manifest.get("installation")
    if type(identity) is not dict or set(identity) != {"worker_sha256", "backend_sha256", "catalog_sha256"}:
        raise ValueError("online input requires a manifest with all three installation identities")
    if any(type(value) is not str or len(value) != 64
           or any(c not in "0123456789abcdef" for c in value) for value in identity.values()):
        raise ValueError("invalid installation identity")
    return {"sha256": sha256(raw).hexdigest(), "installation": identity,
            "matches": [row["selection"] for row in entries if row["installation"] == identity],
            "scope": "retained observation; freshness and loaded binary unestablished",
            "live_probe_performed": False}
def describe(root=ROOT, *, development_root=None, online_manifest=None):
    entries = [release(Path(root), name) for name in SELECTIONS]
    return {"schema": "hepta.hia.entry-catalog.v1", "entries": entries,
            "development": development(development_root) if development_root else None,
            "online": online(online_manifest, entries) if online_manifest else None,
            "backend_selection": {"cli_build_default": "llvm", "cli_direct_flags": ["--backend", "native"],
                                  "cli_hia_emit": "LLVM text", "mcp_hia_emit": "hia-direct"},
            "execution_authority_granted": False}
def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--development-root", type=Path, help="explicit checkout; never inferred from main")
    parser.add_argument("--online-manifest", type=Path, help="retained manifest; no live probe")
    args = parser.parse_args(argv)
    try:
        report = describe(development_root=args.development_root, online_manifest=args.online_manifest)
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
