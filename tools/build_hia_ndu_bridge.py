#!/usr/bin/env python3
"""Build the HIA transport against exact original NDU Rust source bytes.

The source checkout is read-only. A separate workspace excludes unrelated
monorepo members and dev-only dependencies; all three production src trees
are copied from the pinned Git object and independently inventoried.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "rust/hia-ndu-bridge"


def _quote(value):
    return json.dumps(value)


def build(checkout, output, *, cargo="cargo"):
    checkout, output = Path(checkout).resolve(), Path(output).resolve()
    if output.exists():
        raise ValueError("build output must be a new directory")
    locked = json.loads((ADAPTER / "upstream.json").read_text())
    commit = locked["commit"]
    observed = subprocess.check_output(["git", "rev-parse", commit + "^{commit}"], cwd=checkout, text=True).strip()
    if observed != commit:
        raise ValueError("upstream commit identity mismatch")
    paths = ["codex-rs/" + name for name in locked["crates"]]
    archive = subprocess.check_output(["git", "archive", commit, *paths, "codex-rs/Cargo.toml"], cwd=checkout)
    output.mkdir(parents=True)
    inventory, original_manifests = {}, {}
    with tarfile.open(fileobj=io.BytesIO(archive)) as package:
        for item in package:
            if not item.isfile():
                if item.isdir():
                    continue
                raise ValueError("unsupported upstream archive member")
            rel = Path(item.name)
            if rel.is_absolute() or ".." in rel.parts or rel.parts[0] != "codex-rs":
                raise ValueError("unsafe upstream archive path")
            data = package.extractfile(item).read()
            inventory[item.name] = sha256(data).hexdigest()
            if item.name == "codex-rs/Cargo.toml":
                upstream_workspace = tomllib.loads(data.decode())["workspace"]
                continue
            destination = output / Path(*rel.parts[1:])
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            if destination.name == "Cargo.toml" and len(rel.parts) == 3:
                original_manifests[rel.parts[1]] = tomllib.loads(data.decode())
    required = set()
    for name, manifest in original_manifests.items():
        # Original Rust source is unchanged; this manifest contains precisely
        # the original production dependencies, not upstream dev/test targets.
        lines = ["[package]", f"name = {_quote(manifest['package']['name'])}",
                 'version = "0.0.0"', 'edition = "2024"', 'license = "Apache-2.0"',
                 "autobins = false", "autotests = false", "autoexamples = false", "",
                 "[lib]", f"name = {_quote(manifest['lib']['name'])}", 'path = "src/lib.rs"',
                 "doctest = false", "", "[features]"]
        for feature, values in manifest.get("features", {}).items():
            lines.append(feature + " = " + json.dumps(values))
        lines += ["", "[dependencies]"]
        for dep, spec in manifest.get("dependencies", {}).items():
            if "path" in spec:
                lines.append(dep + " = { path = " + _quote(spec["path"]) + " }")
            elif spec.get("workspace"):
                required.add(dep)
                extra = (", features = " + json.dumps(spec["features"])) if spec.get("features") else ""
                lines.append(dep + " = { workspace = true" + extra + " }")
            else:
                raise ValueError("unreviewed upstream dependency specification")
        (output/name/"Cargo.toml").write_text("\n".join(lines)+"\n")
    workspace = ['[workspace]', 'resolver = "2"', 'members = ["hia-ndu-bridge", "hepta-ndu", "hepta-contracts", "hepta-types"]',
                 '', '[workspace.dependencies]']
    for dep in sorted(required):
        spec = upstream_workspace["dependencies"][dep]
        if isinstance(spec, str):
            workspace.append(dep+" = "+_quote(spec))
        elif set(spec) <= {"version", "features", "default-features"}:
            fields = [key+" = "+json.dumps(value) for key,value in spec.items()]
            workspace.append(dep+" = { "+", ".join(fields)+" }")
        else:
            raise ValueError("upstream non-registry dependency requires explicit review")
    workspace += ['', '[profile.dev]', 'debug = 0', 'incremental = false']
    (output/"Cargo.toml").write_text("\n".join(workspace)+"\n")
    shutil.copytree(ADAPTER, output/"hia-ndu-bridge")
    committed_lock = ADAPTER/"Cargo.lock"
    if not committed_lock.is_file():
        raise ValueError("a committed isolated Cargo.lock is required")
    shutil.copy2(committed_lock, output/"Cargo.lock")
    adapter_files = {str(p.relative_to(ADAPTER)): sha256(p.read_bytes()).hexdigest()
                     for p in sorted(ADAPTER.rglob("*")) if p.is_file()}
    # Include embedded fixtures and generated manifests, not just Rust src/.
    build_inputs = {str(p.relative_to(output)): sha256(p.read_bytes()).hexdigest()
                    for p in sorted(output.rglob("*")) if p.is_file()}
    env = dict(os.environ, CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0")
    command = [cargo, "build", "--manifest-path", str(output/"Cargo.toml"), "-p", "hia-ndu-bridge", "--locked"]
    subprocess.run(command, env=env, check=True)
    binary = Path(env.get("CARGO_TARGET_DIR", output/"target"))/"debug/hia-ndu-bridge"
    # Re-read every original non-manifest byte after the build, including
    # include_str! fixtures, independently of the checkout and compiler.
    for name, digest in inventory.items():
        rel = Path(name)
        replaced_manifest = (name == "codex-rs/Cargo.toml"
                             or len(rel.parts) == 3 and rel.name == "Cargo.toml")
        if not replaced_manifest and sha256((output/Path(*rel.parts[1:])).read_bytes()).hexdigest() != digest:
            raise ValueError("upstream input changed during build")
    for name, digest in build_inputs.items():
        if sha256((output/name).read_bytes()).hexdigest() != digest:
            raise ValueError("isolated build input changed during build")
    for name, digest in adapter_files.items():
        if sha256((ADAPTER/name).read_bytes()).hexdigest() != digest:
            raise ValueError("adapter source changed during build")
    report = {"schema":"hepta.hia.ndu-build.v1", "upstream":locked,
              "original_source_files":inventory, "original_rust_sources_unchanged":True,
              "all_original_non_manifest_inputs_unchanged":True,
              "adapter_files":adapter_files, "build_inputs":build_inputs,
              "build_inputs_unchanged":True, "locked_dependencies":True,
              "isolated_production_manifests":True, "binary":str(binary),
              "binary_sha256":sha256(binary.read_bytes()).hexdigest(),
              "cargo_lock_sha256":sha256((output/"Cargo.lock").read_bytes()).hexdigest(),
              "cargo_version":subprocess.check_output([cargo,"--version"],text=True).strip(),
              "rustc_version":subprocess.check_output(["rustc","-vV"],text=True).strip(),
              "builder_sha256":sha256(Path(__file__).read_bytes()).hexdigest(),
              "build_environment":{k:env.get(k,"") for k in ("RUSTFLAGS","CARGO_ENCODED_RUSTFLAGS","CARGO_BUILD_TARGET")},
              "production_activation":False}
    (output/"build-receipt.json").write_text(json.dumps(report,indent=2)+"\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream",required=True,type=Path)
    parser.add_argument("--output",required=True,type=Path)
    parser.add_argument("--cargo",default="cargo")
    args = parser.parse_args()
    result = build(args.upstream,args.output,cargo=args.cargo)
    print(json.dumps({key:result[key] for key in ("binary","binary_sha256","original_rust_sources_unchanged")},indent=2))


if __name__ == "__main__":
    main()
