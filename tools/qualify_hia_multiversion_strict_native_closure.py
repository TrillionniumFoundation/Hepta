"""Fresh native construction and original strict multiversion component gates.

External qualification only: all product roles are compiled twice by the exact
native source builder and packed/linked by actual HIA policies. Host reference
object builders are independent byte comparators, never product constructors.
"""
from pathlib import Path
import argparse
import hashlib
import importlib
import json
import os
import struct
import subprocess
import sys
import time
import traceback
from tools import qualify_hia_generation_lease_public_lifecycle as old
from tools import generate_hia_generation_lease_owner_packer as owner

ROOT = Path(__file__).resolve().parents[1]
BOOT = "examples/hia_bootstrap/"
sha = lambda raw: hashlib.sha256(raw).hexdigest()
PROOF_ROLES = (
    "native_scalar_proof_policy", "native_scalar_proof_hash", "core_admission",
    "json_canonical", "multiversion_proof_graph", "cnf",
    "evaluate_reference_wire", "scalar_reference", "general_cnf",
)


def main():
    p = argparse.ArgumentParser()
    for name in ("compiler", "normalizer", "builder", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    flats_dir = a.output / "flats"
    flats_dir.mkdir()
    report = dict(schema="hepta.hia.strict-multiversion-native-closure.v1",
                  passed=False, full_release_pass=False,
                  production_activated=False, compiler_sha256=old.COMPILER_SHA,
                  compile=[], components={}, commands=[])
    captured = {}
    executable_inputs = {name: (getattr(a, name), getattr(a, name).read_bytes())
                         for name in ("compiler", "normalizer", "builder")}
    assert sha(executable_inputs["compiler"][1]) == old.COMPILER_SHA

    def save():
        (a.output / "qualification.json").write_text(
            json.dumps(report, indent=2) + "\n")

    def compile_role(name):
        if name in captured:
            return (flats_dir / (name + ".flat")).read_bytes()
        path = ROOT / BOOT / (name + ".hepta")
        source = path.read_bytes()
        captured[name] = (path, source)
        runs = []
        for index in range(2):
            started = time.monotonic()
            q = subprocess.run([str(a.compiler), "compile"], input=source,
                               capture_output=True, timeout=30)
            (flats_dir / (name + ".run" + str(index) + ".stderr")).write_bytes(q.stderr)
            (flats_dir / (name + ".run" + str(index) + ".flat")).write_bytes(q.stdout)
            row = dict(path=BOOT + name + ".hepta", source_bytes=len(source),
                       source_sha256=sha(source), attempt=index,
                       returncode=q.returncode, flat_bytes=len(q.stdout),
                       flat_sha256=sha(q.stdout), stderr_bytes=len(q.stderr),
                       stderr_sha256=sha(q.stderr),
                       elapsed_seconds=time.monotonic() - started)
            report["compile"].append(row)
            save()
            assert q.returncode == 0 and not q.stderr, row
            runs.append(q.stdout)
        assert runs[0] == runs[1], name
        (flats_dir / (name + ".flat")).write_bytes(runs[0])
        print("NATIVE_ROLE_DOUBLE_BUILD", name, len(runs[0]), flush=True)
        return runs[0]

    def command(label, argv):
        intent = dict(label=label, argv=argv, started_unix=time.time())
        (a.output / (label + ".intent.json")).write_text(
            json.dumps(intent, indent=2) + "\n")
        started = time.monotonic()
        with (a.output / (label + ".stdout")).open("wb") as stdout, \
             (a.output / (label + ".stderr")).open("wb") as stderr:
            result = subprocess.run(argv, cwd=ROOT, stdout=stdout, stderr=stderr)
        row = dict(**intent, returncode=result.returncode,
                   elapsed_seconds=time.monotonic() - started)
        for stream in ("stdout", "stderr"):
            raw = (a.output / (label + "." + stream)).read_bytes()
            row[stream] = dict(bytes=len(raw), sha256=sha(raw))
        report["commands"].append(row)
        save()
        print("ORIGINAL_GATE_TERMINAL", label, result.returncode,
              row["elapsed_seconds"], flush=True)
        assert result.returncode == 0, row

    def component(name, packer_name, sources, destination, filename):
        packer = importlib.import_module("tools." + packer_name)
        assert tuple(sources) == packer.ROLES, (name, tuple(sources), packer.ROLES)
        parts = [compile_role(sources[role]) for role in packer.ROLES]
        frame = struct.pack("<" + str(len(parts) + 2) + "Q",
                            packer.MAGIC, len(parts), *map(len, parts)) + b"".join(parts)
        policy = compile_role(packer_name.removeprefix("generate_hia_"))
        obj = old.run_packer(policy, frame)
        assert obj == packer.reference_object(parts), name
        linked = old.run_packer(compile_role("multiversion_runtime_linker"), obj)
        destination.mkdir(parents=True, exist_ok=True)
        path = destination / filename
        path.write_bytes(linked)
        (destination / (name + ".o")).write_bytes(obj)
        rows = [dict(role=role, path=str(flats_dir / (sources[role] + ".flat")),
                     source_path=BOOT + sources[role] + ".hepta",
                     sha256=sha(part), bytes=len(part))
                for role, part in zip(packer.ROLES, parts, strict=True)]
        record = dict(roles=rows, protocol=packer.MAGIC.to_bytes(8, "little").decode(),
                      native_pack=True, native_link=True,
                      native_object_matches_reference=True, image_bytes=len(linked),
                      image_sha256=sha(linked), object_sha256=sha(obj))
        (destination / (name + "-build.json")).write_text(
            json.dumps(record, indent=2) + "\n")
        if name == "admission":
            # The original lifetime/pack gate invokes this actual compiled policy.
            (destination / "packer.flat").write_bytes(policy)
            record.update(packer_bytes=len(policy), packer_sha256=sha(policy))
            (destination / "build.json").write_text(json.dumps(record, indent=2) + "\n")
        report["components"][name] = record
        save()
        return path

    try:
        # The MV proof process expects HIAMVP02 on stdin, with no command args.
        # The unrelated Safe Core verifier cannot substitute for this ABI.
        parts = [compile_role(name) for name in PROOF_ROLES]
        proof_frame = b"HIAMVK02" + struct.pack("<9Q", *map(len, parts)) + b"".join(parts)
        proof = old.run_packer(compile_role("native_scalar_proof_packer"), proof_frame)
        proof_path = a.output / "hia-native-scalar-proof"
        proof_path.write_bytes(proof)
        proof_path.chmod(0o700)
        report["proof"] = dict(bytes=len(proof), sha256=sha(proof),
                               protocol="HIAMVP02", pack_protocol="HIAMVK02",
                               roles=list(PROOF_ROLES), actual_native_pack=True)
        save()

        common = ["--compiler", str(a.compiler), "--normalizer", str(a.normalizer),
                  "--proof", str(proof_path), "--builder", str(a.builder)]
        command("owner", [sys.executable, "-u", "-m",
                         "tools.qualify_hia_generation_lease_owner",
                         *common, "--output", str(a.output / "owner")])

        base = {row["role"]: Path(row["path"]).stem for row in owner.CARRIER_SOURCES}
        base["handles"] = "multiversion_runtime_handles"
        base["effects"] = "multiversion_runtime_effects"
        base["state"] = "multiversion_runtime_state"
        assert len(base) == 50
        admission = {role.removeprefix("gen_intake_"): source
                     for role, source in base.items() if role.startswith("gen_intake_")}
        generation = {role.removeprefix("gen_"): source
                      for role, source in base.items() if role.startswith("gen_")}
        effects = {role: source for role, source in base.items() if role != "handles"}
        provider = {"provider": "multiversion_background_runtime",
                    "payload": "multiversion_background_payload", **base}
        identity = {role.removeprefix("identity_"): source
                    for role, source in base.items() if role.startswith("identity_")}
        components = a.output / "components"
        component("admission", "generate_hia_multiversion_prepare_admission_packer",
                  admission, components / "admission", "prepare-admission-component.so")
        component("generation", "generate_hia_multiversion_runtime_generation_packer",
                  generation, components / "generation", "runtime-generation.so")
        effects_path = component("effects", "generate_hia_multiversion_runtime_effects_packer",
                                 effects, components, "runtime-effects.so")
        component("handles", "generate_hia_multiversion_runtime_handles_packer",
                  base, components, "runtime-handles.so")
        provider_path = component("provider", "generate_hia_multiversion_background_runtime_packer",
                                  provider, components, "runtime-provider.so")
        identity_path = component("identity", "generate_hia_multiversion_runtime_identity_packer",
                                  identity, components, "identity-component.so")
        future_path = component("future", "generate_hia_multiversion_future_packer",
                                {"policy": base["future"]}, components, "future-component.so")
        for label, module, args in (
            ("strict-admission", "qualify_hia_multiversion_prepare_admission_strict",
             ["--directory", str(components / "admission"), "--normalizer", str(a.normalizer)]),
            ("legacy-admission", "qualify_hia_multiversion_prepare_admission_legacy",
             ["--directory", str(components / "admission"), "--normalizer", str(a.normalizer)]),
            ("admission-lifetime", "qualify_hia_multiversion_prepare_admission_lifetime",
             ["--directory", str(components / "admission"), "--normalizer", str(a.normalizer)]),
            ("strict-generation", "qualify_hia_multiversion_runtime_strict_generation",
             ["--directory", str(components / "generation"), "--normalizer", str(a.normalizer),
              "--proof", str(proof_path), "--builder", str(a.builder)]),
            ("strict-effects", "qualify_hia_multiversion_runtime_strict_effects",
             ["--component", str(effects_path), "--output", str(a.output / "strict-effects"),
              "--normalizer", str(a.normalizer), "--proof", str(proof_path),
              "--builder", str(a.builder), "--identity", str(identity_path)]),
            ("strict-provider", "qualify_hia_multiversion_runtime_strict_provider",
             ["--component", str(provider_path), "--output", str(a.output / "strict-provider"),
              "--normalizer", str(a.normalizer), "--proof", str(proof_path),
              "--builder", str(a.builder), "--future", str(future_path)]),
            ("strict-wrapper-guards", "qualify_hia_multiversion_runtime_strict_guards",
             ["--directory", str(components)]),
        ):
            command(label, [sys.executable, "-u", "-m", "tools." + module, *args])
        for path, raw in captured.values():
            assert path.read_bytes() == raw, str(path)
        for path, raw in executable_inputs.values():
            assert path.read_bytes() == raw, str(path)
        report.update(passed=True, source_and_executable_end_reread=True,
                      current_owner_roles=55, current_carrier_roles=50)
        save()
        print("STRICT_MULTIVERSION_NATIVE_CLOSURE_PASS", flush=True)
    except BaseException:
        report["failure"] = traceback.format_exc()
        save()
        raise


if __name__ == "__main__":
    main()
