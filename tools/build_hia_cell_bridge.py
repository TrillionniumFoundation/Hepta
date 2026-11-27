"""Build the Cell continuation with admitted HIA compile, pack and link calls.

Host Python transports and checks captured inputs. It does not emit code or ELF.
The old f33 component oracle is retained separately in cell_bridge_native.py.
"""
from __future__ import annotations

import argparse
from contextlib import nullcontext
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SELF_BYTES = Path(__file__).read_bytes()

from tools.hia_cold_compiler import _regular, read_cold_build_inputs
from tools.hia_component_input_custody import _git, verify_component_custody
from tools.qualify_hia_selfhost import compile_stage, invoke, release_compiler_calls
from tools.build_hia_source_build import _check_compile_receipt, _check_pack_output

SCHEMA = "hepta.cell-hia-native-build.v1"
CAPACITY = 1 << 20
MAX_FLAT = CAPACITY - 4096
MAX_EXTENT = 65792
NATIVE_INPUTS = (
    "examples/hia_cell_bridge/continuation.hepta",
    "examples/hia_cell_bridge/image_packer.hepta",
    "examples/hia_bootstrap/elf_shared_linker.hepta",
)
PACKET_MAGIC = b"HCLPACK1"
HOST_CONTEXT_INPUTS = (
    "pyproject.toml",
    "docs/HIA_CORE_LOWERING_ABI.json",
    "docs/HIA_CORE_EMITTER_ABI.json",
    "docs/HIA_BYTE_WRAPPER_ABI.json",
    "docs/HIA_MACHINE_OBJECT_ABI.json",
)


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _hash(raw):
    return sha256(raw).hexdigest()


def _inputs(root):
    """Capture the complete tracked Python implementation domain, not its imports."""
    names = _git(root, "ls-files", "-z", "--", "hepta", "tools").split(b"\0")
    host = [name.decode("ascii") for name in names if name.endswith(b".py")]
    _require(host and len(host) == len(set(host)), "Cell host input inventory differs")
    selected = tuple(sorted(set(host) | set(NATIVE_INPUTS) | set(HOST_CONTEXT_INPUTS)))
    captured = {name: _regular(root / name, 16 << 20) for name in selected}
    _require(captured.get("tools/build_hia_cell_bridge.py") == SELF_BYTES,
             "Cell builder differs from its imported source bytes")
    return captured


def _check_loaded_sources(root, captured):
    """Bind implementation module names and aliases to captured physical Python."""
    root = Path(root).absolute()
    for module_name, module in tuple(sys.modules.items()):
        implementation = module_name in ("tools", "hepta") or module_name.startswith(("tools.", "hepta."))
        location = getattr(module, "__file__", None)
        if not location:
            if implementation:
                paths = tuple(getattr(module, "__path__", ()))
                expected = root.joinpath(*module_name.split("."))
                _require(paths and all(
                    Path(path).absolute() == expected
                    and Path(path).resolve(strict=True) == expected
                    for path in paths
                ), "Cell implementation namespace escaped its physical source root: " + module_name)
            continue
        path = Path(location).absolute()
        if implementation:
            _require(path.suffix == ".py" and path.is_relative_to(root)
                     and path.resolve(strict=True) == path,
                     "Cell implementation module escaped its physical source root: " + module_name)
        if path.suffix != ".py" or not path.is_relative_to(root):
            continue
        relative = path.relative_to(root).as_posix()
        if not relative.startswith(("tools/", "hepta/")):
            _require(not implementation, "Cell implementation module has a foreign source role")
            continue
        _require(relative in captured, "uncaptured Cell implementation module: " + relative)
        _require(_regular(path, 16 << 20) == captured[relative],
                 "Cell implementation module bytes differ from captured source: " + relative)


def _verify_artifacts(expected_artifacts):
    _require(all(_regular(path, CAPACITY) == raw for path, raw in expected_artifacts.items()),
             "Cell compiler or produced artifact changed during native packaging")


def _compile_pipeline(root, directory, compiler_bytes, captured, *, cold_bytes=None):
    """One mechanical pipeline; development callers receive no cold authority."""
    compiler = directory / "captured-compiler.flat"
    compiler.write_bytes(compiler_bytes)
    compiler.chmod(0o400)
    artifacts, receipts, expected_artifacts = {}, {}, {compiler: compiler_bytes}
    start = time.perf_counter_ns()
    context = release_compiler_calls(cold_bytes) if cold_bytes is not None else nullcontext()
    with context:
        for role, name in zip(("continuation", "image-packer", "shared-linker"), NATIVE_INPUTS, strict=True):
            raw = captured[name]
            artifact, receipt = compile_stage(directory, role, compiler, raw)
            produced = artifact.read_bytes()
            _check_compile_receipt(receipt, compiler=compiler_bytes, source=raw, produced=produced)
            artifacts[role], receipts[role] = artifact, receipt
            expected_artifacts[artifact] = produced
        flat = expected_artifacts[artifacts["continuation"]]
        _require(0 < len(flat) <= MAX_FLAT, "Cell flat exceeds the fixed native packet bound")
        packet = struct.pack("<8s3Q", PACKET_MAGIC, len(flat), MAX_EXTENT, 0) + flat
        packer_raw = expected_artifacts[artifacts["image-packer"]]
        packed_receipt, output = invoke(
            directory, "cell-pack", artifacts["image-packer"], packet,
            capacity=CAPACITY, workspace_size=128,
        )
        object_bytes = _check_pack_output(
            packed_receipt, output, artifact=packer_raw, source=packet, capacity=CAPACITY,
        )
        _require(object_bytes[:6] == b"\x7fELF\x02\x01"
                 and struct.unpack_from("<HH", object_bytes, 16) == (1, 62),
                 "native Cell packer did not return an x86-64 ET_REL")
        object_path = directory / "cell-continuation.o"
        object_path.write_bytes(object_bytes)
        expected_artifacts[object_path] = object_bytes
        linker_raw = expected_artifacts[artifacts["shared-linker"]]
        link_receipt, output = invoke(
            directory, "cell-link", artifacts["shared-linker"], object_bytes,
            capacity=CAPACITY, workspace_size=CAPACITY,
        )
        image_bytes = _check_pack_output(
            link_receipt, output, artifact=linker_raw, source=object_bytes, capacity=CAPACITY,
        )
        _require(image_bytes[:6] == b"\x7fELF\x02\x01"
                 and struct.unpack_from("<HH", image_bytes, 16) == (3, 62),
                 "native Cell linker did not return an x86-64 ET_DYN")
        image_path = directory / "cell-continuation.so"
        image_path.write_bytes(image_bytes)
        expected_artifacts[image_path] = image_bytes
        receipts["pack"], receipts["link"] = packed_receipt, link_receipt
    _verify_artifacts(expected_artifacts)
    _require(all(_regular(root / name, 16 << 20) == raw for name, raw in captured.items()),
             "Cell source changed during native packaging")
    elapsed = time.perf_counter_ns() - start
    report = {
        "schema": SCHEMA, "image_path": str(image_path),
        "image_bytes": len(image_bytes), "image_sha256": _hash(image_bytes),
        "source_sha256": _hash(captured[NATIVE_INPUTS[0]]),
        "compiler_sha256": _hash(compiler_bytes), "compiler_bytes": len(compiler_bytes),
        "compile_wall_ns": elapsed,
        "native_artifacts": {
            role: {"path": str(path), "bytes": len(expected_artifacts[path]),
                   "sha256": _hash(expected_artifacts[path])}
            for role, path in artifacts.items()
        },
        "object": {"path": str(object_path), "bytes": len(object_bytes), "sha256": _hash(object_bytes)},
        "native_calls": receipts,
    }
    return report, expected_artifacts


def build_native_bridge(root, output, *, cold_report, generation_index=None):
    """Public build: require current native cold plus exact clean host Git custody."""
    root = Path(root).absolute()
    _require(root == ROOT and root == root.resolve(strict=True),
             "Cell native builder must execute from its explicit physical source root")
    inputs = read_cold_build_inputs(cold_report, generation_index=generation_index)
    _require(inputs.native is True, "Cell current build requires a native cold report")
    captured = _inputs(root)
    _check_loaded_sources(root, captured)
    custody = inputs.capture_custody(captured, root=root)
    directory = Path(output).absolute()
    directory.mkdir(parents=True, exist_ok=False)
    report, expected_artifacts = _compile_pipeline(root, directory, inputs.compiler_bytes, captured,
                               cold_bytes=inputs.report_bytes)
    _require(_inputs(root) == captured, "Cell source inventory changed after build")
    _check_loaded_sources(root, captured)
    inputs.unchanged()
    verify_component_custody(custody, inputs.compiler_bytes, inputs.report_bytes,
                             inputs.sources, captured, root=root)
    inputs.unchanged()
    report.update({
        "scope": "native Cell component from the exact current cold campaign",
        "compiler_commit": inputs.source_head,
        "cold_report_sha256": _hash(inputs.report_bytes),
        "generation_index_sha256": _hash(inputs.location_bytes),
        "generation_sha256": [_hash(raw) for _, raw in inputs.generations],
        "source_head": inputs.source_head, "input_custody": custody,
        "claims": {"native_compile_pack_link": True, "fallback_used": False,
                   "cold_compiler_admitted": True, "development_only": False,
                   "cell_execution_qualified": False, "whole_stack_qualified": False,
                   "host_authoring_is_native_qualified": False},
    })
    report_bytes = (json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    (directory / "native-build.json").write_bytes(report_bytes)
    _require(_regular(directory / "native-build.json", 16 << 20) == report_bytes,
             "Cell build receipt changed at publication")
    verify_component_custody(custody, inputs.compiler_bytes, inputs.report_bytes,
                             inputs.sources, captured, root=root)
    _require(_inputs(root) == captured, "Cell source changed at final publication")
    inputs.unchanged()
    _verify_artifacts(expected_artifacts)
    _require(_regular(directory / "native-build.json", 16 << 20) == report_bytes,
             "Cell build receipt changed at final publication")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cold-report", type=Path, required=True)
    parser.add_argument("--generation-index", type=Path)
    args = parser.parse_args()
    report = build_native_bridge(ROOT, args.output, cold_report=args.cold_report,
                                 generation_index=args.generation_index)
    print(json.dumps({"image": report["image_path"], "sha256": report["image_sha256"],
                      "cold_source": report["source_head"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
