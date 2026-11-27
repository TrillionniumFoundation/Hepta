"""Bind the retained R3 development bridge to a completed native cold build.

The C/CPython bridge is an explicitly selected development observation
component. Its host inputs are exact clean Git blobs, never native release
inputs or an extension of the HIA cold source authority.
"""
from pathlib import Path, PurePosixPath

from tools.hia_cold_native_transport_bridge import SCHEMA, SOURCE_INPUTS
from tools.hia_cold_native_transport_evidence import Captures, canonical, data_pin, parse
from tools.hia_component_input_custody import capture_component_custody
from tools.hia_native_cold_admission import SCHEMA as NATIVE_SCHEMA


ROOT = Path(__file__).resolve().parents[1]
HOST_SUFFIXES = frozenset({".py", ".pyc", ".c", ".h", ".rs"})
DEVELOPMENT_INPUTS = (
    "tools/hia_cold_native_transport_cold.py", "tools/hia_cold_compiler.py",
    "tools/hia_component_input_custody.py", "tools/hia_native_cold_admission.py",
    "tools/hia_release_contract.py", "tools/hia_native_worker_source_authority.py",
    "tools/replay_hia_native_cold.py",
)
TRANSPORT_INPUTS = (*SOURCE_INPUTS, *DEVELOPMENT_INPUTS)


def capture_transport_custody(compiler_raw, cold_raw, sources, inputs, *, root):
    """Use the fixed transport closure without relabelling host code as HIA."""
    if set(inputs) != set(TRANSPORT_INPUTS):
        raise ValueError("transport custody requires the exact fixed input whitelist")
    cold = parse(cold_raw)
    if type(cold) is not dict or cold.get("schema") != NATIVE_SCHEMA:
        raise ValueError("native transport custody requires an original native-v2 report")
    if any(name in sources and PurePosixPath(name).suffix in HOST_SUFFIXES for name in inputs):
        raise ValueError("host transport inputs cannot enter native source authority")
    return capture_component_custody(compiler_raw, cold_raw, sources, inputs, root=root)


def read_native_transport_binding(manifest_path, cold_path):
    """Reread complete cold admission and clean Git custody before selection.

    This admits only the development bridge binding. The existing original,
    selected, handoff, reference, FD and CT36 controls remain mandatory.
    """
    from tools.hia_cold_compiler import compiler_from_cold_report

    capture = Captures()
    manifest_path, cold_path = Path(manifest_path).absolute(), Path(cold_path).absolute()
    manifest_raw, cold_raw = capture.raw(manifest_path), capture.raw(cold_path)
    manifest, cold = parse(manifest_raw), parse(cold_raw)
    if (type(cold) is not dict or type(manifest) is not dict
            or cold.get("schema") != NATIVE_SCHEMA
            or manifest.get("schema") != SCHEMA
            or manifest.get("status") != "BUILT_NOT_QUALIFIED_EXPLICIT_DEVELOPMENT"
            or manifest.get("scope") != "MATCHING_SOURCE_COLD_COMPILER"
            or manifest.get("whole_native") is not False
            or manifest.get("development_observation_only") is not True
            or manifest.get("host_bridge_is_native_release") is not False):
        raise ValueError("native cold transport is not an explicit development component")
    if (manifest.get("source_root") != str(ROOT)
            or type(manifest.get("inputs")) is not dict
            or set(manifest["inputs"]) != set(SOURCE_INPUTS)
            or type(manifest.get("development_inputs")) is not dict
            or set(manifest["development_inputs"]) != set(DEVELOPMENT_INPUTS)):
        raise ValueError("transport input root or fixed whitelist differs from this checkout")
    compiler = compiler_from_cold_report(cold_path)
    compiler_raw = capture.raw(compiler)
    if (manifest.get("compiler") != {"path": str(compiler), "pin": data_pin(compiler_raw)}
            or manifest.get("cold_report") != {"path": str(cold_path), "pin": data_pin(cold_raw)}
            or manifest.get("cold_source") != cold.get("source_manifest")):
        raise ValueError("transport compiler/report binding differs from actual native cold")
    inputs = {name: capture.raw(ROOT / name, manifest["inputs"][name])
              for name in sorted(SOURCE_INPUTS)}
    inputs.update({name: capture.raw(ROOT / name, manifest["development_inputs"][name])
                   for name in sorted(DEVELOPMENT_INPUTS)})
    custody = capture_transport_custody(compiler_raw, cold_raw, cold["source_manifest"],
                                        inputs, root=ROOT)
    if canonical(manifest.get("component_input_custody")) != canonical(custody):
        raise ValueError("transport native and host input custody differs")
    index_path = cold_path.with_suffix(".generations.json")
    index_raw = capture.raw(index_path)
    if parse(index_raw).get("source_head") != custody["source_head"]:
        raise ValueError("transport authoring commit differs from this native cold campaign")
    capture.unchanged()
    return {"manifest": str(manifest_path), **data_pin(manifest_raw),
            "source": str(ROOT), "source_head": custody["source_head"],
            "compiler": str(compiler), "compiler_pin": data_pin(compiler_raw),
            "cold_report": {"path": str(cold_path), **data_pin(cold_raw)},
            "generation_index": {"path": str(index_path), **data_pin(index_raw)},
            "whole_native": False, "host_bridge_is_native_release": False,
            "scope": "EXPLICIT_DEVELOPMENT_REGRESSION_ONLY"}
