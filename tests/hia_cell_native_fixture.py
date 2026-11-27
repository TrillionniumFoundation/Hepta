"""Explicit development-only Cell packaging; never a cold qualification."""
from hashlib import sha256
import json
from pathlib import Path

from tools import build_hia_cell_bridge as build


def development_build(root, output, compiler):
    root, compiler = Path(root).absolute(), Path(compiler).absolute()
    original = build._regular(compiler, build.CAPACITY)
    captured = {name: build._regular(root / name, 16 << 20) for name in build.NATIVE_INPUTS}
    directory = Path(output).absolute()
    directory.mkdir(parents=True, exist_ok=False)
    report, expected_artifacts = build._compile_pipeline(root, directory, original, captured)
    if build._regular(compiler, build.CAPACITY) != original:
        raise ValueError("development compiler changed after Cell packaging")
    report.update({
        "scope": "development component, no matching current native cold authority",
        "compiler_commit": None,
        "development_compiler_path": str(compiler),
        "source_before": {name: {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}
                          for name, raw in captured.items()},
        "claims": {"native_compile_pack_link": True, "fallback_used": False,
                   "cold_compiler_admitted": False, "development_only": True,
                   "cell_execution_qualified": False, "whole_stack_qualified": False,
                   "host_authoring_is_native_qualified": False},
    })
    report_bytes = (json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    (directory / "native-build.json").write_bytes(report_bytes)
    build._verify_artifacts(expected_artifacts)
    build._require(build._regular(directory / "native-build.json", 16 << 20) == report_bytes,
                   "Cell development receipt changed at final publication")
    return report
