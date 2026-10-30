"""Retain immutable generated debug sources beside a requested native artifact."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .ast import Diagnostic, HeptaError
from .source_map import source_markers


def retain_debug_source(source: str, artifact: Path, language: str) -> tuple[Path, dict]:
    data = source.encode()
    identity = hashlib.sha256(data).hexdigest()
    directory = artifact.parent / (artifact.name + ".hepta-debug") / identity
    directory.mkdir(parents=True, exist_ok=True)
    generated = directory / ("program.rs" if language == "rust" else "program.c")
    markers = [{"generated_start_line": a, "generated_end_line": b, "source": span, "precision": kind}
               for a, b, span, kind in source_markers(source)] if language == "rust" else []
    manifest = {"schema": "hepta.debug-source.v1", "backend": language,
                "generated_source": str(generated), "generated_sha256": identity,
                "mappings": markers,
                "mapping_kind": "statement/declaration ranges" if language == "rust" else "C #line directives",
                "optimized_variable_visibility_guaranteed": False}
    metadata = directory / "source-map.json"
    for destination, content in ((generated, data), (metadata, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())):
        try:
            with destination.open("xb") as stream:
                stream.write(content)
        except FileExistsError:
            if destination.is_symlink() or not destination.is_file() or destination.read_bytes() != content:
                raise HeptaError(Diagnostic("E_DEBUG_SOURCE", "Retained debug source identity differs: " + str(destination), phase="backend"))
    return generated, {"manifest": str(metadata), "source": str(generated),
                       "source_sha256": identity, "mapping_count": len(markers)}
