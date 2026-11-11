"""Map generated Rust diagnostics through explicit emitter source markers.

Mappings refer to whole Hepta statements/declarations. They do not pretend
that generated Rust columns are precise Hepta expression columns.
"""
from __future__ import annotations

import json
from pathlib import PurePath

PREFIX = "// hepta-source: "


def source_markers(generated):
    result, stack = [], []
    for number, line in enumerate(generated.splitlines(), 1):
        stripped = line.strip()
        if not stripped.startswith(PREFIX):
            continue
        try:
            value = json.loads(stripped[len(PREFIX):])
        except (ValueError, TypeError):
            return []
        if not isinstance(value, dict):
            return []
        if value == {"event": "end"}:
            if not stack:
                return []
            start, span, kind = stack.pop()
            result.append((start + 1, number - 1, span, kind))
            continue
        span = value.get("span")
        if (not isinstance(span, dict) or not isinstance(span.get("path"), str)
                or value.get("event") != "begin" or value.get("kind") not in {"statement", "declaration"}
                or any(type(span.get(k)) is not int for k in ("start", "end", "line", "column"))
                or not 0 <= span["start"] <= span["end"] or span["line"] < 1 or span["column"] < 1):
            return []
        stack.append((number, {k: span[k] for k in ("path", "start", "end", "line", "column")}, value["kind"]))
    return [] if stack else result


def map_diagnostics(generated, diagnostics, *, generated_path=None):
    markers = source_markers(generated)
    out = []
    for diagnostic in diagnostics:
        mapped = []
        for span in diagnostic.get("generated_spans", []):
            line = span.get("line_start")
            last_line = span.get("line_end", line)
            # Expansion from an external Rust module is not in this source.
            filename = span.get("file_name", "")
            expected_file = filename == generated_path if generated_path is not None else PurePath(filename).name == "program.rs"
            if type(line) is not int or type(last_line) is not int or not expected_file:
                continue
            choices = [m for m in markers if m[0] <= line <= last_line <= m[1]]
            if not choices:
                continue
            _, _, original, kind = min(choices, key=lambda m: m[1] - m[0])
            mapped.append({"span": original, "precision": kind,
                           "is_primary": bool(span.get("is_primary")),
                           "generated_line": line})
        current = dict(diagnostic)
        if mapped:
            current["source_mappings"] = mapped
            current["span"] = next((m["span"] for m in mapped if m["is_primary"]), mapped[0]["span"])
        out.append(current)
    return out
