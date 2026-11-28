"""Exact one-byte options-domain preparation for the retained full Worker CLI gate.

This is an external qualification fixture. It never participates in an installed
Worker and preserves every original scenario, assertion, and timeout.
"""
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import ast
import json

ROOT = Path(__file__).resolve().parents[1]
SELF = "tools/hia_worker_entry_protocol_fixture.py"
ORIGINAL = "tools/qualify_hia_worker_install_entry.py"
FIXTURE = "tests/fixtures/hia_worker_entry_protocol_original_v1.json"
FIXTURE_SHA256 = "7138fecd1ad7fa917054be3babd9ff7347968c79589f1ae98d1f8b92ccbaa8bd"
ORIGINAL_SHA256 = "bf2cfbc9f9767be73240f8d612540f327025636d746914c480944698f333384a"
_EXECUTING_SOURCE = Path(__file__).read_bytes()


@dataclass
class Prepared:
    root: Path
    take: object
    protocol: str
    source: bytes
    captured: dict

    def verify(self):
        for name, raw in self.captured.items():
            if self.take(self.root / name) != raw:
                raise ValueError("Worker entry fixture input changed: " + name)

    def evidence(self):
        return {"protocol": self.protocol,
                "scope": "EXPLICIT_FULL_CLI_FIXTURE_OPTIONS_DOMAIN_ONLY",
                "original_sha256": ORIGINAL_SHA256,
                "prepared_bytes": len(self.source),
                "prepared_sha256": sha256(self.source).hexdigest(),
                "physical_inputs": {n: {"bytes": len(b), "sha256": sha256(b).hexdigest()}
                                    for n, b in sorted(self.captured.items())}}


def prepare(root, protocol, *, take=Path.read_bytes):
    if type(protocol) is not str or protocol not in ("01", "02", "03"):
        raise ValueError("unknown fixed Worker options domain")
    root = Path(root).resolve(strict=True)
    captured = {}
    for name in (SELF, FIXTURE, ORIGINAL):
        raw = take(root / name)
        if type(raw) is not bytes:
            raise ValueError("Worker fixture requires captured bytes")
        captured[name] = raw
    if captured[SELF] != _EXECUTING_SOURCE:
        raise ValueError("executing Worker fixture source differs")
    raw = captured[FIXTURE]
    if sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError("fixed complete Worker CLI fixture differs")
    value = json.loads(raw)
    original = value["source"].encode("utf-8")
    if (value["path"] != ORIGINAL or value["bytes"] != len(original)
            or value["sha256"] != ORIGINAL_SHA256
            or sha256(original).hexdigest() != ORIGINAL_SHA256
            or captured[ORIGINAL] != original):
        raise ValueError("original complete Worker CLI source differs")
    before = b"options==b'HIAWOP01'"
    after = ("options==b'HIAWOP"+protocol+"'").encode("ascii")
    if original.count(before) != 1:
        raise ValueError("fixed options assertion is not unique")
    prepared = original.replace(before, after)
    if prepared.replace(after, before) != original:
        raise ValueError("Worker fixture inverse differs")
    # Only the one protocol literal may differ in the complete original AST.
    class Domain(ast.NodeTransformer):
        def visit_Constant(self, node):
            if type(node.value) is bytes and node.value == ("HIAWOP"+protocol).encode():
                return ast.copy_location(ast.Constant(value=b"HIAWOP01"), node)
            return node
    if ast.dump(Domain().visit(ast.parse(prepared)), include_attributes=False) != ast.dump(
            ast.parse(original), include_attributes=False):
        raise ValueError("Worker fixture changed outside the options-domain assertion")
    result = Prepared(root, take, protocol, prepared, captured)
    result.verify()
    return result
