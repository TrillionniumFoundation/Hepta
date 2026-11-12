"""Read existing source bytes and build an unexecuted template-authoring revision.

This is a static extraction/projection tool. It never imports project modules,
invokes a generator, runs machine code, or starts a process.
"""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
BASE = Path("/workspace/scratch/e26ed3e2edcf/core-numeric-v88-integration-r1/source")
NAMES = ("artifact_publication", "release_install")
EXPECTED = {
    "artifact_publication": {
        "generator_sha256": "9d1f46a84c39e26bbb50764fbd885b2ca7cad85aa39031b94111897534eb83c1",
        "prefix_bytes": 4154, "holes": [425, 3751, 3797],
    },
    "release_install": {
        "prefix_bytes": 3623, "holes": [389, 3500, 3546],
    },
}
HOLE_NAMES = ("policy_initial_hole", "policy_hole", "sha_hole")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path, raw):
    return {
        "path": path, "bytes": len(raw), "sha256": sha(raw),
        "git_blob_sha1": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
    }


def save(path, raw):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as stream:
        stream.write(raw)
    return pin(path, raw)


def node_text(text, node):
    return "".join(text.splitlines(keepends=True)[node.lineno - 1: node.end_lineno])


def extract_prefix(raw):
    """Read f0's literal f3 write calls; no HIA instructions are executed."""
    text = raw.decode("utf-8")
    function = None
    constants = {}
    prefix = bytearray()
    records = []
    trailing_writes = []
    collecting = True
    for number, line in enumerate(text.splitlines(), 1):
        if line.startswith("fn "):
            function = line.split("(", 1)[0][3:]
            constants = {}
        if function != "f0":
            continue
        if line.startswith("block "):
            constants = {}
        item = re.fullmatch(r"  (v\d+):u64 = const\(\) (\{.*\})", line)
        if item:
            value = json.loads(item[2])["value"]
            if type(value) is not int or not 0 <= value < 1 << 64:
                raise ValueError("non-u64 literal")
            constants[item[1]] = value
            continue
        item = re.fullmatch(r"  v\d+:u64 = call\(([^)]*)\) \{\"function\":\"f3\"\}", line)
        if not item:
            continue
        arguments = item[1].split(",")
        if len(arguments) != 4:
            raise ValueError("unexpected write signature")
        _, at_name, value_name, count_name = arguments
        at = constants.get(at_name)
        value = constants.get(value_name)
        count = constants.get(count_name)
        if collecting and prefix and (at != len(prefix) or value is None or count is None):
            collecting = False
        if collecting:
            if at != len(prefix) or value is None or count not in range(1, 9):
                raise ValueError("literal writes are not an exact contiguous prefix")
            if value >= 1 << (8 * count):
                raise ValueError("literal write loses bits")
            prefix.extend(value.to_bytes(count, "little"))
            records.append({"line": number, "offset": at, "value": value, "bytes": count})
        else:
            trailing_writes.append({
                "line": number, "offset": at, "bytes": count,
                "arguments": arguments, "raw": line,
            })
    if [row["offset"] for row in trailing_writes[:2]] != [96, 104]:
        raise ValueError("fixed ELF extent writes differ")
    if len(trailing_writes) != 5 or any(row["bytes"] != 4 for row in trailing_writes[2:]):
        raise ValueError("expected exactly three rel32 hole writes")
    holes = [row["offset"] for row in trailing_writes[2:]]
    for offset in holes:
        if prefix[offset - 1:offset + 4] != b"\xe8\0\0\0\0":
            raise ValueError("expected an unresolved direct-call hole")
    return bytes(prefix), holes, records, trailing_writes


def literal_section(name, code, holes, source_sha):
    groups = [code.hex()[i:i+96] for i in range(0, len(code.hex()), 96)]
    literals = "\n".join("    " + repr(group) for group in groups)
    values = dict(zip(HOLE_NAMES, (offset - 176 for offset in holes)))
    return f'''# Fixed Linux/SysV transport. HIA owns the policy and ELF packer below.
# Keep the .S source and assembled_template() as the independent authoring oracle.
# No assembler, linker, payload code, or native image is executed by template().
TRANSPORT_SOURCE_SHA256 = {source_sha!r}
TRANSPORT_SHA256 = {sha(code)!r}
TRANSPORT_BYTES = {len(code)}
TRANSPORT = bytes.fromhex(
{literals}
)
TRANSPORT_HOLES = {values!r}


def template():
    source = ROOT / "tools/hia_{name}_syscalls.S"
    if hashlib.sha256(source.read_bytes()).hexdigest() != TRANSPORT_SOURCE_SHA256:
        raise ValueError("fixed {name} syscall source changed; refresh and independently verify the transport")
    if len(TRANSPORT) != TRANSPORT_BYTES or hashlib.sha256(TRANSPORT).hexdigest() != TRANSPORT_SHA256:
        raise ValueError("fixed {name} transport bytes changed")
    expected_holes = {values!r}
    if TRANSPORT_HOLES != expected_holes:
        raise ValueError("fixed {name} transport holes changed")
    for offset in TRANSPORT_HOLES.values():
        if TRANSPORT[offset - 1:offset + 4] != b"\\xe8\\0\\0\\0\\0":
            raise ValueError("fixed {name} rel32 call hole changed")
    header = (b"\\x7fELF\\x02\\x01\\x01" + bytes(9)
              + struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
              + struct.pack("<IIQQQQQQ", 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    return header + TRANSPORT, {{name: 176 + offset for name, offset in TRANSPORT_HOLES.items()}}


'''


def main():
    files = []
    derivations = []
    for name in NAMES:
        generator_path = f"tools/generate_hia_{name}.py"
        assembly_path = f"tools/hia_{name}_syscalls.S"
        packer_path = f"examples/hia_bootstrap/{name}_packer.hiaasm"
        policy_path = f"examples/hia_bootstrap/{name}_policy.hiaasm"
        originals = {path: (BASE / path).read_bytes() for path in (
            generator_path, assembly_path, packer_path, policy_path)}
        wanted = EXPECTED[name]
        if "generator_sha256" in wanted and sha(originals[generator_path]) != wanted["generator_sha256"]:
            raise ValueError("source generator identity differs")
        prefix, holes, records, trailing = extract_prefix(originals[packer_path])
        if len(prefix) != wanted["prefix_bytes"] or holes != wanted["holes"]:
            raise ValueError("extracted prefix differs from reviewed literal call sites")
        if prefix[:8] != b"\x7fELF\x02\x01\x01\0":
            raise ValueError("fixed ELF header differs")
        text = originals[generator_path].decode()
        tree = ast.parse(text)
        original = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "template")
        original_body = node_text(text, original)
        renamed = original_body.replace("def template():", "def assembled_template():", 1)
        if renamed == original_body:
            raise ValueError("oracle rename anchor differs")
        updated = text[:]
        updated = updated.replace("from __future__ import annotations\n", "from __future__ import annotations\n\nimport hashlib\n", 1)
        updated = updated.replace(original_body, literal_section(name, prefix[176:], holes, sha(originals[assembly_path])) + renamed, 1)
        # An exact reverse projection proves that the original policy/packer and
        # assembler body are retained byte for byte, apart from the oracle name.
        replacement = literal_section(name, prefix[176:], holes, sha(originals[assembly_path])) + renamed
        reverse = updated.replace(replacement, original_body, 1)
        reverse = reverse.replace("from __future__ import annotations\n\nimport hashlib\n", "from __future__ import annotations\n", 1)
        if reverse != text:
            raise ValueError("candidate reverse projection differs")
        ast.parse(updated)
        files.append(save("inputs/" + generator_path, updated.encode()))
        for path, raw in originals.items():
            files.append(save("reference/" + path, raw))
        files.append(save(f"reference/{name}.transport.bin", prefix[176:]))
        files.append(save(f"reference/{name}.prefix.bin", prefix))
        derivations.append({
            "name": name, "generator": pin(generator_path, originals[generator_path]),
            "assembly": pin(assembly_path, originals[assembly_path]),
            "packer": pin(packer_path, originals[packer_path]),
            "prefix": pin(f"{name}.prefix.bin", prefix),
            "transport": pin(f"{name}.transport.bin", prefix[176:]),
            "holes_in_prefix": dict(zip(HOLE_NAMES, holes)),
            "holes_in_transport": dict(zip(HOLE_NAMES, (offset - 176 for offset in holes))),
            "literal_writes": records, "following_writes": trailing,
            "original_body_retained": True,
            "reverse_projection_exact": True,
            "candidate_ast_parsed": True,
            "candidate_generated": False,
            "assembler_oracle_executed": False,
            "native_executed": False,
        })
    report = {
        "schema": "hepta.hia.fixed-transport-source-repair.derivation.v1",
        "status": "STATIC_EXTRACTION_AND_PROJECTION_PASS",
        "source_failure_run": 43261208151,
        "source_failure_job": 131332684167,
        "source_failure_artifact": 13963368322,
        "source_failure_artifact_sha256": "4dabb0b7ddcf5c0cc8d4582c2da1ca5fa55e347a95fb010ea14cea4ef3b984d3",
        "baseline": str(BASE), "derivations": derivations, "files": files,
        "scope": {"generator_execution": False, "source83": False,
                  "native": False, "independent_assembler_oracle": False},
    }
    save("DERIVATION.json", (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({"status": report["status"], "files": len(files),
                      "templates": [{k: row[k] for k in ("name", "prefix", "transport", "holes_in_prefix")} for row in derivations]}))


if __name__ == "__main__":
    main()

