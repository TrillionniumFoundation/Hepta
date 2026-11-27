"""Build current native entry preparation tools from seven explicit native roots.

This is development orchestration. The products are not a cold qualification;
the public native construction must rebuild and compare the entry and roots.
"""
from pathlib import Path
from hashlib import sha256
import argparse
import json
import struct
import subprocess
import time
import traceback

ROOT_NAMES = (
    "hia-seed-assembly", "hia-seed-projector", "hia-seed-backend",
    "hia-seed-filter-pack", "hia-cold-qualification-driver",
    "hia-independent-subprocess", "hia-cold-process-owner",
)
PROFILE_SOURCE = {
    "v1": "seed_backend", "div": "seed_div_backend",
    "bulk": "seed_bulk_backend", "div-bulk": "seed_div_bulk_backend",
    "word": "seed_word_backend", "endian": "seed_endian_backend",
    "cold-bulk": "seed_cold_bulk_backend", "cold-endian": "seed_cold_endian_backend",
    "cold-endian-shift": "seed_cold_endian_shift_backend",
    "cold-bulk-word": "seed_cold_bulk_word_backend",
    "owned": "seed_owned_backend", "vm": "seed_vm_backend",
}

def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}

class Builder:
    def __init__(self, source, output, root_receipt):
        self.source = Path(source).resolve(strict=True)
        self.output = Path(output)
        self.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.calls = self.output / "calls"
        self.calls.mkdir(mode=0o700)
        self.root_dir = self.output / "bootstrap"
        self.root_dir.mkdir(mode=0o700)
        self.products_dir = self.output / "products"
        self.products_dir.mkdir(mode=0o700)
        self.record = {
            "schema": "hepta.hia.current-independent-entry-tools.v1",
            "passed": False, "source": str(self.source),
            "driver": {"path": __file__, **pin(Path(__file__).read_bytes())},
            "whole_cold_qualified": False, "whole_native_delivery_qualified": False,
            "target_or_successor_compiler_used": False,
            "python_orchestration_outside_production": True,
            "historical_qualification_reused": False,
            "initial_root_receipt": {"path": str(root_receipt), **pin(Path(root_receipt).read_bytes())},
            "initial_roots": [], "sources": {}, "invocations": [], "products": {},
        }
        prior = json.loads(Path(root_receipt).read_bytes())
        rows = prior["bootstrap"]
        assert [r["name"] for r in rows] == list(ROOT_NAMES)
        self.roots = {}
        for row in rows:
            raw = Path(row["path"]).read_bytes()
            assert pin(raw) == {k: row[k] for k in ("bytes", "sha256")}
            target = self.root_dir / row["name"]
            target.write_bytes(raw)
            target.chmod(0o500)
            assert target.read_bytes() == raw
            self.roots[row["name"]] = target
            self.record["initial_roots"].append({"name": row["name"], "path": str(target), **pin(raw)})
        self.flats = {}
        self.tools = {}
        self.backends = {"v1": self.roots["hia-seed-backend"]}
        self.save()

    def save(self):
        (self.output / "report.json").write_text(json.dumps(self.record, indent=2, sort_keys=True) + "\n")

    def invoke(self, label, executable, raw, arguments=(), timeout=30):
        number = len(self.record["invocations"])
        prefix = self.calls / ("%03d-" % number + label)
        (prefix.with_suffix(".stdin.bin")).write_bytes(raw)
        start = time.monotonic_ns()
        child = subprocess.run(
            [str(executable), *arguments], input=raw, capture_output=True,
            env={"PATH": "", "LANG": "C", "LC_ALL": "C"}, timeout=timeout,
        )
        prefix.with_suffix(".stdout.bin").write_bytes(child.stdout)
        prefix.with_suffix(".stderr.bin").write_bytes(child.stderr)
        row = {
            "label": label, "executable": str(executable), "executable_pin": pin(Path(executable).read_bytes()),
            "arguments": list(arguments), "input": pin(raw), "stdout": pin(child.stdout),
            "stderr": pin(child.stderr), "returncode": child.returncode,
            "wall_elapsed_ns": time.monotonic_ns() - start,
        }
        self.record["invocations"].append(row)
        self.save()
        print("NATIVE_PRESEED", label, child.returncode, len(child.stdout), flush=True)
        assert child.returncode == 0 and not child.stderr and child.stdout, row
        return child.stdout

    def source_bytes(self, role):
        name = "examples/hia_bootstrap/" + role + ".hepta"
        raw = (self.source / name).read_bytes()
        identity = pin(raw)
        if name in self.record["sources"]:
            assert self.record["sources"][name] == identity
        self.record["sources"][name] = identity
        return raw

    def profile(self, role):
        text = self.source_bytes(role).decode()
        div = "int.div" in text or "int.rem" in text
        bulk = "buffer.move_within" in text
        word = "buffer.store.u64.le" in text or "buffer.store.u64.be" in text
        endian = "buffer.load.u64.be" in text or "buffer.store.u64.be" in text
        if endian:
            assert not (div or bulk), (role, "undeclared combined endian profile")
            return "cold-endian"
        if word:
            assert not div, (role, "undeclared combined word/div profile")
            return "cold-bulk-word" if bulk else "word"
        return "div-bulk" if div and bulk else "div" if div else "cold-bulk" if bulk else "v1"

    def backend(self, profile):
        if profile not in self.backends:
            flat = self.flat(PROFILE_SOURCE[profile], "v1")
            packer = self.tool("seed_backend_filter_packer", "v1")
            image = self.framed(packer, "seed-" + profile + "-transport", b"HIAFLT01", [flat])
            assert image.startswith(b"\x7fELF")
            self.backends[profile] = self.publish("seed-" + profile + ".tool", image, inventory=False)
        return self.backends[profile]

    def flat(self, role, profile=None):
        profile = self.profile(role) if profile is None else profile
        key = role, profile
        if key not in self.flats:
            raw = self.source_bytes(role)
            core = self.invoke(role + "-core", self.roots["hia-seed-assembly"], raw, ("--agent-compact",))
            wire = b"[" + core + b',"f0",1]'
            projected = self.invoke(role + "-project", self.roots["hia-seed-projector"], wire)
            flat = self.invoke(role + "-flat-" + profile, self.backend(profile), projected)
            self.flats[key] = flat
            self.publish(role + "-" + profile + ".flat", flat, executable=False, inventory=False)
        return self.flats[key]

    def wrap(self, flat, label):
        raw = self.invoke(label + "-filter", self.roots["hia-seed-filter-pack"], b"HIAFLT01" + struct.pack("<Q", len(flat)) + flat)
        assert raw.startswith(b"\x7fELF")
        return self.publish(label + ".tool", raw, inventory=False)

    def tool(self, role, profile=None):
        profile = self.profile(role) if profile is None else profile
        key = role, profile
        if key not in self.tools:
            self.tools[key] = self.wrap(self.flat(role, profile), role + "-" + profile)
        return self.tools[key]

    def framed(self, tool, label, magic, pieces):
        raw = magic + struct.pack("<" + "Q" * len(pieces), *(len(p) for p in pieces)) + b"".join(pieces)
        return self.invoke(label, tool, raw)

    def publish(self, name, raw, executable=True, inventory=True):
        path = self.products_dir / name
        if path.exists():
            assert path.read_bytes() == raw
        else:
            path.write_bytes(raw)
            path.chmod(0o500 if executable else 0o400)
        if inventory:
            self.record["products"][name] = {"path": str(path), **pin(raw)}
            self.save()
        return path

    def construct(self):
        contract = self.tool("source_contract_generate")
        self.publish("hia-source-contract", contract.read_bytes())
        fallback = self.flat("cold_sha256_stream", "word")
        fast = self.flat("cold_sha256_nonalias", "cold-endian-shift")
        sha = self.framed(self.tool("cold_sha256_alias_packer", "word"),
                          "cold-sha-dispatch", b"HIASHA01", [fallback, fast])
        self.publish("tmp-cold-sha256-flat", sha, executable=False)
        # The qualification driver source changed after F.  Rebuild it through
        # the admitted independent native assembly/projector/backend/packer,
        # then preserve both the historical inputs and this exact new root.
        # No historical qualification or target compiler is inherited.
        policy = self.flat("cold_qualification_driver", "cold-bulk-word")
        driver_packer = self.tool("cold_qualification_driver_packer", "v1")
        driver = self.framed(driver_packer, "current-qualification-driver",
                             b"HIAQDP01", [policy, sha])
        import sys
        sys.path.insert(0, str(self.source))
        from tools.generate_hia_cold_qualification_driver import template
        reference_author = self.source / "tools/generate_hia_cold_qualification_driver.py"
        reference_author_raw = reference_author.read_bytes()
        prefix, holes = template()
        reference = bytearray(prefix + policy + sha)
        struct.pack_into("<Q", reference, 96, len(reference))
        struct.pack_into("<Q", reference, 104, len(reference))
        struct.pack_into("<I", reference, holes["policy_hole"],
                         len(prefix) - holes["policy_hole"] - 4)
        struct.pack_into("<I", reference, holes["sha_hole"],
                         len(prefix) + len(policy) - holes["sha_hole"] - 4)
        assert driver == bytes(reference)
        assert reference_author.read_bytes() == reference_author_raw
        historical = list(self.record["initial_roots"])
        fresh_root_dir = self.output / "current-bootstrap"
        fresh_root_dir.mkdir(mode=0o700, exist_ok=False)
        current = []
        for row in historical:
            raw = driver if row["name"] == "hia-cold-qualification-driver" else Path(row["path"]).read_bytes()
            if row["name"] != "hia-cold-qualification-driver":
                assert pin(raw) == {k: row[k] for k in ("bytes", "sha256")}
            target = fresh_root_dir / row["name"]
            with target.open("xb") as stream:
                stream.write(raw)
            target.chmod(0o500)
            assert target.stat().st_nlink == 1 and target.read_bytes() == raw
            current.append({"name": row["name"], "path": str(target), **pin(raw)})
        self.record["historical_bootstrap_inputs"] = historical
        self.record["initial_roots"] = current
        self.record["current_root_derivations"] = {
            "hia-cold-qualification-driver": {
                "source_path": "examples/hia_bootstrap/cold_qualification_driver.hepta",
                "source": self.record["sources"]["examples/hia_bootstrap/cold_qualification_driver.hepta"],
                "policy": pin(policy), "sha256_flat": pin(sha), "product": pin(driver),
                "native_packer": {"path": str(driver_packer), **pin(driver_packer.read_bytes())},
                "independent_reference_author": {"path": str(reference_author), **pin(reference_author_raw)},
                "independent_complete_byte_comparison": True,
                "whole_cold_qualification_claimed": False}}
        self.save()
        self.publish("tmp-build-entry-policy", self.flat("cold_build_entry"), executable=False)
        self.publish("tmp-build-entry-packer", self.tool("cold_build_entry_packer").read_bytes())
        self.publish("tmp-source-bootstrap-entry-policy", self.flat("cold_source_bootstrap_entry", "cold-bulk"), executable=False)
        self.publish("tmp-source-bootstrap-entry-packer", self.tool("cold_source_bootstrap_entry_packer", "v1").read_bytes())
        for name, expected in self.record["sources"].items():
            assert pin((self.source / name).read_bytes()) == expected, name
        self.record["passed"] = True
        self.record["current_source_pins_preserved"] = True
        self.save()
        print("CURRENT_NATIVE_PRESEED_PASS", len(self.record["sources"]), len(self.record["invocations"]), flush=True)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--root-receipt", type=Path, required=True)
    args = parser.parse_args()
    builder = Builder(args.source, args.output, args.root_receipt)
    try:
        builder.construct()
    except BaseException:
        builder.record["error"] = traceback.format_exc()
        builder.save()
        raise

if __name__ == "__main__":
    main()
