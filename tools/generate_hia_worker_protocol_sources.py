"""Regenerate all closed native Worker installation protocol sources.

The ordinary product is fixed protocol 03. Protocols 01/02 are separate complete
compatibility installations, with their own native owners, tables and DAGs.
Authoring does not run in a published installation.
"""
from pathlib import Path
from hashlib import sha256
import argparse
import json

ROOT = Path(__file__).resolve().parents[1]


def generated_files(native_source_authority=None):
    if native_source_authority is None:
        raise ValueError("native Worker products require an explicit native source authority")
    from tools.hia_worker_protocols import PROTOCOLS, protocol, recipe_path
    from tools.generate_hia_worker_protocol_manifest import generated_files as manifest_files
    from tools.generate_hia_worker_install_recipes import recipes
    from tools import generate_hia_worker_install_owner as owner
    from tools import generate_hia_worker_install_entry as entry
    from tools import generate_hia_worker_install_bind as binding
    from tools import generate_hia_worker_continuation_pack as continuation
    from tools.generate_hia_artifact_publication import document
    from hepta.hia_agent_assembly import render_assembly
    from hepta.hia_program import verify_program

    result = {}
    records = []

    def add(name, raw):
        if name in result or type(raw) is not bytes or not raw:
            raise ValueError("duplicate or empty Worker generated source: " + name)
        result[name] = raw

    # Shared current mechanics preserve their independent protocol domains.
    for profile in ("v1", "v2"):
        text, stats = continuation.render(profile)
        suffix = "_v2" if profile == "v2" else ""
        add("examples/hia_bootstrap/source_worker_continuation_pack" + suffix + ".hepta",
            text.encode("ascii"))
    for number in ("01", "03"):
        text, stats = binding.render(protocol=number)
        suffix = "_v1" if number == "01" else ""
        add("examples/hia_bootstrap/source_worker_install_bind" + suffix + ".hepta",
            text.encode("ascii"))

    mechanical_packer = owner.packer_source()
    for number in PROTOCOLS:
        selected = protocol(number)
        files, stats = manifest_files(native_source_authority, protocol=number)
        for name, raw in files.items():
            add(name, raw)
        for kind, recipe in recipes(native_source_authority, protocol=number).items():
            add(recipe_path(number, kind), recipe.binary())
        sources = (
            (selected.install_stem + "_owner", owner.policy_source(protocol=number)),
            (selected.install_stem + "_dag", owner.policy_source(stage=True, protocol=number)),
            (selected.install_stem + "_owner_packer", mechanical_packer),
        )
        for name, source in sources:
            value = document(source, name)
            verify_program(value)
            add("examples/hia_bootstrap/" + name + ".hepta",
                render_assembly(value).encode("ascii"))
        outputs, entry_metadata = entry.render(number)
        for name, text in outputs.items():
            add("examples/hia_bootstrap/" + name + ".hepta", text.encode("ascii"))
        records.append(dict(protocol=number, helpers=selected.helper_count,
                            records=stats["recipes"], core_profile=selected.core_profile,
                            entry=selected.entry_executable, compatibility=number != "03"))
    return result, records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--native-source-authority", type=Path, required=True)
    args = parser.parse_args()
    captured = (args.native_source_authority.read_bytes()
                if args.native_source_authority is not None else None)
    products, records = generated_files(args.native_source_authority)
    if captured is not None and args.native_source_authority.read_bytes() != captured:
        raise ValueError("native authority changed while authoring Worker protocols")
    for name, raw in products.items():
        target = ROOT / name
        if args.check:
            if target.read_bytes() != raw:
                raise SystemExit("Worker protocol source differs: " + name)
        else:
            target.write_bytes(raw)
    print(json.dumps(dict(protocols=records, products=len(products),
                          check=args.check,
                          native_authority_sha256=sha256(captured).hexdigest() if captured is not None else None),
                     sort_keys=True))


if __name__ == "__main__":
    main()
