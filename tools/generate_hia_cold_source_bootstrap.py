"""Serialize the closed native post-cold construction graph.

The production graph always admits the actual captured final-cold.json, B3,
source inventory and contract before executing B3.  All compilation, packing,
SHA, exact equality and source-kit fixed-point checks are HIA operations.
This development serializer supplies only relative paths and topology.
"""
from pathlib import Path
import argparse
import json

from tools.generate_hia_cold_toolchain_build import (
    ROOT, BOOT, AUTHORITY, POST_RECIPE, BOOTSTRAP, Build, q, cold_sha,
)
from tools.hia_cold_qualification_plan_parts import (
    call, observe, check_flat, utility,
)
from tools.generate_hia_cold_qualification_plan import U64

PLANS = BOOT + "cold_source_bootstrap_plans/"
CAPACITY = 1 << 20


def bounded_length(p, handle, maximum, label):
    length = p.length(handle)
    bounded = p.number(length, 0, maximum=maximum)
    p.drop(length)
    return bounded


def actual_frame(s, magic, parts, label, extra=()):
    p = s.p
    header = p.literal(magic)
    sizes = [p.length(part) for part in parts]
    wire = p.concat(header, *sizes, *extra, *parts, label=label)
    p.drop(header, *sizes)
    return wire


def independent_profile(s, name, role):
    policy = s.flat(role, "v1")
    image = s.framed(s.tool("seed_backend_filter_packer", "v1"),
                     b"HIAFLT01", [policy], "post-bootstrap-" + name)
    s.seeds[name] = image
    return image


def independent_roots(s):
    s.semantic_roots()
    independent_profile(s, "bulk", "seed_bulk_backend")
    independent_profile(s, "word", "seed_word_backend")
    independent_profile(s, "endian", "seed_endian_backend")
    independent_profile(s, "cold-bulk", "seed_cold_bulk_backend")
    independent_profile(s, "cold-endian", "seed_cold_endian_backend")
    independent_profile(s, "cold-bulk-word", "seed_cold_bulk_word_backend")
    return s


def admit_actual_cold(s):
    """The sole production path to a B3 handle."""
    p = s.p
    b3 = s.bind("actual-current-B3", 6, 0)
    cold = s.bind("actual-current-cold-report", 7, 0)
    manifest = s.bind("actual-source-manifest", 3, 0)
    inventory = call(p, s.tool("source_contract_manifest", "v1"), manifest,
                     label="captured-source-manifest-to-exact-inventory")
    contract = s.source("docs/HIA_SELFHOST_CORE_SUPPORT.json")
    refusal = s.flat("cold_build_refusal", "v1")
    gate = s.packed("source_release_cold_admit", "source_build_packer",
                    b"HIASBL01", (refusal, refusal))
    b3_pin = p.sha256(b3)
    cold_pin = p.sha256(cold)
    frame = actual_frame(s, b"HIACLD01", [cold, inventory, contract],
                         "strict-whole-cold-and-current-source-frame",
                         extra=(b3_pin,))
    receipt = call(p, gate, frame, argv=("hia-cold-admit", "build"),
                   label="strict-sixty-phase-current-source-current-B3-admission")
    magic = p.literal(b"HIAADC01")
    count = p.slice(inventory, 8, 8)
    expected = p.concat(magic, b3_pin, count)
    p.compare(receipt, expected, label="exact-admitted-B3-and-source-count")
    binding_magic = p.literal(b"HIASBIN1")
    binding = p.concat(binding_magic, b3_pin, cold_pin, receipt)
    s.publish(binding, "cold-inputs.receipt", "cold-inputs.receipt",
              executable=False, maximum=120)
    p.drop(frame, magic, count, expected, binding_magic, binding,
           b3_pin, cold_pin, receipt)
    return b3


class TargetCompiler:
    """Actual admitted B3, observed by an independently constructed tool."""
    def __init__(self, s, b3):
        self.s, self.p, self.b3 = s, s.p, b3
        empty = self.p.literal(b"")
        self.observer = call(self.p, s.tool("native_observer_packer", "v1"),
                             empty, label="independent-compiler-observer")
        self.p.drop(empty)
        self.check = s.tool("cold_qualification_flat", "v1")
        self.util = s.tool("cold_qualification_util", "v1")
        self.flats = {}

    def invoke(self, image, source, label):
        observed = observe(self.p, self.observer, image, source,
                           cap=CAPACITY, work=CAPACITY, label=label)
        product = check_flat(self.p, self.check, observed, source,
                             cap=CAPACITY, work=CAPACITY, mode=0,
                             label=label + ":complete-source-output-and-receipt")
        self.p.drop(observed)
        return product

    def flat(self, role):
        if role not in self.flats:
            source = self.s.source(BOOT + role + ".hepta")
            self.flats[role] = self.invoke(
                self.b3, source, role + ":actual-admitted-B3-compile")
        return self.flats[role]

    def inspect(self, image, label):
        inspected = utility(self.p, self.util, 3, image,
                            label=label + ":closed-ELF-inspection")
        self.p.drop(inspected)
        return image

    def pack(self, packer, magic, parts, label):
        frame = actual_frame(self.s, magic, parts, label + ":native-pack-frame")
        checked_size = bounded_length(self.p, frame, CAPACITY,
                                      label + ":retained-observer-input-bound")
        self.p.drop(checked_size)
        image = self.invoke(self.flat(packer), frame, label + ":native-pack")
        self.p.drop(frame)
        return self.inspect(image, label)


def source_bundle(p, members, label):
    head = p.literal(b"HIAREL01" + q(len(members), 0))
    pieces, temporary = [head], [head]
    for name, raw in members:
        encoded = name.encode("ascii")
        prefix = p.literal(q(len(encoded), 0o400))
        size = bounded_length(p, raw, CAPACITY, label + ":" + name + ":extent")
        path = p.literal(encoded)
        pieces += [prefix, size, path, raw]
        temporary += [prefix, size, path]
    result = p.concat(*pieces, label=label)
    p.drop(*temporary)
    return result


def construct_release_bootstrap(s, b3):
    """Reusable construction body; production calls it only after strict admission."""
    p = s.p
    target = TargetCompiler(s, b3)
    policy = target.flat("source_build_policy")
    packer = target.flat("source_build_packer")
    bootstrap = target.pack("source_build_packer", b"HIASBL01",
                            [policy, b3, packer], "source-builder-bootstrap")
    selfhost_source = s.source(BOOT + "selfhost.hepta")
    reproduced = call(p, bootstrap, selfhost_source,
                      argv=("hia-source-build", "compile"),
                      label="raw-source-compiler-reproduces-admitted-B3")
    p.compare(reproduced, b3, label="compiled-selfhost-entire-B3-equality")
    p.drop(reproduced)
    roles = ("source_build_policy.hepta", "selfhost.hepta",
             "source_build_packer.hepta")
    source_members = [(name, s.source(BOOT + name)) for name in roles]
    source_wire = source_bundle(p, source_members, "source-builder-three-role-input")
    images = (policy, b3, packer)
    expected_members = []
    for (name, source), image in zip(source_members, images):
        expected_members += [(name, source), (name + ".bin", image)]
    expected_kit = source_bundle(p, expected_members,
                                "actual-current-source-and-B3-compiled-six-member-kit")
    prior_kit = None
    for generation in (1, 2):
        kit = call(p, bootstrap, source_wire,
                   argv=("hia-source-build", "build"),
                   label=f"source-builder-native-generation-{generation}-compile")
        p.compare(kit, expected_kit,
                  label=f"generation-{generation}-exact-current-source-image-kit")
        if prior_kit is not None:
            p.compare(kit, prior_kit, label="native-generations-sourcekit-byte-equality")
            p.drop(prior_kit)
        rebuilt = call(p, bootstrap, kit, argv=("hia-source-build", "pack"),
                       label=f"source-builder-native-generation-{generation}-self-pack")
        p.compare(rebuilt, bootstrap,
                  label=f"generation-{generation}-entire-executable-fixed-point")
        p.drop(bootstrap)
        bootstrap, prior_kit = rebuilt, kit
    s.publish(bootstrap, "hia-source-build", "hia-source-build")
    p.drop(source_wire, expected_kit, prior_kit)

    sha = target.flat("sha256_stream")
    runner = target.pack("subprocess_packer", b"HIASUPK1",
                         [target.flat("subprocess")], "release-subprocess")
    capture = target.pack("source_capture_packer", b"HIACAPK1",
                          [target.flat("source_capture"), sha],
                          "release-source-capture")
    owner = target.pack("release_owner_packer", b"HIAOWPK1",
                        [target.flat("release_owner"), target.flat("release_dag"), sha],
                        "release-five-DAG-owner")
    for name, image in (("hia-release-owner", owner),
                        ("hia-subprocess", runner),
                        ("hia-source-capture", capture)):
        s.publish(image, name, name)

    unbound = target.pack("release_build_entry_packer", b"HIAENPK1",
                          [target.flat("release_build_entry"), sha],
                          "ordinary-release-entry-unbound")
    binder = target.pack("source_build_packer", b"HIASBL01",
                         [target.flat("release_build_entry_bind"), b3, packer],
                         "ordinary-entry-four-capability-binder")
    pins = [p.sha256(image) for image in (owner, runner, bootstrap, capture)]
    magic = p.literal(b"HIAENBD1")
    request = p.concat(magic, *pins, unbound)
    bound = call(p, binder, request, argv=("hia-release-entry-bind", "build"),
                 label="ordinary-entry-binds-actual-four-capabilities")
    old_head, new_head = p.slice(unbound, 0, 824), p.slice(bound, 0, 824)
    old_tail, new_tail = p.slice(unbound, 952, U64), p.slice(bound, 952, U64)
    actual_pins = p.slice(bound, 824, 128)
    expected_pins = p.concat(*pins)
    old_size, new_size = p.length(unbound), p.length(bound)
    p.compare(old_head, new_head, label="entry-binding-preserves-entire-prefix")
    p.compare(old_tail, new_tail, label="entry-binding-preserves-all-code-and-metadata")
    p.compare(actual_pins, expected_pins, label="entry-binding-exact-four-current-pins")
    p.compare(old_size, new_size, label="entry-binding-preserves-exact-extent")
    target.inspect(bound, "ordinary-bound-release-entry")
    s.publish(bound, "hia-release-build", "hia-release-build")
    p.drop(magic, request, old_head, new_head, old_tail, new_tail,
           actual_pins, expected_pins, old_size, new_size, *pins)
    installer = target.pack("release_install_packer", b"HIAINS01",
                            [target.flat("release_install_policy"), sha],
                            "release-package-installer")
    return {"builder": bootstrap, "owner": owner, "runner": runner,
            "capture": capture, "entry": bound, "installer": installer}


def rebuild_public_self(s):
    p = s.p
    authority = s.source(AUTHORITY)
    recipe = s.source(POST_RECIPE)
    pins = [p.sha256(authority), p.sha256(recipe)]
    pins.extend(p.sha256(s.boot(i)) for i in range(7))
    policy = s.flat("cold_source_bootstrap_entry", "cold-bulk")
    sha = cold_sha(s)
    packer = s.tool("cold_source_bootstrap_entry_packer", "v1")
    rebuilt = s.framed(packer, b"HIASBP01", [policy, sha],
                       "post-entry-independent-source-rebuild", extra=pins)
    current = s.bind("actual-current-bootstrap-entry", 5, 0)
    p.compare(rebuilt, current,
              label="post-entry-entire-image-equals-current-captured-executable")
    s.publish(rebuilt, "hia-source-bootstrap", "hia-source-bootstrap")
    p.drop(*pins)


def build_plans(root=ROOT):
    build = Build(Path(root), plan_prefix=PLANS)
    s = independent_roots(build.stage("source-bootstrap"))
    b3 = admit_actual_cold(s)
    release = construct_release_bootstrap(s, b3)
    rebuild_public_self(s)
    # Preserve the baseline seven publications and append the independently
    # source-built native installer; installation never needs host extraction.
    s.publish(release["installer"], "hia-release", "hia-release")
    result = build.finish(Path(root) / PLANS)
    result["schema"] = "hepta.hia.native-source-bootstrap-build.v1"
    result["target_compiler_required"] = True
    result["target_compiler_authority"] = "current captured cold input, after strict native whole admission"
    result["source_paths"] = sorted(set(result["source_paths"]) | {POST_RECIPE})
    (Path(root) / PLANS / "build-plan.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    result = build_plans(args.root)
    print(json.dumps({"stages": len(result["stages"]),
                      "maximum_stage_imports": result["maximum_stage_imports"],
                      "nodes": result["total_nodes"],
                      "publications": len(result["publications"])}, sort_keys=True))


if __name__ == "__main__":
    main()
