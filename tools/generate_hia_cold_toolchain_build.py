"""Development serializer for the public, entirely native cold toolchain build.

The emitted HIAQPL01 plans perform every source projection, machine emission,
link, pack and binding operation at run time.  This serializer selects source
paths and topology; it embeds neither machine images nor historical results.
"""
from pathlib import Path
from hashlib import sha256
import argparse
import json
import struct

from tools.generate_hia_cold_qualification_plan import Plan, U64
from tools.hia_cold_qualification_plan_parts import call

ROOT = Path(__file__).resolve().parents[1]
BOOT = "examples/hia_bootstrap/"
PLANS = BOOT + "cold_build_plans/"
AUTHORITY = BOOT + "cold_build_sources.hiadat"
RECIPE = BOOT + "cold_build_recipe.hiadat"
POST_RECIPE = BOOT + "cold_source_bootstrap_recipe.hiadat"
BUNDLE_RECIPE = BOOT + "cold_bundle_recipe.hiadat"
BOOTSTRAP = (
    "hia-seed-assembly", "hia-seed-projector", "hia-seed-backend",
    "hia-seed-filter-pack", "hia-cold-qualification-driver",
    "hia-independent-subprocess", "hia-cold-process-owner",
)
TOP_ROOTS = {
    0: BOOTSTRAP[4], 2: BOOTSTRAP[5], 3: BOOTSTRAP[6],
    4: BOOTSTRAP[0], 5: BOOTSTRAP[1], 40: BOOTSTRAP[2],
}
PROFILE_SOURCE = {
    "v1": "seed_backend", "div": "seed_div_backend",
    "bulk": "seed_bulk_backend", "div-bulk": "seed_div_bulk_backend",
    "word": "seed_word_backend", "endian": "seed_endian_backend",
    "cold-bulk": "seed_cold_bulk_backend", "cold-endian": "seed_cold_endian_backend",
    "owned": "seed_owned_backend",
    "vm": "seed_vm_backend",
}
FRONT = (
    "seed_front_bulk/core_cli/assembly_syntax_diagnostics",
    "seed_front_bulk/core_admission", "seed_front_bulk/json_canonical",
    "seed_front_bulk/core_cli/assembly_diagnostic_report",
    "seed_front_bulk/core_cli/assembly_pretty", "core_cli/assembly_driver",
    "seed_front_bulk/core_edit/publication_frontend",
    "seed_front_bulk/core_edit/publication_import", "core_edit/publication_policy",
)
GENERIC_ROOTS = (
    (8, "cases_gate", "cold_cases_gate"),
    (10, "check", "cold_qualification_flat"),
    (12, "linked_check", "cold_qualification_linked"),
    (13, "linker", "cold_export_linker"),
    (14, "owned_inventory", "cold_owned_elf_inventory"),
    (15, "util", "cold_qualification_util"),
    (20, "structure", "cold_source_structure"),
    (23, "word_source", "cold_export_word_source"),
    (27, "mutate", "cold_qualification_mutation"),
    (28, "alpha_tool", "cold_qualification_alpha"),
    (42, "observer_linker", "cold_observer_linker"),
    (44, "export_inventory", "cold_export_inventory"),
    (45, "general_linker", "elf_shared_linker"),
    (47, "allocator_bundle", "cold_allocator_bundle"),
    (48, "allocator_bind", "cold_allocator_bind"),
    (50, "allocator_gate", "cold_allocator_validate"),
)


def q(*values):
    return struct.pack("<" + "Q" * len(values), *values)


def artifact(index, name):
    return f"artifact-{index:03d}-{name}"


def root_path(index, name):
    return TOP_ROOTS.get(index, "roots/" + artifact(index, name))


def normalize_bundle_recipe(path):
    raw = bytearray(path.read_bytes())
    if raw[:8] != b"HIAQBT01":
        raise ValueError("closed bundle recipe magic")
    count = struct.unpack_from("<Q", raw, 16)[0]
    seen = set()
    for i in range(count):
        at = 256 + 384 * i
        name_n = struct.unpack_from("<Q", raw, at + 8)[0]
        name = bytes(raw[at + 64:at + 64 + name_n]).decode("ascii")
        index = int(name.split("-")[1])
        if index in TOP_ROOTS:
            if struct.unpack_from("<Q", raw, at + 24)[0] != 0:
                raise ValueError("bootstrap root must be a tool file")
            target = TOP_ROOTS[index].encode("ascii")
            struct.pack_into("<Q", raw, at + 16, len(target))
            raw[at + 192:at + 384] = target.ljust(192, b"\0")
            seen.add(index)
    if seen != set(TOP_ROOTS):
        raise ValueError("missing bootstrap root from bundle recipe")
    if bytes(raw) != path.read_bytes():
        path.write_bytes(raw)
    return bytes(raw)


def phase_sources(raw):
    nr, np = struct.unpack_from("<2Q", raw, 16)
    start = 256 + nr * 384
    result = []
    for i in range(np):
        at = start + i * 384
        n = struct.unpack_from("<Q", raw, at + 176)[0]
        path = raw[at + 256:at + 256 + n].decode("ascii")
        if not path or path.startswith("/") or ".." in path.split("/"):
            raise ValueError("phase source path")
        result.append(path)
    if len(result) != 60 or len(set(result)) != 60:
        raise ValueError("the complete source-bound sixty phase set is required")
    return result


class Build:
    def __init__(self, root, plan_prefix=PLANS):
        self.root = Path(root)
        self.plan_prefix = plan_prefix
        self.stages = []
        self.publications = []
        self.by_publication = {}

    def stage(self, name):
        s = Stage(self, len(self.stages), name)
        self.stages.append(s)
        return s

    def finish(self, directory):
        directory.mkdir(parents=True, exist_ok=True)
        source_paths = set()
        rows = []
        for stage in self.stages:
            packed = stage.p.pack()
            path = self.plan_prefix + f"{stage.index:02d}-{stage.name}.hiacases"
            (self.root / path).write_bytes(packed)
            if len(stage.bindings) > 64:
                raise ValueError((stage.name, "more than sixty-four stage imports"))
            source_paths.update(b["source"] for b in stage.bindings if b["kind"] == 1)
            source_paths.add(path)
            rows.append({
                "id": stage.index, "name": stage.name, "plan": path,
                "plan_sha256": sha256(packed).hexdigest(), "plan_bytes": len(packed),
                "nodes": len(stage.p.nodes), "bindings": stage.bindings,
                "publication_start": stage.publication_start,
                "publication_count": len(stage.publications),
                "publications": stage.publications,
                "peak_handle": stage.p.next_id - 1,
            })
        result = {
            "schema": "hepta.hia.native-cold-toolchain-build.v1",
            "scope": "immutable construction topology; qualification is separate",
            "bootstrap": list(BOOTSTRAP), "stages": rows,
            "publications": self.publications,
            "source_paths": sorted(source_paths | {AUTHORITY, RECIPE, BUNDLE_RECIPE}),
            "target_compiler_required": False,
            "maximum_stage_imports": max(len(s.bindings) for s in self.stages),
            "total_nodes": sum(len(s.p.nodes) for s in self.stages),
        }
        (directory / "build-plan.json").write_text(json.dumps(result, indent=2) + "\n")
        return result


class Stage:
    def __init__(self, build, index, name):
        self.build = build
        self.index = index
        self.name = name
        self.p = Plan()
        self.bindings = []
        self.bound = {}
        self.flats = {}
        self.tools = {}
        self.publications = []
        self.publication_start = len(build.publications)
        self.bind("fast", 0, 5)
        self.bind("cold", 0, 6)

    def bind(self, alias, kind, index=0, source=None):
        key = (kind, source if kind == 1 else index)
        if key in self.bound:
            return self.bound[key]
        encoded = alias.encode("ascii")
        if not encoded or len(encoded) > 95:
            raise ValueError("stage import alias")
        if any(x["alias"] == alias for x in self.bindings):
            raise ValueError("duplicate stage alias")
        row = {"alias": alias, "kind": kind, "index": index}
        if source is not None:
            row["source"] = source
        self.bindings.append(row)
        h = self.p.imported(alias)
        self.bound[key] = h
        return h

    def boot(self, index):
        return self.bind("bootstrap-" + str(index), 0, index)

    def source(self, path):
        for b in self.bindings:
            if b["kind"] == 1 and b["source"] == path:
                return self.bound[(1, path)]
        return self.bind("source-" + str(len(self.bindings)), 1, source=path)

    def prior(self, name):
        i = self.build.by_publication[name]
        if i >= self.publication_start:
            raise ValueError("a stage import must precede its publications")
        return self.bind(name, 2, i)

    def semantic_roots(self):
        if self.index == 0:
            self.A, self.R, self.G = self.boot(0), self.boot(1), self.boot(3)
            self.seeds = {"v1": self.boot(2)}
        else:
            self.A, self.R, self.G = (
                self.prior(BOOTSTRAP[0]), self.prior(BOOTSTRAP[1]),
                self.prior(BOOTSTRAP[3]),
            )
            self.seeds = {"v1": self.prior(BOOTSTRAP[2])}
        return self

    def seed(self, profile):
        if profile not in self.seeds:
            self.seeds[profile] = self.prior("tmp-seed-" + profile)
        return self.seeds[profile]

    def profile(self, role):
        path = self.build.root / (BOOT + role + ".hepta")
        text = path.read_text()
        div = "int.div" in text or "int.rem" in text
        bulk = "buffer.move_within" in text
        word = "buffer.store.u64.le" in text or "buffer.store.u64.be" in text
        endian = "buffer.load.u64.be" in text
        if endian:
            if div or bulk:
                raise ValueError((role, "no combined endian/div/bulk constructor declared"))
            return "cold-endian"
        if word:
            if div or bulk:
                raise ValueError((role, "no combined word/div/bulk constructor declared"))
            return "word"
        return "div-bulk" if div and bulk else "div" if div else "cold-bulk" if bulk else "v1"

    def core(self, role):
        source = self.source(BOOT + role + ".hepta")
        return call(self.p, self.A, source, argv=("hia-seed-assembly", "--agent-compact"),
                    label=role + ":actual-source-to-Core")

    def projected(self, core, entry="f0"):
        left = self.p.literal(b"[")
        right = self.p.literal(b"," + json.dumps(entry).encode("ascii") + b",1]")
        wire = self.p.concat(left, core, right)
        result = call(self.p, self.R, wire, label=entry + ":actual-Core-to-reference-wire")
        self.p.drop(left, right, wire)
        return result

    def flat(self, role, profile=None):
        if role in self.flats:
            return self.flats[role]
        profile = self.profile(role) if profile is None else profile
        core = self.core(role)
        projected = self.projected(core)
        flat = call(self.p, self.seed(profile), projected,
                    label=role + ":independent-" + profile + "-machine-emission")
        self.p.drop(core, projected)
        self.flats[role] = flat
        return flat

    def framed(self, image, magic, pieces, label, extra=()):
        prefix = self.p.literal(magic)
        lengths = [self.p.length(h) for h in pieces]
        wire = self.p.concat(prefix, *lengths, *extra, *pieces, label=label + ":actual-lengths")
        result = call(self.p, image, wire, label=label)
        self.p.drop(prefix, *lengths, wire)
        return result

    def wrap(self, flat, label):
        return self.framed(self.G, b"HIAFLT01", [flat], label)

    def tool(self, role, profile=None):
        if role not in self.tools:
            self.tools[role] = self.wrap(self.flat(role, profile), role + ":native-filter-pack")
        return self.tools[role]

    def packed(self, role, packer, magic, companions=(), profile=None):
        body = self.flat(role, profile)
        parts = [body, *companions]
        return self.framed(self.tool(packer), magic, parts, role + ":native-product-pack")

    def publish(self, handle, name, path=None, executable=True, maximum=64 << 20):
        if name in self.build.by_publication or len(name.encode("ascii")) > 63:
            raise ValueError("publication name must be globally unique and bounded")
        if path is not None and (len(path.encode("ascii")) > 191 or path.startswith("/")
                                or any(x in ("", ".", "..") for x in path.split("/"))):
            raise ValueError("publication relative install path")
        row = {"name": name, "path": "" if path is None else path,
               "mode": 0o500 if executable else 0o400,
               "flags": 0 if path is None else 1, "max_bytes": maximum}
        if path and any(x["path"] == path for x in self.build.publications):
            raise ValueError("duplicate installed target")
        self.p.publish(handle, name)
        self.build.by_publication[name] = len(self.build.publications)
        self.build.publications.append(row)
        self.publications.append(row)

    def publish_root(self, handle, index, name, executable=True):
        target = root_path(index, name)
        pub = TOP_ROOTS.get(index, artifact(index, name))
        self.publish(handle, pub, target, executable=executable)

    def generic_root(self, index, name, role):
        if role in ("cold_export_linker", "elf_shared_linker"):
            image = self.framed(self.tool("direct_shared_linker_filter_packer"),
                                 b"HIADSL01", [self.flat(role)],
                                 role + ":qualified-64MiB-linker-transport")
            self.tools[role] = image
        else:
            image = self.tool(role)
        self.publish_root(image, index, name)
        return image


def stage_semantic(build):
    s = build.stage("semantic-roots").semantic_roots()
    p = s.p
    generic = s.wrap(s.flat("native_filter_packer", "v1"), "self-rebuild-generic-filter")
    p.compare(generic, s.G, label="bootstrap-generic-filter-entire-image-equality")
    s.G = generic
    seedpack = s.tool("seed_backend_filter_packer", "v1")
    for profile, source in PROFILE_SOURCE.items():
        body = s.flat(source, "v1")
        image = s.framed(seedpack, b"HIAFLT01", [body], "rebuild-seed-" + profile)
        if profile == "v1":
            p.compare(image, s.boot(2), label="bootstrap-v1-entire-image-equality")
            s.seeds["v1"] = image
            s.publish(image, BOOTSTRAP[2], BOOTSTRAP[2])
        elif profile == "owned":
            s.seeds[profile] = image
            s.publish_root(image, 43, "general_backend")
            s.publish(image, "tmp-seed-owned")
        else:
            s.seeds[profile] = image
            s.publish(image, "tmp-seed-" + profile)
    s.publish(generic, BOOTSTRAP[3], BOOTSTRAP[3])
    front = [s.flat(role, "word" if role.startswith("seed_front_bulk/") else "v1") for role in FRONT]
    offset_words = []
    for i in range(6):
        prefix = p.concat(*front[3:3+i]) if i else p.literal(b"")
        n = p.length(prefix)
        offset_words.append(p.number(n, 48, maximum=64 << 20))
        p.drop(prefix, n)
    inner = p.concat(*offset_words, *front[3:])
    sections = [*front[:3], inner]
    assembler = s.framed(s.tool("seed_backend_assembly_packer", "v1"),
                         b"HIASBA01", sections, "self-rebuild-assembly")
    p.compare(assembler, s.boot(0), label="bootstrap-assembly-entire-image-equality")
    s.publish(assembler, BOOTSTRAP[0], BOOTSTRAP[0])
    projector = s.framed(s.tool("evaluate_reference_wire_filter_packer", "v1"),
                         b"HIAEPF01", [s.flat("seed_front_bulk/evaluate_reference_wire", "word")],
                         "self-rebuild-projector")
    p.compare(projector, s.boot(1), label="bootstrap-projector-entire-image-equality")
    s.publish(projector, BOOTSTRAP[1], BOOTSTRAP[1])
    p.drop(*offset_words, inner)


def cold_sha(s):
    fallback = s.flat("cold_sha256_stream", "word")
    fast = s.flat("cold_sha256_nonalias", "cold-endian")
    image = s.framed(s.tool("cold_sha256_alias_packer", "word"),
                    b"HIASHA01", [fallback, fast],
                    "cold-SHA-exact-alias-dispatch-and-independent-policies")
    return image


def stage_orchestration(build, entry=True):
    s = build.stage("orchestration").semantic_roots()
    p = s.p
    sha = cold_sha(s)
    s.publish(sha, "tmp-cold-sha256-flat", executable=False)
    items = (
        ("cold_qualification_driver", "cold_qualification_driver_packer", b"HIAQDP01", 0, "driver"),
        ("subprocess", "subprocess_packer", b"HIASUPK1", 2, "fast"),
        ("cold_replay_owner", "cold_replay_owner_packer", b"HIACOP01", 3, "cold"),
        ("cold_master_archive", "cold_master_archive_packer", b"HIAQAP01", 1, "archive"),
    )
    for role, packer, magic, index, name in items:
        image = s.packed(role, packer, magic, () if index in (2,3) else (sha,))
        if index in (0,2,3):
            boot_index = {0:4, 2:5, 3:6}[index]
            p.compare(image, s.boot(boot_index), label="bootstrap-" + name + "-entire-image-equality")
        s.publish_root(image, index, name)
    master = s.packed("cold_master", "cold_master_packer", b"HIAQMP01", (sha,))
    s.publish(master, "hia-cold-master", "hia-cold-master")
    exporter = s.packed("cold_source_export", "cold_qualification_driver_packer", b"HIAQDP01", (sha,))
    s.publish(exporter, "hia-cold-source-export", "hia-cold-source-export")
    transport = s.tool("cold_descriptor_filter_packer")
    for role, pub in (("cold_plan_inventory","tmp-plan-inventory"),
                      ("cold_descriptor_compose","tmp-descriptor-compose"),
                      ("cold_cli_bind","tmp-cli-bind")):
        image = s.framed(transport, b"HIAQPF01", [s.flat(role)], role + ":bounded-transport")
        s.publish(image, pub)
    s.publish(s.flat("cold_cli"), "tmp-cold-cli-policy", executable=False)
    s.publish(s.tool("cold_cli_packer"), "tmp-cold-cli-packer")
    s.publish(s.tool("source_contract_generate"), "hia-source-contract", "hia-source-contract")
    s.publish(s.tool("source_contract_manifest", "v1"),
              "hia-source-contract-manifest", "hia-source-contract-manifest")
    refusal = s.flat("cold_build_refusal", "v1")
    gate = s.packed("source_release_cold_admit", "source_build_packer", b"HIASBL01",
                    (refusal, refusal))
    s.publish(gate, "hia-cold-report-admit", "hia-cold-report-admit")
    if entry:
        s.publish(s.flat("cold_build_entry"), "tmp-build-entry-policy", executable=False)
        s.publish(s.tool("cold_build_entry_packer"), "tmp-build-entry-packer")
        s.publish(s.flat("cold_source_bootstrap_entry", "cold-bulk"),
                  "tmp-source-bootstrap-entry-policy", executable=False)
        s.publish(s.tool("cold_source_bootstrap_entry_packer", "v1"),
                  "tmp-source-bootstrap-entry-packer")


def stage_tools(build):
    s = build.stage("native-tools").semantic_roots()
    p = s.p
    for index, name, role in GENERIC_ROOTS:
        s.generic_root(index, name, role)
    fault = s.packed("cold_cli_fault", "cold_replay_owner_packer", b"HIACOP01")
    s.publish_root(fault, 51, "fault")
    packet_packer = s.tool("cold_export_reference_filter_packer")
    for index, name, role in (
        (6, "reference_packet", "cold_export_reference_prepare"),
        (32, "reference_packet_30m", "cold_export_reference_prepare_30m"),
    ):
        image = s.framed(packet_packer, b"HIAVMP01", [s.flat(role)], name + ":pack")
        s.publish_root(image, index, name)
    empty = p.literal(b"")
    observer = call(p, s.tool("native_observer_packer"), empty, label="flat-observer-fixed-native-image")
    s.publish_root(observer, 9, "observer")
    object_packer = s.tool("linked_observer_packer")
    s.publish_root(object_packer, 31, "linked_packer_root")
    native_linker = s.tool("cold_observer_linker")
    for index, name, role, packer in (
        (11, "linked_observer", "linked_observer_policy", "linked_observer_packer"),
        (49, "allocator_observer", "cold_allocator_observer", "cold_allocator_observer_packer"),
        (52, "export_observer", "cold_export_observer", "cold_export_packer"),
    ):
        obj = call(p, s.tool(packer), s.flat(role), label=role + ":actual-ET_REL")
        image = call(p, native_linker, obj, label=role + ":native-ELF-link")
        p.drop(obj)
        s.publish_root(image, index, name)
    s.publish_root(s.flat("cold_allocator_witness"), 46, "allocator_policy", executable=False)
    p.drop(empty)


def stage_vms(build):
    s = build.stage("complete-vms").semantic_roots()
    p = s.p
    vm_backend = s.seed("vm")
    linker = s.tool("cold_reference_kernel_linker", "v1")
    packer = s.tool("owned_reference_cli_packer", "v1")
    for index, name, role in (
        (7, "vm", "owned_reference"),
        (33, "vm_30m", "cold_export_reference_vm"),
    ):
        core = s.core(role)
        flats = []
        for entry, mode in (("f0", 3), ("f3", 7)):
            projected = s.projected(core, entry)
            p.word(projected, 0, int.from_bytes(b"HIAERW02", "little"))
            p.word(projected, 56, 0)
            head = p.literal(b"HIAVMR01")
            fields = p.slice(projected, 8, 48)
            arity = p.literal(q(mode))
            body = p.slice(projected, 64)
            wire = p.concat(head, fields, arity, body)
            obj = call(p, vm_backend, wire, label=role + "-" + entry + ":independent-machine-object")
            link_head = p.literal(b"HIAVLK01" + q(mode))
            obj_n = p.length(obj)
            link_request = p.concat(link_head, obj_n, obj)
            linked = call(p, linker, link_request, label=role + "-" + entry + ":closed-native-link")
            flats.append(linked)
            p.drop(projected, head, fields, arity, body, wire, obj, link_head, obj_n, link_request)
        joined = p.concat(*flats)
        prefix = p.literal(b"HIAOPK01")
        size = p.length(joined)
        run_offset = p.length(flats[0])
        wire = p.concat(prefix, size, run_offset, joined)
        image = call(p, packer, wire, label=role + ":complete-native-VM-pack")
        s.publish_root(image, index, name)
        p.drop(core, *flats, joined, prefix, size, run_offset, wire)


def stage_inventories(build, sources):
    for group in range(2):
        s = build.stage("inventories-" + str(group))
        p = s.p
        inventory = s.prior("tmp-plan-inventory")
        records = []
        for path in sources[group * 30:group * 30 + 30]:
            plan = s.source(path)
            record = call(p, inventory, plan, label=path + ":actual-native-plan-inventory")
            records.extend((p.length(record), record))
        header = p.literal(b"HIAQPB01" + q(30))
        bundle = p.concat(header, *records)
        s.publish(bundle, "tmp-plan-inventory-" + str(group), executable=False)
        p.drop(header, *records, bundle)


def stage_binding(build, entry=True):
    s = build.stage("descriptor-and-entries")
    p = s.p
    first = s.prior("tmp-plan-inventory-0")
    last = s.prior("tmp-plan-inventory-1")
    header = p.literal(b"HIAQPB01" + q(60))
    tails = [p.slice(x, 16) for x in (first,last)]
    plans = p.concat(header, *tails)
    source_map = s.bind("captured-source-manifest", 3)
    tool_map = s.bind("installed-tool-manifest", 4)
    inventory = call(p, s.prior("hia-source-contract-manifest"), source_map,
                     label="actual-source-manifest-to-contract-inventory")
    metadata = s.source("docs/HIA_NATIVE_SELFHOST_METADATA.json")
    zero_contract = p.literal(bytes(8))
    contract = s.framed(s.prior("hia-source-contract"), b"HIASCG01",
                        [metadata, inventory], "native-frozen-source-contract",
                        extra=(zero_contract,))
    frozen_contract = s.source("docs/HIA_SELFHOST_CORE_SUPPORT.json")
    p.compare(contract, frozen_contract,
              label="frozen-source-contract-must-match-actual-captured-source")
    p.drop(inventory, zero_contract, contract)
    recipe = s.source(BUNDLE_RECIPE)
    inputs = [recipe, source_map, tool_map, plans]
    magic = p.literal(b"HIAQCA01")
    lengths = [p.length(x) for x in inputs]
    zero = p.literal(bytes(24))
    wire = p.concat(magic, *lengths, zero, *inputs)
    descriptor = call(p, s.prior("tmp-descriptor-compose"), wire, label="actual-source-tool-plan-descriptor")
    s.publish(descriptor, "cold-bundle.hiadat", "cold-bundle.hiadat", executable=False)
    p.drop(header, *tails, plans, magic, *lengths, zero, wire)
    master = s.prior("hia-cold-master")
    owner = s.prior(BOOTSTRAP[6])
    exporter = s.prior("hia-cold-source-export")
    policy = s.prior("tmp-cold-cli-policy")
    sha = s.prior("tmp-cold-sha256-flat")
    parts = [descriptor, master, owner, exporter, policy, sha]
    prefix = p.literal(b"HIAQBC01")
    lengths = [p.length(x) for x in parts]
    zero = p.literal(bytes(8))
    binding = p.concat(prefix, *lengths, zero, *parts)
    packet = call(p, s.prior("tmp-cli-bind"), binding, label="actual-four-pin-CLI-binding")
    cli = call(p, s.prior("tmp-cold-cli-packer"), packet, label="public-native-cold-CLI-pack")
    s.publish(cli, "hia-cold", "hia-cold")
    p.drop(prefix, *lengths, zero, binding, packet, cli)
    if entry:
        authority = s.source(AUTHORITY)
        build_recipe = s.source(RECIPE)
        pin_inputs = [authority, build_recipe, *[s.boot(i) for i in range(7)]]
        pins = [p.sha256(x) for x in pin_inputs]
        build_policy = s.prior("tmp-build-entry-policy")
        prefix = p.literal(b"HIAQBE01")
        lengths = [p.length(x) for x in (build_policy,sha)]
        packet = p.concat(prefix, *lengths, *pins, build_policy, sha)
        image = call(p, s.prior("tmp-build-entry-packer"), packet, label="actual-nine-pin-build-entry-pack")
        running = s.bind("captured-build-entry", 5)
        p.compare(image, running, label="public-build-entry-source-rebuild-entire-image")
        s.publish(image, "hia-cold-build", "hia-cold-build")
        p.drop(prefix, *lengths, *pins, packet, image)
        post_recipe = s.source(POST_RECIPE)
        post_pin_inputs = [authority, post_recipe, *[s.boot(i) for i in range(7)]]
        pins = [p.sha256(x) for x in post_pin_inputs]
        post_policy = s.prior("tmp-source-bootstrap-entry-policy")
        prefix = p.literal(b"HIASBP01")
        lengths = [p.length(x) for x in (post_policy,sha)]
        packet = p.concat(prefix, *lengths, *pins, post_policy, sha)
        image = call(p, s.prior("tmp-source-bootstrap-entry-packer"), packet,
                     label="actual-nine-pin-source-bootstrap-entry-pack")
        s.publish(image, "hia-source-bootstrap", "hia-source-bootstrap")
        p.drop(prefix, *lengths, *pins, packet, image)


def encode_metadata(root, result, sources, recipe_path=RECIPE):
    paths = sorted(set(sources) | set(result["source_paths"]))
    if not 1 <= len(paths) <= 4096:
        raise ValueError("source authority count")
    for path in paths:
        b = path.encode("ascii")
        if not 1 <= len(b) <= 4095 or path.startswith("/") or any(x in ("", ".", "..") for x in path.split("/")):
            raise ValueError(("source authority path",path))
        if path not in (AUTHORITY, RECIPE, POST_RECIPE) and not (root / path).is_file():
            raise ValueError(("authority input is absent",path))
    authority = bytearray(b"HIATBS01" + q(1, len(paths), 0))
    for path in paths:
        b = path.encode("ascii")
        authority += q(len(b)) + b + bytes((-len(b)) % 8)
    indices = {path: i for i,path in enumerate(paths)}
    bindings = []
    stages = []
    for stage in result["stages"]:
        start = len(bindings)
        for row in stage["bindings"]:
            index = indices[row["source"]] if row["kind"] == 1 else row["index"]
            alias = row["alias"].encode("ascii")
            bindings.append(q(len(alias),row["kind"],index,0)+alias.ljust(96,b"\0"))
        stages.append(q(stage["id"],indices[stage["plan"]],start,len(stage["bindings"]),
                        stage["publication_start"],stage["publication_count"],0,0))
    publications = []
    for row in result["publications"]:
        name, path = row["name"].encode("ascii"),row["path"].encode("ascii")
        publications.append(q(len(name),len(path),row["mode"],row["flags"],row["max_bytes"],0,0,0)+
                            name.ljust(64,b"\0")+path.ljust(192,b"\0"))
    stage_off = 128
    bind_off = stage_off + 64 * len(stages)
    pub_off = bind_off + 128 * len(bindings)
    size = pub_off + 320 * len(publications)
    header = b"HIATBR01"+q(1,len(stages),len(bindings),len(publications),len(paths),
                           stage_off,bind_off,pub_off,size)+bytes(48)
    if len(header) != 128:
        raise AssertionError("build recipe header")
    recipe = header+b"".join(stages+bindings+publications)
    if len(recipe) != size:
        raise AssertionError("build recipe extent")
    (root / AUTHORITY).write_bytes(authority)
    (root / recipe_path).write_bytes(recipe)
    return {"sources":len(paths),"authority_bytes":len(authority),
            "authority_sha256":sha256(authority).hexdigest(),
            "recipe_bytes":len(recipe),"recipe_sha256":sha256(recipe).hexdigest()}


def generate(root=ROOT, entry=True):
    root = Path(root)
    recipe = normalize_bundle_recipe(root / BUNDLE_RECIPE)
    build = Build(root)
    stage_semantic(build)
    stage_orchestration(build, entry=entry)
    stage_tools(build)
    stage_vms(build)
    stage_inventories(build, phase_sources(recipe))
    stage_binding(build, entry=entry)
    if len(build.stages) != 7:
        raise AssertionError("seven construction stages")
    return build.finish(root / PLANS)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source",type=Path,default=ROOT)
    ap.add_argument("--without-entry",action="store_true",
                    help="development component plans only; never a public build closure")
    ap.add_argument("--authority",type=Path,
                    help="final reviewed JSON path list; all listed files must actually exist")
    args = ap.parse_args()
    result = generate(args.source,entry=not args.without_entry)
    if args.authority:
        data = json.loads(args.authority.read_text())
        paths = data if isinstance(data,list) else data["paths"]
        result["metadata"] = encode_metadata(args.source,result,paths)
    print(json.dumps({key:result[key] for key in ("maximum_stage_imports","total_nodes")}))
    print(json.dumps([{"stage":x["name"],"imports":len(x["bindings"]),
                       "nodes":x["nodes"],"publications":x["publication_count"],
                       "bytes":x["plan_bytes"]} for x in result["stages"]]))

if __name__ == "__main__":
    main()
