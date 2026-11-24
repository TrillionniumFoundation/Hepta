"""Author the checked native Core release DAG from the retained declarations.

This tool writes data at development time. Release execution uses the HIA owner,
native compiler, codec, checked static adapters and native linkers exclusively.
"""
from pathlib import Path
import json
import struct

from tools import build_hia_core_edit as core
from tools import build_hia_core_edit_link as linked
from tools import build_hia_core_static as static
from tools.generate_hia_release_stage_recipes import Recipe, ROOT, PROGRAMS, outputs


class CoreRecipe(Recipe):
    def __init__(self):
        super().__init__()
        self.constants = {}
        self.lengths = {}
        self.source_views = {}
        self.compiled = {}
        self.digests = {}
        self.codec_executables = {}
        self.static_rows = {}
        self.products = {}
        self.empty = self.literal(b'')

    def literal(self, raw):
        raw = bytes(raw)
        if raw not in self.constants:
            self.constants[raw] = super().literal(raw)
        return self.constants[raw]

    def q(self, *values):
        return self.literal(struct.pack('<' + 'Q' * len(values), *values))

    def concat(self, *parts):
        if not parts:
            return self.literal(b'')
        if len(parts) == 1:
            return parts[0]
        while len(parts) > 128:
            parts = tuple(self.node(16, parts[i:i + 128]) for i in range(0, len(parts), 128))
        return self.node(16, parts)

    def length(self, view):
        if view not in self.lengths:
            self.lengths[view] = self.node(17, (view,))
        return self.lengths[view]

    def digest(self, view):
        if view not in self.digests:
            self.digests[view] = self.node(13, (view,))
        return self.digests[view]

    def source(self, path):
        if path not in self.source_views:
            self.source_views[path] = super().source(path)
        return self.source_views[path]

    def compile_paths(self, paths):
        pending = sorted(set(paths) - self.compiled.keys())
        for at in range(0, len(pending), 12):
            chunk = pending[at:at + 12]
            named = {f'unit-{i}.hepta': path for i, path in enumerate(chunk)}
            sources, images = self.compile(named)
            for alias, path in named.items():
                original = self.source_views.get(path)
                if original is not None:
                    self.node(8, (original, sources[alias]))
                self.source_views[path] = sources[alias]
                self.compiled[path] = images[alias]

    def policy(self, policy, leaf):
        return self.kit(policy, leaf)[0]

    def codec(self, mode, capacity):
        key = mode, capacity
        if key not in self.codec_executables:
            path = (core.RELEASE_DEFLATE, core.ARGUMENT_PAYLOAD, core.PACKER)[mode - 1]
            source, image = self.source_views[path], self.compiled[path]
            wire = self.concat(self.literal(struct.pack('<8s2Q', b'HIACCO01', mode, capacity)),
                               self.length(source), self.length(image), source, image)
            self.codec_executables[key] = self.run(self.codec_builder, wire)
        return self.codec_executables[key]

    def compress(self, raw, capacity=1 << 20):
        return self.node(18, (0, raw, self.codec(1, capacity), self.codec_builder,
                             self.source_views[core.ARGUMENT_PAYLOAD],
                             self.compiled[core.ARGUMENT_PAYLOAD], capacity))

    def archive(self, raw):
        bundle = self.node(18, (1, raw, self.codec(1, 1 << 20), self.codec_builder,
                               self.source_views[core.ARGUMENT_PAYLOAD],
                               self.compiled[core.ARGUMENT_PAYLOAD], 1 << 20))
        return self.pick(bundle, 0), self.pick(bundle, 1)

    def product(self, kind, paths, suffix, sections, *, source_overrides=None, image_overrides=None):
        ordinal = static.ROLE_ORDER.index(kind) + 1
        adapter_path = f'tools/hia_core_edit_{kind}.S'
        adapter = self.source(adapter_path)
        packer = self.policy(static.POLICY, core.PACKER)
        if kind == 'emit_object':
            relay = self.source(core.REGISTER_RELAY)
            frame = self.concat(self.literal(struct.pack('<8sQ', b'HIACINC1', ordinal)),
                                self.length(adapter), self.length(relay), adapter, relay)
            adapter = self.run(packer, frame)
        if kind not in self.static_rows:
            group, _ = core.STATIC_ADAPTER_ROLES[adapter_path]
            self.static_rows[kind] = self.run(self.policy(static.POLICY, group),
                                             self.literal(struct.pack('<8sQ', b'HIACST01', ordinal)))
        row = self.static_rows[kind]
        sources = {**self.source_views, **(source_overrides or {})}
        images = {**self.compiled, **(image_overrides or {})}
        pairs = [(sources[path], images[path]) for path in paths]
        header = self.concat(self.literal(struct.pack('<8sQ', b'HIACSA01', ordinal)),
                             self.length(adapter), self.length(row),
                             *(self.concat(self.length(source), self.length(image)) for source, image in pairs))
        wire = self.concat(header, adapter, row, *(piece for pair in pairs for piece in pair), suffix)
        binary = self.run(packer, wire)
        if kind in ('selfhost_component', 'emit_object', 'packed_exec'):
            binary = self.run(self.codec(3, core.CAPACITY), binary, operation=0)
        targets = tuple(target for _, target in core.STATIC_RELOCATIONS[adapter_path])
        self.node(10, (7, len(targets), binary, adapter, row, self.q(*targets), *sections))
        return binary

    def packed(self, executable, prover=None):
        members = (executable,) if prover is None else (executable, prover)
        encoded = [self.q(len(members))]
        sections = [self.compiled[core.ARGUMENT_PAYLOAD]]
        for raw in members:
            body, archive = self.archive(raw)
            encoded.append(body)
            sections.append(archive)
        binary = self.product('packed_exec', (core.ARGUMENT_PAYLOAD,), self.concat(*encoded), sections)
        self.node(10, (8, len(members), binary))
        return binary

    def static_products(self, kinds, *, source_overrides=None):
        paths = {path for kind in kinds for path in static.source_paths(kind, core.PROGRAMS[kind][1])}
        overrides = source_overrides or {}
        self.compile_paths(paths - overrides.keys())
        images = dict(self.compiled)
        for path, source in overrides.items():
            images[path] = self.run(self.import_product('hia-source-build'), source, operation=4)
        products = {}
        for kind in kinds:
            name, roles = core.PROGRAMS[kind]
            inputs = static.source_paths(kind, roles)
            sections = [images[path] for path in inputs]
            suffix = self.empty
            if kind == 'dispatch':
                control, formatter = sections[4:]
                raw = self.concat(control, formatter)
                suffix = self.compress(raw, (1 << 20) - 24)
                arguments = self.concat(self.length(suffix), self.length(raw), self.length(control), suffix)
                sections = [self.node(19, sections[:2]), *sections[2:4], arguments]
            elif kind == 'import_assembly':
                sections = [*sections[:3], self.node(19, sections[3:])]
            elif kind == 'selfhost_component':
                sections = [*sections[:2], self.node(19, sections[2:5]), sections[5]]
            binary = self.product(kind, inputs, suffix, sections,
                                  source_overrides=overrides, image_overrides=images)
            if kind == 'selfhost_component':
                binary = self.packed(binary)
            products[name] = binary
        return products

    def linked_implementations(self, prover):
        kinds = [kind for kind in core.NOMINAL_CLI_IMAGES if kind != 'build_object'] + ['build_object']
        payloads_by_kind = {kind: core.nominal_cli_payloads(kind) for kind in kinds}
        paths = set().union(*(payloads_by_kind[kind] for kind in kinds))
        self.compile_paths(paths)
        templates, objects = {}, {}
        for path, (template, role) in core.NOMINAL_ADAPTER_ROLES.items():
            source = self.source(path)
            templates.setdefault(template, self.policy(linked.POLICY, template))
            if role == 0:
                relay = self.source(core.REGISTER_RELAY)
                wire = self.concat(self.literal(struct.pack('<8sQ', b'HIACERL1', role)),
                                   self.length(source), self.length(relay), source, relay)
            else:
                wire = self.concat(self.literal(struct.pack('<8sQ', b'HIACEAD1', role)),
                                   self.length(source), source)
            objects[path] = self.run(templates[template], wire)
        result = {}
        for kind in kinds:
            path = f'tools/hia_core_edit_{kind}.S'
            template, role = core.NOMINAL_ADAPTER_ROLES[path]
            adapters = [path, core.NOMINAL_ADAPTER]
            if kind in core.EDIT_ENVELOPE_ROLES:
                adapters.append(core.EDIT_ENVELOPE)
            if kind in ('apply', 'publish_edit'):
                adapters.append(core.EDIT_RESPONSE)
            if kind in ('batch_apply', 'publish_batch'):
                adapters.append(core.BATCH_CAPTURE)
            payloads = payloads_by_kind[kind]
            parts = [*(objects[path] for path in adapters), *(self.source_views[path] for path in payloads)]
            if kind == 'build_object':
                parts.append(prover)
            wire = self.concat(self.literal(struct.pack('<8s2Q', b'HIACELK1', role, len(parts))),
                               *(self.length(part) for part in parts), *parts)
            wire = self.run(templates[template], wire)
            packed = {}
            if kind == 'build_object':
                for source in core.PACKED_BUILD_IMAGES:
                    raw = self.compiled[source]
                    compressed = self.compress(raw)
                    packed[source] = self.concat(self.length(raw), self.length(compressed),
                                                 self.digest(raw), compressed)
                owner = self.policy(linked.PACKED_POLICY, core.PACKER)
                frame = self.concat(self.literal(b'HIACPA01'), self.length(wire), wire, *packed.values())
                wire = self.run(owner, frame)
            executable = self.run(self.import_product('hia-elf-link'), wire, operation=0)
            for source in payloads:
                self.check_image(executable, packed.get(source, self.compiled[source]))
            if kind == 'build_object':
                for label in ('build_shared_linker', 'build_verified_linker'):
                    path = next(path for path, value in payloads.items() if value == label)
                    self.check_image(executable, self.digest(self.compiled[path]))
                self.check_image(executable, self.concat(self.length(prover), self.digest(prover)))
            self.node(10, (9, 0, executable))
            result[kind] = executable
        return result

    def bound_source(self, owner, mode, template, products):
        entries = [(name.encode('ascii'), raw) for name, raw in sorted(products.items())]
        lengths = [self.concat(self.q(len(name)), self.length(raw)) for name, raw in entries]
        body = [part for name, raw in entries for part in (self.literal(name), raw)]
        wire = self.concat(self.literal(struct.pack('<8sQ', b'HIACPIN1', mode)),
                           self.length(template), *lengths, template, *body)
        return self.run(owner, wire)

    def build(self):
        self.compile_paths((core.RELEASE_DEFLATE, core.ARGUMENT_PAYLOAD, core.PACKER))
        self.codec_builder = self.policy('source_core_codec.hepta', 'core_edit/source_codec_packer.hepta')
        prover = self.import_product('hia-safe-core-prove')
        self.products = self.static_products(static.KINDS)
        for kind, implementation in self.linked_implementations(prover).items():
            name = core.PROGRAMS[kind][0]
            self.products[name] = self.packed(implementation, prover if kind == 'build_object' else None)
            if kind == 'build_object':
                self.products['hia-worker-scalar-implementation'] = implementation
        constructor = self.import_product('hia-nominal-constructor')
        roles = {name: self.products[name] for name in core.DISPATCH_ROLES if name != 'hia-nominal-constructor'}
        roles['hia-nominal-constructor'] = constructor
        pin_owner = self.policy('source_core_pin.hepta', 'source_build_packer.hepta')
        overrides = {
            core.DISPATCH: self.bound_source(pin_owner, 1, self.source(core.DISPATCH), roles),
            core.SELFHOST_ENTRY: self.bound_source(pin_owner, 2, self.source(core.SELFHOST_ENTRY), {
                'hia-selfhost-component': self.products['hia-selfhost-component']}),
        }
        self.products.update(self.static_products(('dispatch',), source_overrides=overrides))
        expected = outputs(3)
        if set(self.products) != set(expected):
            raise ValueError(('Core outputs differ from declared stage', sorted(self.products), expected))
        for name in expected:
            self.publish(name, self.products[name])
        return self


def main():
    recipe = CoreRecipe().build()
    path = ROOT / PROGRAMS / 'release_stage_core.hiastd'
    raw = recipe.binary()
    path.write_bytes(raw)
    print(json.dumps({'path': str(path), 'nodes': len(recipe.nodes),
                      'handles': recipe.next_handle - 1, 'bytes': len(raw),
                      'publications': recipe.published}, sort_keys=True))


if __name__ == '__main__':
    main()
