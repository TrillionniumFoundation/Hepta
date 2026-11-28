"""Native stage 20: independently bound Worker 01 and 02 installer products.

The existing source filter, member packers and entry binder construct each ELF.
A separate double compilation and the complete native member frame are compared
before publication. The normal Worker 03 frontend and all runtime limits remain
owned by their existing authors.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from tools.generate_hia_native_controller_release import ControllerRecipe
from tools.generate_hia_release_stage_recipes import PROGRAMS, U64_MAX
from tools.hia_worker_protocols import protocol, recipe_path
from tools.generate_hia_worker_install_owner import STAGES

ROOT = Path(__file__).resolve().parents[1]
RECIPE = PROGRAMS + 'release_stage_worker_compat.hiastd'
PROTOCOLS = ('01', '02')
OUTPUTS = (
    'hia-worker-install-owner-v1', 'hia-worker-install-v1',
    'hia-worker-install-owner-v2', 'hia-worker-install-v2',
    'worker-compat-publication.bin',
)
IMPORTS = ('selfhost.image.bin', 'hia-source-build', 'hia-subprocess', 'hia-source-capture')
ADAPTERS = ('tools/hia_worker_install_owner_syscalls.S',
            'tools/hia_worker_install_entry_syscalls.S')
SHARED = tuple(PROGRAMS + name for name in (
    'source_filter_member.hepta', 'source_build_packer.hepta',
    'source_release_kit.hepta', 'selfhost.hepta', 'sha256_stream.hepta'))


def protocol_sources(number):
    selected = protocol(number)
    members = tuple(PROGRAMS + selected.install_stem + '_' + suffix + '.hepta'
                    for suffix in ('owner', 'dag', 'owner_packer', 'entry',
                                   'entry_packer', 'entry_bind'))
    recipes = tuple(recipe_path(number, kind) for kind in STAGES)
    if len(members) != 6 or len(recipes) != 16:
        raise ValueError('Worker compatibility source domain changed')
    return (*members, selected.manifest_source, selected.manifest_table, *recipes)


SOURCES = tuple(sorted(set((*SHARED, *ADAPTERS,
                           *(name for number in PROTOCOLS for name in protocol_sources(number))))))
COMPILED = tuple(name for name in SOURCES if name.endswith('.hepta')
                 and name not in {protocol(n).manifest_source for n in PROTOCOLS})


def template(root, path, labels):
    """Development authoring only; production executes the resulting HIA DAG."""
    source = root / path
    before = source.read_bytes()
    with tempfile.TemporaryDirectory(prefix='hia-worker-compat-template-') as temporary:
        directory = Path(temporary)
        captured = directory / 'captured.S'
        captured.write_bytes(before)
        obj, raw = directory / 'adapter.o', directory / 'adapter.bin'
        subprocess.run(['as', '--64', str(captured), '-o', str(obj)],
                       check=True, capture_output=True, timeout=30)
        subprocess.run(['objcopy', '-O', 'binary', '-j', '.text', str(obj), str(raw)],
                       check=True, capture_output=True, timeout=30)
        symbols = {name: int(address, 16) for address, _, name in
                   (line.split() for line in subprocess.check_output(
                       ['nm', '-n', str(obj)], text=True, timeout=30).splitlines())}
        if symbols.get('_start') != 0 or 'R_X86_64' in subprocess.check_output(
                ['objdump', '-r', str(obj)], text=True, timeout=30):
            raise ValueError('Worker compatibility adapter has unresolved relocations')
        code = raw.read_bytes()
    if source.read_bytes() != before:
        raise ValueError('Worker compatibility adapter changed during authoring')
    header = (b'\x7fELF\x02\x01\x01' + bytes(9)
              + struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0x4000b0, 64, 0, 0, 64, 56, 2, 0, 0, 0)
              + struct.pack('<IIQQQQQQ', 1, 5, 0, 0x400000, 0x400000, 0, 0, 4096)
              + struct.pack('<IIQQQQQQ', 0x6474e551, 6, 0, 0, 0, 0, 0, 16))
    prefix = header + code
    offsets = {name: 176 + symbols[name] for name in labels}
    if len(set(offsets.values())) != len(offsets):
        raise ValueError('Worker compatibility adapter labels overlap')
    return prefix, offsets, sha256(before).digest()


class CompatRecipe(ControllerRecipe):
    def checked_policy(self, policy, packer):
        executable, sources, images = self.kit(policy, packer)
        for alias, path in (
            ('source_build_policy.hepta', PROGRAMS + policy),
            ('selfhost.hepta', PROGRAMS + 'selfhost.hepta'),
            ('source_build_packer.hepta', PROGRAMS + packer),
        ):
            self.node(8, (sources[alias], self.source_views[path]))
            self.node(8, (images[alias], self.compiled[path]))
        return executable

    def replaced_prefix(self, prefix, replacements):
        cursor, parts = 0, []
        for at, (size, value) in sorted(replacements.items()):
            if type(at) is not int or type(size) is not int or at < cursor or size <= 0 or at + size > len(prefix):
                raise ValueError('Worker compatibility ELF patch overlaps or escapes prefix')
            if at > cursor:
                parts.append(self.literal(prefix[cursor:at]))
            # Every replacement is an exact-width native view.
            self.node(8, (self.length(value), self.q(size)))
            parts.append(value)
            cursor = at + size
        parts.append(self.literal(prefix[cursor:]))
        return self.concat(*parts)

    def expected_elf(self, prefix, offsets, labels, parts, *, metadata=None):
        if len(parts) != len(labels) or prefix[96:112] != bytes(16):
            raise ValueError('Worker compatibility ELF shape changed')
        extent = self.length(self.concat(self.literal(prefix), *parts))
        replacements = {96: (8, extent), 104: (8, extent)}
        for index, name in enumerate(labels):
            at = offsets[name]
            if not 176 < at < len(prefix) - 4 or prefix[at - 1] != 0xe8:
                raise ValueError('Worker compatibility call site changed')
            distance = self.length(self.concat(self.literal(prefix[at + 4:]), *parts[:index]))
            replacements[at] = (4, self.node(15, (distance, 0, 4)))
        if metadata is not None:
            if len(parts) != 2:
                raise ValueError('Worker entry metadata requires its two complete images')
            replacements[metadata + 8] = (8, self.length(parts[0]))
            replacements[metadata + 16] = (8, self.length(parts[1]))
        return self.concat(self.replaced_prefix(prefix, replacements), *parts)

    def checked_member(self, selected, kind, named, prefix, offsets):
        packer = selected.install_stem + '_' + kind + '_packer.hepta'
        builder = self.checked_policy('source_filter_member.hepta', packer)
        captured = self.capture(named, b'HIAMUL01')
        for index, path in enumerate(named.values()):
            self.node(8, (self.pick(captured, index), self.source_views[path]))
        actual = self.run(builder, captured)
        parts = tuple(self.compiled[path] for path in named.values())
        labels = ('policy_hole', 'stage_hole', 'sha_hole') if kind == 'owner' else ('policy_hole', 'sha_hole')
        expected = self.expected_elf(prefix, offsets, labels, parts,
                                     metadata=None if kind == 'owner' else offsets['entry_metadata'])
        footer = self.concat(self.length(expected), *(self.length(part) for part in parts),
                             self.q(len(parts)), self.literal(b'HIAOBJS1'))
        full_frame = self.concat(expected, *parts, footer)
        self.node(8, (actual, full_frame))
        return expected

    def checked_bound_entry(self, selected, unbound, owner, pin_at):
        binder = self.checked_policy(selected.install_stem + '_entry_bind.hepta',
                                     'source_build_packer.hepta')
        capabilities = (owner, self.import_product('hia-subprocess'),
                        self.import_product('hia-source-build'),
                        self.import_product('hia-source-capture'))
        pins = self.concat(*(self.digest(raw) for raw in capabilities))
        self.node(8, (self.length(pins), self.q(128)))
        request = self.concat(self.literal(b'HIAENBD1'), pins, unbound)
        bound = self.run(binder, request)
        expected = self.concat(self.node(15, (unbound, 0, pin_at)), pins,
                               self.node(15, (unbound, pin_at + 128, U64_MAX)))
        self.node(8, (bound, expected))
        return bound

    def source_record(self, name):
        encoded = name.encode('ascii')
        raw = self.source_views[name]
        return self.concat(self.q(len(encoded)), self.literal(encoded),
                           self.length(raw), self.digest(raw))

    def build_compat(self, root):
        captured = {name: (root / name).read_bytes() for name in SOURCES}
        for name in SOURCES:
            self.source(name)
        self.compile_exact(COMPILED)
        owner_prefix, owner_offsets, owner_sha = template(
            root, ADAPTERS[0], ('policy_hole', 'stage_hole', 'sha_hole'))
        entry_prefix, entry_offsets, entry_sha = template(
            root, ADAPTERS[1], ('policy_hole', 'sha_hole', 'entry_pins', 'entry_metadata'))
        for name, digest in zip(ADAPTERS, (owner_sha, entry_sha), strict=True):
            self.node(9, (self.source_views[name],), digest)
        common = [self.import_product(name) for name in IMPORTS]
        variants, products = [], {}
        for number, owner_name, entry_name in zip(PROTOCOLS, OUTPUTS[:4:2], OUTPUTS[1:4:2], strict=True):
            selected = protocol(number)
            primary = PROGRAMS + selected.install_stem
            owner_sources = {'hia-worker-install-owner.hepta': primary + '_owner.hepta',
                             'worker_install_dag.hepta': primary + '_dag.hepta',
                             'sha256_stream.hepta': PROGRAMS + 'sha256_stream.hepta'}
            entry_sources = {'hia-worker-install.hepta': primary + '_entry.hepta',
                             'sha256_stream.hepta': PROGRAMS + 'sha256_stream.hepta'}
            owner = self.checked_member(selected, 'owner', owner_sources, owner_prefix, owner_offsets)
            unbound = self.checked_member(selected, 'entry', entry_sources, entry_prefix, entry_offsets)
            entry = self.checked_bound_entry(selected, unbound, owner, entry_offsets['entry_pins'])
            products[owner_name], products[entry_name] = owner, entry
            variants.append(self.concat(self.literal(selected.options_magic),
                                         self.q(selected.helper_count, selected.record_count),
                                         self.length(owner), self.digest(owner),
                                         self.length(entry), self.digest(entry)))
        record = self.concat(self.literal(b'HIAWCR01'), self.q(len(PROTOCOLS), len(SOURCES)),
                             *(self.concat(self.length(raw), self.digest(raw)) for raw in common),
                             *variants, *(self.source_record(name) for name in SOURCES))
        # Re-capture all source inputs after the real child executions.
        from tools.generate_hia_release_stage_recipes import Recipe
        for name in SOURCES:
            self.node(8, (self.source_views[name], Recipe.source(self, name)))
        if any((root / name).read_bytes() != raw for name, raw in captured.items()):
            raise ValueError('Worker compatibility source changed during authoring')
        for name in OUTPUTS[:-1]:
            self.publish(name, products[name])
        self.publish(OUTPUTS[-1], record)
        if tuple(self.published) != OUTPUTS:
            raise ValueError('Worker compatibility publication order differs')
        return self


def build_recipe(root=ROOT):
    return CompatRecipe().build_compat(Path(root))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    recipe = build_recipe(root)
    raw = recipe.binary()
    path = root / RECIPE
    if args.check:
        if path.read_bytes() != raw:
            raise SystemExit('Worker compatibility release DAG differs')
    else:
        path.write_bytes(raw)
    print(json.dumps({'recipe': RECIPE, 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
                      'nodes': len(recipe.nodes), 'handles': recipe.next_handle - 1,
                      'publications': recipe.published, 'sources': SOURCES,
                      'native_imports': IMPORTS}, sort_keys=True))


if __name__ == '__main__':
    main()
