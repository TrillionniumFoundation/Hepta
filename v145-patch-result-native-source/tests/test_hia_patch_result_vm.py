"""Twelve finite Core-VM replays of actual new patch-image transitions.

No foreign provider is synthesized by replay. Each input/output/workspace is
the complete observed physical buffer from a completed Native predecessor.
"""
from __future__ import annotations

import json
from pathlib import Path
import traceback
import unittest

from tests.hia_patch_result_support import (
    BufferStore, VM_CALL_DEPTH, VM_HEAP, VM_KEYS, VM_STEPS,
    context, pin, publish, require,
)


class PatchResultFrameVMTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from hepta.hia_agent_assembly import assemble_program
        cfg = context()
        cls.directory = Path(cfg['evidence']).absolute() / 'vm'
        cls.directory.mkdir(mode=0o700)
        cls.buffers = BufferStore(cls.directory / 'buffers')
        source = Path(cfg['source']).absolute() / 'examples/hia_bootstrap/patch_result.hepta'
        raw = source.read_bytes()
        require(pin(raw) == cfg['hia_source_pin'], 'VM HIA source is not its exact generated predecessor')
        cls.program = assemble_program(raw)
        cls.function = cls.program.as_dict()['functions'][0]
        catalog_raw = Path(cfg['catalog']).read_bytes()
        require(pin(catalog_raw) == cfg['catalog_pin'], 'actual Native catalog changed')
        cls.catalog = json.loads(catalog_raw)
        require(cls.catalog['schema'] == 'hepta.hia.patch-result.native-vm-catalog.v1'
                and tuple(cls.catalog['selection_order']) == VM_KEYS
                and set(cls.catalog['selected']) == set(VM_KEYS)
                and cls.catalog['max_steps'] == VM_STEPS
                and cls.catalog['heap_bytes'] == VM_HEAP
                and cls.catalog['call_depth'] == VM_CALL_DEPTH
                and cls.catalog['image_sha256'] == cfg['image_sha256'],
                'fixed twelve same-image Native witnesses and original VM bounds required')
        # Pin every complete predecessor index once for this bounded child.
        # Never rehash an entire large index once per recorded frame.
        for binding in cls.catalog['inputs']:
            require(pin(Path(binding['path']).read_bytes()) ==
                    {key: binding[key] for key in ('bytes', 'sha256', 'git_blob')},
                    'actual Native index changed before replay')
        cls.observations = []

    @classmethod
    def tearDownClass(cls):
        publish(cls.directory / 'INDEX.json', {
            'schema': 'hepta.hia.patch-result.actual-vm-observations.v1',
            'observations': cls.observations, 'max_steps_per_frame': VM_STEPS,
            'all_native_frames_replayed': False,
        })

    def replay(self, key):
        from hepta.hia_program_runtime import _Machine, _Owner, _View
        selected = self.catalog['selected'][key]
        after_raw = Path(selected['after']).read_bytes()
        require(pin(after_raw) == selected['after_pin']
                and json.loads(after_raw) == selected['frame'], 'exact actual Native frame changed')
        row = selected['frame']
        store = BufferStore(selected['buffers'], create=False)
        before = [store.get(row[name + '_before']) for name in ('source', 'output', 'workspace')]
        expected = [store.get(row[name + '_after']) for name in ('source', 'output', 'workspace')]
        owners = [_Owner(-1 - index, bytearray(raw)) for index, raw in enumerate(before)]
        machine = _Machine(self.program, VM_STEPS, VM_HEAP, None, VM_CALL_DEPTH)
        observation = {'key': key, 'native_frame': row['index'], 'native_case': row['case'],
                       'native_result': row['result'], 'status': 'FAIL',
                       'before': {name: self.buffers.put(raw)
                                  for name, raw in zip(('source', 'output', 'workspace'), before)}}
        try:
            result = machine.invoke(self.function, [_View(owners[0], False),
                                                    _View(owners[1], True), _View(owners[2], True)])[0]
            observation['result'] = result
            self.assertIs(type(result), int)
            self.assertEqual(result, row['result'])
            self.assertEqual([bytes(owner.data) for owner in owners], expected)
            observation['status'] = 'PASS'
        except BaseException:
            observation['traceback'] = traceback.format_exc()
            raise
        finally:
            # A trap/fuel/host exception retains this run's actual partial
            # spans, never a reference span or a later successful execution.
            observation['after'] = {name: self.buffers.put(bytes(owner.data))
                                    for name, owner in zip(('source', 'output', 'workspace'), owners)}
            observation['steps'] = machine.steps
            observation['source_unchanged'] = bytes(owners[0].data) == before[0]
            observation['exact_native_buffers'] = [bytes(owner.data) for owner in owners] == expected
            self.observations.append(observation)
            publish(self.directory / (key + '.json'), observation)

    def test_apply_start_full_buffers(self): self.replay('apply-start')
    def test_interface_start_full_buffers(self): self.replay('interface-start')
    def test_real_import_claim_full_buffers(self): self.replay('import-claim')
    def test_real_import_ack_full_buffers(self): self.replay('import-ack')
    def test_four_unpack_claim_full_buffers(self): self.replay('unpack4-claim')
    def test_four_unpack_ack_full_buffers(self): self.replay('unpack4-ack')
    def test_lazy_generator_start_full_buffers(self): self.replay('generator-start')
    def test_normal_terminal_full_buffers(self): self.replay('normal-terminal')
    def test_exception_terminal_full_buffers(self): self.replay('exception-terminal')
    def test_retirement_start_full_buffers(self): self.replay('retirement-start')
    def test_retirement_ack_full_buffers(self): self.replay('retirement-ack')
    def test_actual_lost_claim_return_full_buffers(self): self.replay('lost-claim')


if __name__ == '__main__':
    unittest.main()
