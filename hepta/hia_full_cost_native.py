"""Selected HIA arithmetic for the ordinary full-cost caller.

Immutable JSON/field/identity admission and object transport remain hosted.
The image owns sums, peaks, exact signed ratios, control selection and ordered
reason flags. It adds no observation provenance or execution authority.
"""
from __future__ import annotations

import ctypes
import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/full_cost.hepta')
SCHEMA = 'hepta.hia.full-cost-native.v1'
SELECTOR = 'HEPTA_HIA_FULL_COST_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HIAFCP01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAFCR01', 'little')
OUTPUT_BYTES = 80
ORDER = ('baseline', 'dp', 'fixed', 'ndu')
COSTS = ('toolchain', 'dependencies', 'controller_build', 'candidate_build',
         'calibration', 'search', 'verification', 'measurement', 'publication', 'switch', 'rollback')
REASONS = ('unaccounted_costs', 'different_observation_sources', 'no_absolute_full_cost_advantage',
           'no_relative_full_cost_advantage', 'memory_limit_exceeded', 'p99_limit_exceeded')


def arm_packet(costs, rows):
    values = [REQUEST_MAGIC, 1, len(rows), *(costs[name] for name in COSTS)]
    for row in rows:
        values.extend(row[name] for name in ('execution_ns', 'controller_ns',
                                             'failed_attempt_ns', 'peak_rss_bytes', 'p99_ns'))
    return struct.pack('<' + str(len(values)) + 'Q', *values)


def decision_packet(totals, peaks, unknown, observers, data):
    return struct.pack('<17Q', REQUEST_MAGIC, 2, *(totals[name] for name in ORDER),
        peaks['ndu']['peak_rss_bytes'], peaks['ndu']['p99_ns'],
        *(len(unknown[name]) for name in ORDER), len(observers),
        data['minimum_gain_ns'], data['minimum_gain_ppm'],
        data['maximum_peak_rss_bytes'], data['maximum_p99_ns'])


class NativeFullCost(NativeHiaJsonImage):
    def observe(self, wire):
        if type(wire) is not bytes:
            raise TypeError('full-cost arithmetic requires exact admitted-fact bytes')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        initial = b'\xa5' * OUTPUT_BYTES
        output = ctypes.create_string_buffer(initial, OUTPUT_BYTES)
        unused = ctypes.create_string_buffer(1)
        code = self._entry(source, len(wire), output, OUTPUT_BYTES, unused, 0)
        if source.raw != (wire or b'\0') or unused.raw != b'\0':
            raise RuntimeError('full-cost image changed immutable facts or zero-length workspace')
        if code != OUTPUT_BYTES:
            if output.raw != initial:
                raise RuntimeError('refused full-cost image changed output')
            raise RuntimeError('full-cost image refused its admitted-fact transport')
        words = struct.unpack('<10Q', output.raw)
        if words[0] != RESULT_MAGIC or words[1] not in (1, 2) or words[1] != struct.unpack_from('<Q', wire, 8)[0]:
            raise RuntimeError('invalid full-cost output identity')
        return words

    def arm(self, costs, rows):
        words = self.observe(arm_packet(costs, rows))
        if (words[2] not in (0, 1) or words[3] > 100000000000000001
                or words[2] != int(words[3] > 100000000000000000)
                or not 1 <= words[4] <= (1 << 48) or not 1 <= words[5] <= 100000000000000000
                or any(words[6:])):
            raise RuntimeError('invalid full-cost arm result')
        return words[3], words[4], words[5]

    def decide(self, totals, peaks, unknown, observers, data):
        words = self.observe(decision_packet(totals, peaks, unknown, observers, data))
        if (words[2] or words[3] >= 3 or words[4] != totals[ORDER[words[3]]]
                or words[5] not in (0, 1) or words[6] > 100000000000000000
                or words[8] > (1 << 14) or words[9] & ~63):
            raise RuntimeError('invalid full-cost comparison result')
        magnitude = words[7] | (words[8] << 64)
        saving = -words[6] if words[5] else words[6]
        fraction_ppm = -magnitude if words[5] else magnitude
        reasons = [reason for bit, reason in enumerate(REASONS) if words[9] & (1 << bit)]
        return (words[4], ORDER[words[3]]), saving, fraction_ppm, reasons


def installed_full_cost(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativeFullCost)
