"""HIA-owned publication measurement decisions with frozen host transport.

The caller retains envelope capture, monotonic observations, cancellation,
locks, all-input translation validation and real artifact construction. This
component owns the complete finite measurement policy, including projections
whose intermediate products exceed 64 bits. It grants no publication authority.
"""
from __future__ import annotations

import ctypes
from hashlib import sha256
import json
import os
import struct

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/publication_measurement.hepta')
SCHEMA = 'hepta.hia.publication-measurement-native.v1'
SELECTOR = 'HEPTA_HIA_PUBLICATION_MEASUREMENT_MANIFEST'
REQUEST_MAGIC = int.from_bytes(b'HIAPME01', 'little')
RESULT_MAGIC = int.from_bytes(b'HIAPMR01', 'little')
OUTPUT_BYTES = 176
STATE_BYTES = 2048
REASONS = ('identical_native_artifacts', 'baseline_timing_noise', 'candidate_timing_noise',
           'insufficient_measured_gain', 'paired_saving_not_above_noise_margin',
           'search_cost_budget', 'experiment_cost_not_recovered')


def packet(measurement, prepare_ns):
    """Transport a caller-frozen envelope; no sample or cost policy runs here.

    Preparation time uses a lossless signed, arbitrary-length magnitude.
    HIA alone applies its finite projected-cost bound. Negative exact integers
    are transported too, including cancellation of a large positive projection,
    although actual monotonic elapsed time is nonnegative.
    """
    if type(prepare_ns) is not int:
        raise TypeError('publication preparation time must be an exact integer')
    magnitude = abs(prepare_ns)
    payload = magnitude.to_bytes((magnitude.bit_length() + 7) // 8, 'little')
    samples = measurement['samples']
    header = struct.pack('<10Q', REQUEST_MAGIC, len(samples), measurement['calls_per_sample'],
        measurement['horizon_calls'], measurement['search_cost_ns'], measurement['maximum_search_ns'],
        int(prepare_ns < 0), len(payload), 0, 0)
    return (header + measurement['before_artifact_sha256'].encode('ascii')
            + measurement['after_artifact_sha256'].encode('ascii')
            + b''.join(struct.pack('<QQ', row['baseline_ns'], row['candidate_ns']) for row in samples)
            + payload)


def _signed(words, offset):
    value = words[offset + 1] | (words[offset + 2] << 64)
    return -value if words[offset] else value


class NativePublicationMeasurement(NativeHiaJsonImage):
    def observe(self, wire):
        if type(wire) is not bytes:
            raise TypeError('publication measurement requires exact packet bytes')
        source = ctypes.create_string_buffer(wire, max(1, len(wire)))
        output = ctypes.create_string_buffer(OUTPUT_BYTES)
        state = ctypes.create_string_buffer(STATE_BYTES)
        result = self._entry(source, len(wire), output, OUTPUT_BYTES, state, STATE_BYTES)
        if result != OUTPUT_BYTES or source.raw != (wire or b'\0'):
            raise RuntimeError('invalid native publication measurement ABI or changed input')
        words = struct.unpack('<22Q', output.raw)
        if (words[0] != RESULT_MAGIC or words[1] not in (0, 1, 2) or words[2] & ~127
                or words[10] > 1 or words[13] > 1 or words[18] > 1 or words[21] > 1):
            raise RuntimeError('invalid native publication measurement output')
        return words

    def assess(self, measurement, *, prepare_ns):
        from .hia_multiversion import MEASUREMENT_POLICY, _DECISION_RESERVE_NS, _reject
        words = self.observe(packet(measurement, prepare_ns))
        if words[1] == 1:
            _reject('measurement projected cost exceeds the finite policy range')
        if words[1]:
            raise RuntimeError('native publication measurement refused its frozen transport')
        if (words[3] != len(measurement['samples'])
                or words[19] != measurement['calls_per_sample']
                or words[20] != measurement['horizon_calls']
                or words[21] != int(words[2] == 0)):
            raise RuntimeError('native publication measurement output changed its observation identity')
        reasons = [reason for bit, reason in enumerate(REASONS) if words[2] & (1 << bit)]
        saving = struct.unpack('<q', struct.pack('<Q', words[8]))[0]
        packed = json.dumps(measurement, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        return {'schema': 'hepta.hia.native-publication-admission.v1', 'profile': MEASUREMENT_POLICY,
            'measurement_sha256': sha256(packed).hexdigest(), 'eligible': bool(words[21]),
            'reasons': reasons, 'samples': words[3], 'calls_per_sample': words[19],
            'horizon_calls': words[20], 'workload_sha256': measurement['workload_sha256'],
            'function': measurement['function'], 'native_artifact_changed': bool(words[18]),
            'maximum_mad_ppm': 50_000, 'minimum_gain_ppm': 20_000,
            'baseline_median_ns': words[4], 'candidate_median_ns': words[5],
            'baseline_mad_ns': words[6], 'candidate_mad_ns': words[7],
            'paired_saving_median_ns': saving, 'paired_saving_mad_ns': words[9],
            'observed_search_cost_ns': measurement['search_cost_ns'], 'actual_prepare_ns': prepare_ns,
            'observed_cost_ns': _signed(words, 10), 'decision_reserve_ns': _DECISION_RESERVE_NS,
            'charged_cost_ns': _signed(words, 13), 'maximum_search_ns': measurement['maximum_search_ns'],
            'projected_baseline_total_ns': words[16], 'projected_candidate_total_ns': words[17],
            'claims': {'measurements_independently_attested': False, 'projection_is_workload_assumption': True,
                       'statistical_confidence_proved': False, 'sample_trimming_or_adaptive_repeats': False,
                       'core_authority_granted': False, 'general_performance_improvement_proved': False}}


def installed_publication_measurement(path):
    return _installed_json_image(path, SOURCE, SCHEMA, NativePublicationMeasurement)


def selected_publication_measurement(measurement, *, prepare_ns):
    path = os.environ[SELECTOR]
    if not path:
        raise ValueError('publication measurement selector must not be empty')
    return installed_publication_measurement(path).assess(measurement, prepare_ns=prepare_ns)
