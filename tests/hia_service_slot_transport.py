"""152 fixed actual native ACK-loss controls; never manufacture a loss record."""
from __future__ import annotations
import argparse
import ctypes
import json
from pathlib import Path
import struct
import sys
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from tests.hia_service_slot_controls import encoded, put, inputs, digest

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    from hepta import hia_service_slot_native as native
    from hepta import hia_native_delivery as delivery
    from tests import hia_service_slot_original_oracle as oracle
    from tools.build_hia_json_preflight import current_sources
    before = current_sources(); manifest_sha = digest(args.manifest)
    image = native.installed_service_slot(str(args.manifest)); actual_entry = image._entry
    cases = {v['id']: v for v in inputs()['cases']}
    observations = []
    for error_type in (RuntimeError, KeyboardInterrupt, SystemExit, MemoryError):
        for port_name in native.PORTS:
            mode = 'rollback' if port_name.startswith('rollback_') else 'adopt'
            if mode == 'rollback':
                name = 'rollback.ledger.' + ('11' if '_ledger_' in port_name else '00') + '.outer0'
            elif port_name == 'adopt_reject_binding':
                name = 'adopt.mismatch.context.truth.return0.outer0'
            elif port_name == 'adopt_reject_abi':
                name = 'adopt.mismatch.abi.truth.return0.outer0'
            else:
                name = 'adopt.ledger.' + ('111' if '_ledger_' in port_name else '000') + '.outer0'
            fault = error_type('actual acknowledgement loss: ' + port_name)
            frames, calls = [], []
            observed = {'fired': False, 'identity': False, 'later': 0}
            def entry(source, size, output, capacity, state, extent):
                words = struct.unpack('<10Q', ctypes.string_at(source, size))
                if observed['fired']: observed['later'] += 1
                code = actual_entry(source, size, output, capacity, state, extent)
                calls.append({'event': words[1], 'port': words[3], 'code': code})
                if (words[1] in (native.SUCCEEDED, native.RAISED)
                        and words[3] == native.PORT[port_name] and not observed['fired']):
                    observed['fired'] = True
                    raise fault
                return code
            image._entry = entry
            def invoke(case_mode, make_service, make_arguments, namespace):
                frame = native.ServiceSlotFrame(image,
                    native.ROLLBACK if case_mode == 'rollback' else native.ADOPT,
                    make_service(), make_arguments(), namespace=namespace)
                frames.append(frame)
                try: return frame.finish()
                except BaseException as error:
                    observed['identity'] = error is fault
                    raise
            try: row = oracle.observe(cases[name], factory=invoke)
            finally: image._entry = actual_entry
            assert observed['fired'] and observed['identity'] and observed['later'] == 0
            frame, = frames
            assert frame._delivery.loss is not None and not frame._delivery.retired and frame.fenced
            assert calls[-1]['port'] == native.PORT[port_name]
            assert calls[-1]['event'] in (native.SUCCEEDED, native.RAISED)
            assert row['observation']['outcome']['kind'] == 'raised'
            assert not row['observation']['callback_errors']
            observations.append({'port': port_name, 'case': name, 'family': error_type.__name__,
                'actual_entry_returned': calls[-1]['code'] == native.OUTPUT_BYTES,
                'fault_identity_in_chain': observed['identity'],
                'fault_is_top_level_original_object': observed['identity'],
                'no_later_entry': observed['later'] == 0, 'record_retained': not frame._delivery.retired,
                'entries': calls, 'observation': row['observation'],
                'late_events': row['late_events'], 'tracebacks': row['raw_tracebacks']})
    assert len(observations) == 152
    after = current_sources()
    assert after == before and digest(args.manifest) == manifest_sha
    put(args.output / 'report.json', {'schema': 'hepta.hia.service-slot-transport-controls.v1',
        'status': 'PASS', 'planned_count': 152, 'observations': observations,
        'source_before': before, 'source_after': after, 'manifest_sha256': manifest_sha,
        'custody_at_process_end': delivery.custody_snapshot(),
        'unknown_records_intentionally_not_retired': True,
        'loss_fields_written_by_test': False, 'whole_qualification': False})
    print(encoded({'status': 'PASS', 'count': 152}).decode(), end='')

if __name__ == '__main__': main()
