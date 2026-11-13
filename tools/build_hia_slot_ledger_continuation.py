"""Build the native slot/version/lease ledger from source-matched cold HIA."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.hia_selfhost_contract import PROFILE

ROOT = Path(__file__).resolve().parents[1]


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    from tools.qualify_hia_selfhost import compile_stage
    compiler_bytes, cold_bytes = compiler.read_bytes(), cold_report.read_bytes()
    sources = admit_cold_build(compiler_bytes, cold_bytes)
    name = 'examples/hia_bootstrap/slot_ledger_continuation.hepta'
    source_path = ROOT / name
    source = source_path.read_bytes()
    if sources.get(name) != sha256(source).hexdigest():
        raise ValueError('HIA slot ledger source differs from admitted cold source')
    output.mkdir(mode=0o700)
    image, receipt = compile_stage(output, 'slot-ledger', compiler, source)
    image_bytes = image.read_bytes()
    if (source_path.read_bytes() != source or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != cold_bytes or current_sources() != sources
            or image.read_bytes() != image_bytes):
        raise ValueError('HIA slot ledger build inputs changed')
    manifest = {'schema': 'hepta.hia.slot-ledger-native.v1',
        'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
        'image_sha256': sha256(image_bytes).hexdigest(),
        'compiler_sha256': sha256(compiler_bytes).hexdigest()}
    path = output / 'manifest.json'
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.slot-ledger-build.v1', 'status': 'NATIVE_CANDIDATE_BUILT',
        'profile': PROFILE, 'source_manifest': sources, 'manifest': manifest,
        'cold_report_sha256': sha256(cold_bytes).hexdigest(), 'native_compile_receipt': receipt,
        'slot_generation_lease_policy_and_effect_claims_native': True,
        'same_main_slots_versions_leases_and_wal_preserved': True,
        'requires_native_namespace_and_request_transaction_owners': True,
        'adoption_and_rollback_commit_owned_by_request_journal': True,
        'direct_lease_commit_attested_by_native_namespace_epoch': True,
        'repeated_concurrent_and_in_flight_lease_invocation_preserved': True,
        'sql_objects_context_evidence_and_child_runner_foreign': True,
        'direct_lease_historical_idempotency_invented': False,
        'source_selected_service_activated': False, 'old_code_or_state_deleted': False,
        'all_input_equivalence_proved': False, 'whole_stack_rewritten_in_hia': False,
    }, indent=2, sort_keys=True) + '\n')
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--cold-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == '__main__':
    main()
