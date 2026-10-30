#!/usr/bin/env python3
"""Write delivery summary only after the unchanged reader passes current source."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def read(name):
    return json.loads((ROOT / name).read_text())


def save(name, value):
    with (ROOT / name).open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write('\n')


def main():
    result, execution = read('VERIFY.json'), read('VERIFY_EXECUTION.json')
    assert result['passed'] is True and result['latest_required_source_verified'] is True
    assert execution['returncode'] == 0 and execution['inputs_unchanged'] is True
    assert execution['stderr']['bytes'] == 0
    row = result['runs']['953fa62']
    jobs = read('raw/final-api-jobs-953fa62.json')['jobs']
    assert len(jobs) == 1
    job = jobs[0]
    assert job['id'] == 124151631902 and job['run_id'] == 41081527613
    assert job['status'] == 'completed' and job['conclusion'] == 'success'
    assert job['head_sha'] == row['head']
    selected = {s['number']: s for s in job['steps']}
    assert all(selected[n]['conclusion'] == 'success' for n in [23, 24, 26])
    assert all(selected[n]['conclusion'] == 'skipped' for n in [20, 21, 22, 25])
    metadata = read('METADATA_BUILD.json')
    costs = read('ACQUISITION_COSTS.json')
    summary = {
        'schema': 'hepta.ci.delivery-summary.v1',
        'source_head': row['head'], 'source_tree': row['tree'],
        'official_run_url': row['acquisition']['official_run_url'],
        'official_job_id': job['id'], 'official_run_attempt': 1,
        'official_job_status': job['status'], 'official_job_conclusion': job['conclusion'],
        'verification': row, 'current_source_verified': True,
        'official_artifact_digest_matches': True,
        'test_skips': 0, 'matrix_selectors_are_full_regression_subset': True,
        'critical_methods_are_full_regression_subset': True,
        'workflow_conditional_standalone_profile_steps_skipped': [20, 21, 22],
        'workflow_alternative_profile_artifact_step_skipped': 25,
        'workflow_conditional_step_skips_are_not_test_skips': True,
        'source_and_external_tool_identity_scope': row['source_identity_scope'],
        'source_or_tool_installation_bytes_bundled': False,
        'ci_pass_changes_crc_economic_negative_result': False,
        'ci_pass_changes_v13_model_qualification_failure': False,
        'global_optimality_or_absolute_safety_proof': False,
        'costs': {'download_wall_ns': row['acquisition']['download_wall_ns'],
                  'metadata_build_wall_ns_before_encoding': metadata['wall_ns_before_encoding'],
                  'verification_reader_wall_ns': execution['reader_process_wall_ns'],
                  'verification_outer_wall_ns_before_encoding': execution['outer_wall_ns_before_encoding'],
                  'verification_inner_wall_ns_before_encoding': result['verification_wall_ns_before_encoding'],
                  'verification_cost_scopes_are_nested_do_not_add': True,
                  'api_costs': costs,
                  'complete_manual_and_authoring_cost_ns': None},
        'new_workflow_dispatches': 0, 'new_test_or_model_runs': 0,
        'archive_extracted_or_executed': False,
    }
    save('SUMMARY.json', summary)
    p = read('CI_PINS.json')['runs']['953fa62']
    text = f'''# Exact-source CI evidence: 953fa62

The official [GitHub Actions run {p['run_id']}](https://github.com/TrillionniumFoundation/Hepta/actions/runs/{p['run_id']}) completed successfully. The unchanged bounded offline reader independently verified this run's ZIP and retained API receipts. `VERIFY.json` has both `passed=true` and `latest_required_source_verified=true` for source `{p['head']}`, tree `{p['tree']}`.

## Observed denominators

| Observation | Actual count |
|---|---:|
| Integrated gates | 8 |
| Full Python regression, unique method IDs, zero skips/errors/failures | {p['python_tests']} |
| Rust tests, zero failed/ignored/measured/filtered | {p['rust_tests']} |
| Rust binary/doc-test launch and footer records | {p['rust_binaries']} |
| Critical coverage groups / modules / methods | {p['critical_groups']} / {p['critical_modules']} / {p['critical_methods']} |
| Canonical capabilities / unique selectors | {p['capabilities']} / {p['matrix_tests']} |
| Recorded tracked files / external identities | {p['tracked_files']} / {p['external_files']} |
| ZIP members / expanded bytes | {p['members']} / {p['payload_bytes']} |

Critical coverage and canonical selectors are checked subsets of the full regression, so their counts are not added to the full Python total. Three conditional standalone-profile workflow steps (20–22) and the alternative profile's artifact step (25) were intentionally skipped because this run selected the integrated profile; the integrated qualification, matrix, and artifact steps (23, 24, 26) succeeded. The actual selected Python, Rust, and canonical test logs contain zero skipped or ignored tests.

## Identities and scope

Official artifact `{p['artifact_id']}`: `{p['bytes']}` bytes, SHA-256 `{p['sha256']}`. Canonical contract SHA-256: `{p['contract_sha256']}`. `CI_PINS.json` binds the official completed run, artifact API digest and download receipt. `MANIFEST.json` binds every ZIP member.

`verify_ci.py` is byte-for-byte the prior reviewed reader (SHA-256 `e2ab3be7afd0e2b47feb5a0d5a465cc9cc8c2a37426b002a89ec341d58e16437`). It performs a bounded no-follow single read of the ZIP, verifies its official digest, limits expanded sizes/types/paths, and never extracts or executes its contents. It compares source and external inventories before/after, checks all eight separate gate reports against the qualification report, recomputes unique Python IDs, parses each Rust binary footer, verifies exact critical subsets and canonical selector statuses, and keeps all unsupported safety/optimality claims false.

This ZIP records source/tool inventories; it does not bundle the complete source checkout or tool installation and does not independently re-hash those absent bytes. The current CI pass does not reclassify the CRC cold-cost negative observations or the V13 model qualification failure. It establishes no global optimality, absolute safety, or broad performance superiority theorem.

## Cost and raw retention

`SUMMARY.json` gives the measured download and reader costs. Reader inner, process and outer costs are nested. `ACQUISITION_COSTS.json` preserves instrumented connector call durations at millisecond resolution and explicitly leaves the initial uninstrumented calls and complete authoring/manual cost unknown. Raw API snapshots include earlier in-progress states, the final official run/jobs/artifact receipts, the official job log, and the exact ZIP. No workflow was re-dispatched and no test/model payload was run for this audit.

## Repeat the offline readback

Use a fresh output path; the reader refuses to overwrite a prior result:

```sh
python verify_ci.py --root . --pins CI_PINS.json --pins-sha256 {result['pins_sha256']} --manifest MANIFEST.json --manifest-sha256 {result['manifest_sha256']} --output /tmp/hepta-ci-953-independent.json
```

`VERIFY.stdout`, `VERIFY.stderr`, and `VERIFY_EXECUTION.json` retain the actual first readback and its outer receipt. `FILES.json` lists the final portable package files and hashes except itself. No signed download URL or credential is saved.
'''
    with (ROOT / 'README.md').open('x') as f:
        f.write(text)
    print(json.dumps({'summary_written': True, 'counts': {
        k: p[k] for k in ('python_tests', 'rust_tests', 'matrix_tests', 'capabilities')}}))


if __name__ == '__main__':
    main()
