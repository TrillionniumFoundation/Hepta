"""Finite 3.12 fixture controls for the fixed metadata inventory; no product run."""
import csv
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
import zipfile
import importlib.metadata
from hashlib import sha256
import runtime_metadata as subject
from common import wire

HERE = Path(__file__).resolve().parent
WHEEL = HERE.parent / 'setuptools-78.1.1-layout-r1/setuptools-78.1.1-py3-none-any.whl'
OUT = HERE / 'inventory-control-originals'
OUT.mkdir()
checks = []

def check(name, action):
    action()
    checks.append({'name': name, 'status': 'PASS'})

def unpack(report):
    records = report['lstat_observation_records']
    def visit(value):
        if isinstance(value, list):
            return [visit(item) for item in value]
        if not isinstance(value, dict):
            return value
        if set(value) == {'record_indices'}:
            return [records[index] for index in value['record_indices']]
        return {key: visit(item) for key, item in value.items()
                if key not in ('lstat_observation_records', 'lstat_chain_encoding')}
    return visit(report)

wheel_raw = WHEEL.read_bytes()
assert sha256(wheel_raw).hexdigest() == subject.SETUPTOOLS_WHEEL_SHA256
with tempfile.TemporaryDirectory(prefix='core-metadata-r3-') as temp:
    # This prefix is longer/deeper than the actual r2 site-packages root.
    root = Path(temp).resolve() / 'runner/work/Hepta/Hepta/opt/hostedtoolcache/Python/3.14.4/x64/lib/python3.14/site-packages'
    root.mkdir(parents=True)
    with zipfile.ZipFile(WHEEL) as archive:
        assert archive.testzip() is None
        for entry in subject.FIXED_METADATA_FILES['setuptools']:
            path = root / entry
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(archive.read(entry))
    for package in ('wheel', 'z3-solver', 'jsonschema'):
        folder = root / subject.OWN_DIST_INFO[package]
        folder.mkdir()
        (folder / 'METADATA').write_text('Metadata-Version: 2.1\nName: ' + package + '\nVersion: ' + subject.PACKAGES[package] + '\n')
        (folder / 'RECORD').write_text(''.join(entry + ',,\n' for entry in subject.FIXED_METADATA_FILES[package]))
    distributions = {name: importlib.metadata.PathDistribution(root / directory)
                     for name, directory in subject.OWN_DIST_INFO.items()}
    for entries in subject.FIXED_METADATA_FILES.values():
        for entry in entries:
            (root / entry).chmod(0o666)

    dist = distributions['setuptools']
    old = sorted(item for item in dist.files if item.name in ('METADATA', 'RECORD')
                 and item.parent.name.endswith('.dist-info'))
    def old_failure():
        assert len(old) == 34
        assert not (len(old) == 2 and {item.name for item in old} == {'METADATA', 'RECORD'})
    check('actual fixed setuptools RECORD reproduces old 34-versus-2 refusal', old_failure)

    def full_selection():
        result = []
        for name, distribution in distributions.items():
            observed = {}
            chosen = subject.selected_metadata(distribution, name, observed)
            assert [str(item) for item in chosen] == list(subject.FIXED_METADATA_FILES[name])
            assert observed['own_distribution_entries'] == [subject.OWN_DIST_INFO[name] + '/' + basename for basename in ('METADATA','RECORD')]
            original = sorted(item for item in distribution.files if item.name in ('METADATA', 'RECORD')
                              and item.parent.name.endswith('.dist-info'))
            assert chosen == original
            result.extend(chosen)
        assert len(result) == 40
    check('four selected distributions retain all original controller 40 identities', full_selection)

    def refuse_entries(entries):
        fake = SimpleNamespace(files=[importlib.metadata.PackagePath(entry) for entry in entries], version='78.1.1')
        observation = {}
        try:
            subject.selected_metadata(fake, 'setuptools', observation)
        except RuntimeError:
            assert 'controller_metadata_entries' in observation
        else:
            raise AssertionError('bad inventory accepted')
    exact = list(subject.FIXED_METADATA_FILES['setuptools'])
    for label, entries in (
        ('missing own METADATA', exact[1:]),
        ('missing own RECORD', [entry for entry in exact if entry != exact[1]]),
        ('missing vendored METADATA', [entry for entry in exact if entry != exact[2]]),
        ('missing vendored RECORD', [entry for entry in exact if entry != exact[3]]),
        ('duplicate own identity', exact + [exact[0]]),
        ('duplicate vendored identity', exact + [exact[2]]),
        ('vendored pair cannot impersonate selected own pair', exact[2:4]),
        ('extra unlisted vendor identity', exact + ['setuptools/_vendor/unlisted-1.dist-info/METADATA']),
        ('different own distribution directory', [entry.replace('setuptools-78.1.1.dist-info/', 'setuptools-78.1.2.dist-info/') for entry in exact]),
        ('empty metadata inventory', []),
    ):
        check(label + ' refused', lambda entries=entries: refuse_entries(entries))

    def nonowned():
        path = root / exact[0]
        before = path.stat()
        observed = subject.observe_file(path)
        seen = {}
        # Controlled euid predicate input; no chown or privileged operation.
        with patch.object(subject.os, 'geteuid', return_value=os.geteuid()+1), patch.object(subject.os, 'fchmod', side_effect=AssertionError('must refuse before effect')):
            try:
                subject.observe_file(path, repair=True, expected=observed, observation=seen)
            except RuntimeError:
                assert seen['mode_change_attempted'] is False
            else:
                raise AssertionError('non-current-owner mutable file admitted')
        assert subject.identity(path.stat()) == subject.identity(before)
    check('non-current-owner predicate refuses before fchmod (controlled euid input)', nonowned)

    operation = {'repository':'TrillionniumFoundation/Hepta','control_commit':'0'*40,
                 'workflow_commit':'0'*40,'policy_sha256':'0'*64,'run_id':0,'run_attempt':1,
                 'trigger_branch':subject.TRIGGER,'local_fixture_only':True}
    stage_root = Path(temp).resolve() / 'reports'; stage_root.mkdir()
    originals = {str(path): path.read_bytes() for entries in subject.FIXED_METADATA_FILES.values()
                 for path in (root / entry for entry in entries)}
    reports = {}
    for stage in subject.STAGES:
        captured = io.BytesIO()
        sink = SimpleNamespace(buffer=captured)
        with patch.object(subject, 'context', return_value=(stage_root, operation)), \
             patch.object(subject.importlib.metadata, 'distribution', side_effect=distributions.__getitem__), \
             patch.object(sys, 'argv', ['runtime_metadata.py',stage,'--policy-sha256','0'*64,'--control-commit','0'*40]), \
             patch.object(sys, 'stdout', sink), \
             patch.dict(os.environ, {'pythonLocation':str(Path(sys.executable).resolve().parent.parent)}):
            rc=subject.main()
        raw=(stage_root / (subject.NAME+stage+'.json')).read_bytes()
        (OUT / (stage+'.json')).write_bytes(raw)
        (OUT / (stage+'.stdout.log')).write_bytes(captured.getvalue())
        reports[stage]=json.loads(raw)
        assert rc==0, reports[stage]
        assert len(raw)+8192<=subject.MAX_REPORT
        assert len(captured.getvalue())+8192<=subject.MAX_STDOUT
        assert len(reports[stage]['rows'])==40
        assert reports[stage]['own_metadata_original_count']==8
        assert reports[stage]['vendored_metadata_original_count']==32
        assert reports[stage]['complete_controller_metadata_originals']
        reconstructed=unpack(reports[stage])
        assert subject.report_bytes(reconstructed)==raw
    check('all three fixture stages retain 40 originals and fit unchanged caps with 8KiB reserve', lambda: None)
    def all_admitted():
        assert reports['admit']['status']=='FIXED_METADATA_READY_FOR_UNCHANGED_CONTROLLER'
        assert all(row['mode_change_attempted'] and row['predicate_after']['all']
                   and row['after']['posix_mode']==0o644 for row in reports['admit']['rows'])
        assert all(Path(path).read_bytes()==raw for path,raw in originals.items())
        for distribution in distributions.values():
            original=sorted(item for item in distribution.files if item.name in ('METADATA','RECORD')
                            and item.parent.name.endswith('.dist-info'))
            assert all(subject.predicate(Path(distribution.locate_file(item)).stat())['all'] for item in original)
    check('40 real fixture leaves lose only 0022 and satisfy unchanged controller predicate', all_admitted)
    check('compact chain dictionary exactly reconstructs every observed path and identity', lambda: None)
    report={'schema':'hia.core-emitter-runtime-metadata-inventory-controls.v1','status':'PASS',
            'runtime':sys.version,'scope':'Local CPython3.12 finite fixtures; no Actions, compiler, product, or cold execution. setuptools34 inputs are exact wheel members; other6 are explicitly synthetic metadata fixtures.',
            'wheel_sha256':subject.SETUPTOOLS_WHEEL_SHA256,'checks':checks,'check_count':len(checks),
            'denominators':{'own_pairs':8,'vendored':32,'all_controller_files':40},
            'controlled_euid_refusal_not_a_real_other_uid_filesystem':True,
            'report_sizes':{stage:(OUT/(stage+'.json')).stat().st_size for stage in subject.STAGES},
            'stdout_sizes':{stage:(OUT/(stage+'.stdout.log')).stat().st_size for stage in subject.STAGES},
            'caps_unchanged':{'raw':subject.MAX_REPORT,'stdout':subject.MAX_STDOUT,'reserve_tested':8192}}
    (HERE/'LOCAL-INVENTORY.json').write_bytes(wire(report))
    print(json.dumps(report,sort_keys=True))
