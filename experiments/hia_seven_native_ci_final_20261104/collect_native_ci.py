"""Retain exact downloaded CI text, inventory omitted native bytes, and audit scope.

This is an evidence collection tool, not a compiler or a proof validator.
No downloaded program is executed. Original ZIPs remain separately identified.
"""
from pathlib import Path, PurePosixPath
import gzip
import hashlib
import io
import json
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parent
INPUT = ROOT / 'native-e3b'
OUTPUT = ROOT / 'publication-native-e3b'
HEAD = 'e3b380bdb4d52e3d65c77356a3c09a4c6e3cfbf4'
TREE = '9530e9feccf0077696d2e94746fda6bfb6854417'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def scalars(value):
    return {k: v for k, v in value.items() if not isinstance(v, (dict, list))}


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def check_source(value):
    assert value.get('head', value.get('commit')) == HEAD
    assert value['tree'] == TREE
    assert value.get('status', value.get('tracked_status')) == ''


def summarize(z, meta):
    def read(name):
        return json.loads(z.read(name))
    result = {'artifact_id': meta['id'], 'artifact_name': meta['name'],
              'original_zip_sha256': meta['verified_sha256']}
    if meta['name'].startswith('cpp-upstream-'):
        v = read('cpp-upstream-host/qualification.json')
        assert v['ok'] and v['inputs_unchanged'] and v['source_commit'] == HEAD
        check_source(v['source_checkout_before'])
        check_source(v['source_checkout_after'])
        versions = []
        for row in v['versions']:
            assert row['status'] == 'passed'
            o = row['observed']
            assert o['ordinary_live_delta'] == 0
            assert o['cancellation'] == dict(committed=3, replayed=0, requested=7, value=107)
            assert all(c['direct_status'] == c['hepta_status'] and
                       c['direct_value'] == c['hepta_value'] and c['live_delta'] == 0
                       for c in o['cases'])
            versions.append(dict(version=row['version'], observation=scalars(o),
                                 cases=len(o['cases']), cancellation=o['cancellation']))
        result.update(scope='unchanged nlohmann/json reused through C++ bridge and compiled Hepta consumer',
                      host=v['host'], versions=versions, claims=v['claims'],
                      wrong_code_status=v['wrong_code']['status'])
    elif meta['name'].startswith('native-'):
        v = read('native-host.json')
        assert v['status'] == 'passed'
        before = z.read('native-host-source-before.log').decode().splitlines()
        after = z.read('native-host-source-after.log').decode().splitlines()
        assert before[:2] == after[:2] == [HEAD, TREE]
        stb = read('stb-divide-host/qualification.json')
        assert stb['ok'] and stb['source_unchanged_during_run']
        assert all(stb['checks'].values())
        result.update(scope='selected native C ABI profiles and complete declared stb_divide variants; Rust backend',
                      host=v['host'], abi_claims=v['claims'],
                      abi_executions=len(v['executions']),
                      type_negative_controls=len(v['type_negative_controls']),
                      wrong_echo=v['negative_control']['status'],
                      stb_totals=stb['totals'], stb_checks=stb['checks'],
                      stb_claims=stb['claims'], stb_seconds=stb['seconds'])
    elif meta['name'].startswith('hia-c-posttest-native-'):
        v = read('qualification/RESULT.json')
        assert v['ok'] and v['source_stable'] and v['expected_source'] == HEAD
        check_source(read('qualification/source-before.json'))
        check_source(read('qualification/source-after.json'))
        result.update(scope='captured bounded C application compiled to HIA LLVM; direct native host execution',
                      host=v['native_host'], observations=scalars(v), claims=v['claims'])
    elif meta['name'].startswith('standalone-aarch64-native-'):
        v = read('qualification.json')
        assert v['ok'] and v['execution_mode'] == 'native'
        assert z.read('source.log').decode().splitlines()[:2] == [HEAD, TREE]
        assert v['counts']['outstanding_allocations'] == 0
        result.update(scope='finite standalone HIA AArch64 Linux native corpus',
                      counts=v['counts'], claims=v['claims'], status=v['status'])
    else:
        raise ValueError('unregistered artifact family')
    return result


def main():
    metadata = json.loads((INPUT / 'DOWNLOAD_MANIFEST.json').read_text())
    assert metadata['head_sha'] == HEAD
    artifacts = metadata['artifacts']
    assert len(artifacts) == len({a['id'] for a in artifacts}) == 17
    OUTPUT.mkdir(exist_ok=True)
    inventory, summaries = [], []
    archive = OUTPUT / 'native-ci-text-and-source.tar.gz'
    with archive.open('xb') as stream, gzip.GzipFile(fileobj=stream, mode='wb', mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w|') as tar:
            for meta in artifacts:
                raw_zip = (INPUT / meta['local_name']).read_bytes()
                assert len(raw_zip) == meta['size_in_bytes']
                assert digest(raw_zip) == meta['verified_sha256'] == meta['digest'].split(':')[1]
                assert meta['workflow_run']['head_sha'] == HEAD
                members = []
                with zipfile.ZipFile(io.BytesIO(raw_zip)) as z:
                    infos = z.infolist()
                    assert len({i.filename for i in infos}) == len(infos)
                    assert sum(i.file_size for i in infos) <= 100_000_000
                    summaries.append(summarize(z, meta))
                    for info in sorted(infos, key=lambda i: i.filename):
                        name = PurePosixPath(info.filename)
                        assert not name.is_absolute() and '..' not in name.parts and '\\' not in info.filename
                        if info.is_dir():
                            continue
                        raw = z.read(info)
                        try:
                            raw.decode('utf-8')
                            text = b'\0' not in raw
                        except UnicodeDecodeError:
                            text = False
                        record = dict(path=info.filename, bytes=len(raw), sha256=digest(raw),
                                      retained_in_text_archive=text)
                        if text:
                            target = '%s/%s' % (meta['id'], info.filename)
                            member = tarfile.TarInfo(target)
                            member.size, member.mode, member.mtime = len(raw), 0o644, 0
                            tar.addfile(member, io.BytesIO(raw))
                            record['retained_path'] = target
                        members.append(record)
                inventory.append(dict(artifact=meta, members=members))
    raw = archive.read_bytes()
    all_members = [m for a in inventory for m in a['members']]
    report = dict(schema='hepta.seven-native-ci-evidence.v1', head_sha=HEAD, tree_sha=TREE,
                  archive=dict(path=archive.name, bytes=len(raw), sha256=digest(raw)),
                  artifacts=len(artifacts), members=len(all_members),
                  text_members=sum(m['retained_in_text_archive'] for m in all_members),
                  binary_members_inventory_only=sum(not m['retained_in_text_archive'] for m in all_members),
                  summaries=summaries,
                  limits=['No downloaded program was executed by the collector.',
                          'CI observations are finite host-specific evidence, not general soundness proofs.',
                          'Raw ZIP identities and all member hashes are retained; native binaries are inventory-only here.',
                          'Tool versions differ from the desktop fixed composition and are not substituted into it.',
                          'No device/DMA support or arbitrary asynchronous/concurrent foreign safety is established.'])
    (OUTPUT / 'ARTIFACT_INVENTORY.json').write_bytes(canonical(inventory))
    (OUTPUT / 'SUMMARY.json').write_bytes(canonical(report))
    print(json.dumps({k:v for k,v in report.items() if k != 'summaries'}, sort_keys=True))


if __name__ == '__main__':
    main()
