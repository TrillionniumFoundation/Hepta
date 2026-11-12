"""Reclaim two reproducible old exports, retaining every original evidence packet."""
from pathlib import Path
from hashlib import sha1, sha256
import base64
import importlib.util
import json
import shutil
import zlib

ROOT = Path(__file__).resolve().parent
WORK = ROOT.parent
BASE = WORK / 'v76-product-publication-r1/source'


def main():
    spec = importlib.util.spec_from_file_location('restore', WORK / 'v80-global-resolution-development-r1/restore_source.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    base = helper.manifest(BASE)
    assert len(base) == 3153 and helper.tree_hash(base) == '1bc7c90996e1910ad66ba771b0bfee1d5bfa655c'
    packet_path = WORK / 'v79-joint-full-harness-authoring-r1/preproof-r2-original/SOURCE-PACKET.json'
    raw = packet_path.read_bytes()
    assert sha256(raw).hexdigest() == '0fdf556bc32a78f255fae388b6091d3e781c1ed3c384b0a04ec77db00e85f46d'
    packet = json.loads(raw)
    assert helper.simple(packet['base_files']) == base
    preproof = {item['path']: item for item in packet['files']}
    proof_path = WORK / 'v78-proof-contract-development-r1/checkpoint-r2/CUMULATIVE-OVERLAY.zlib.json'
    proof_wrapper = proof_path.read_bytes()
    assert helper.identify(proof_wrapper)['blob'] == '97c1542bd4d8a35a389168dc6e76273dbd575de7'
    proof = json.loads(zlib.decompress(base64.b64decode(json.loads(proof_wrapper)['payload'], validate=True)))
    proof_delta = {name: {'content': row['text'], 'encoding': 'utf-8'} for name, row in proof['files'].items()}
    proof_manifest = {name: {**{k: row[k] for k in ('bytes', 'sha256', 'mode')}, 'blob': row['git_blob_sha']}
                      for name, row in proof['source_manifest'].items()}
    cases = [
        ('v80-global-resolution-development-r1/original-source', helper.simple(packet['final_files']),
         preproof, str(packet_path.relative_to(WORK)), 'aa32ea9110b9b50e5840392324b7ffbcf86d0f45'),
        ('v78-proof-contract-development-r1/source', proof_manifest, proof_delta,
         str(proof_path.relative_to(WORK)), '7a9bfd37447827801a1493fc922a8e373673882c'),
    ]
    records = []
    for name, expected, delta, packet_name, tree in cases:
        directory = WORK / name
        assert directory.resolve().is_relative_to(WORK.resolve()) and directory.is_dir() and not directory.is_symlink()
        observed = helper.manifest(directory)
        assert observed == expected and helper.tree_hash(observed) == tree
        for filename, row in observed.items():
            if filename in delta:
                item = delta[filename]
                rebuilt = (item['content'].encode() if item['encoding'] == 'utf-8'
                           else base64.b64decode(item['content'], validate=True))
            else:
                rebuilt = (BASE / filename).read_bytes()
                assert base[filename] == row
            assert helper.identify(rebuilt) == {k: row[k] for k in ('bytes', 'sha256', 'blob')}
            assert rebuilt == (directory / filename).read_bytes()
        records.append({'removed_export': name, 'files': len(observed),
                        'logical_bytes': sum(row['bytes'] for row in observed.values()),
                        'tree': tree, 'restore_base': str(BASE.relative_to(WORK)),
                        'restore_packet': packet_name, 'all_file_bytes_sha256_gitblob_modes_verified': True,
                        'complete_evidence_packets_retained': True})
    report = {'schema': 'hia.reproducible-local-export-reclamation.v80.r1', 'records': records,
              'base_commit': '4b19af89a766593f7d5f1cc2db256e81aba7afcb',
              'remote_sources_and_artifacts_modified': False, 'active_source_modified': False,
              'production_legacy_removed': False, 'whole_native': False}
    out = ROOT / 'EXPORT-RECLAMATION.json'
    with out.open('x') as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write('\n')
    for name, _, _, _, _ in cases:
        shutil.rmtree(WORK / name)
    print(json.dumps(report, sort_keys=True))


if __name__ == '__main__':
    main()
