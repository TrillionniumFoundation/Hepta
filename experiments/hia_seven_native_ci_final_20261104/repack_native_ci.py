"""Losslessly deduplicate equal CI archive members; verify every retained byte."""
from pathlib import Path
import gzip, hashlib, io, json, tarfile

ROOT = Path(__file__).resolve().parent
SRC = ROOT / 'publication-native-e3b'
OUT = ROOT / 'publication-native-e3b-v2'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def main():
    OUT.mkdir(exist_ok=False)
    old_summary = json.loads((SRC / 'SUMMARY.json').read_bytes())
    inventory_raw = (SRC / 'ARTIFACT_INVENTORY.json').read_bytes()
    inventory = json.loads(inventory_raw)
    expected = {m['retained_path']:m for a in inventory for m in a['members']
                if m['retained_in_text_archive']}
    old_archive = (SRC / old_summary['archive']['path']).read_bytes()
    assert len(old_archive) == old_summary['archive']['bytes']
    assert sha(old_archive) == old_summary['archive']['sha256']
    cache, seen, hardlinks = {}, set(), []
    buffer = io.BytesIO()
    with gzip.GzipFile(filename='', fileobj=buffer, mode='wb', mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w|') as target:
            with tarfile.open(fileobj=io.BytesIO(old_archive), mode='r:gz') as source:
                for member in source:
                    assert member.isfile() and member.name not in seen
                    assert member.name in expected
                    data = source.extractfile(member).read()
                    item = expected[member.name]
                    assert len(data) == item['bytes'] and sha(data) == item['sha256']
                    dest = tarfile.TarInfo(member.name)
                    dest.mode, dest.mtime = 0o644, 0
                    key = (len(data), sha(data))
                    prior = cache.get(key)
                    if prior is not None:
                        prior_name, prior_data = prior
                        assert data == prior_data
                        dest.type, dest.linkname, dest.size = tarfile.LNKTYPE, prior_name, 0
                        target.addfile(dest)
                        hardlinks.append({'path':member.name,'target':prior_name,
                                          'bytes':len(data),'sha256':sha(data)})
                    else:
                        dest.size = len(data)
                        target.addfile(dest, io.BytesIO(data))
                        cache[key] = (member.name, data)
                    seen.add(member.name)
    assert seen == set(expected) and len(seen) == 1983
    archive = buffer.getvalue()
    verified = set()
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        for member in tar:
            assert member.name not in verified and member.name in expected
            assert member.isfile() or (member.islnk() and member.linkname in verified)
            data = tar.extractfile(member).read()
            item = expected[member.name]
            assert len(data) == item['bytes'] and sha(data) == item['sha256']
            verified.add(member.name)
    assert verified == seen
    parts = []
    for i, offset in enumerate(range(0, len(archive), 786432)):
        raw = archive[offset:offset+786432]
        name = 'native-ci-text-and-source.part-%03d.gz' % i
        (OUT / name).write_bytes(raw)
        parts.append({'path':name,'bytes':len(raw),'sha256':sha(raw)})
    part_index = {'schema':'hepta.native-ci.archive-parts.v2','bytes':len(archive),
                  'sha256':sha(archive),'encoding':'ordered raw chunks of one gzip TAR',
                  'same_bytes_hardlinks':len(hardlinks),'parts':parts}
    (OUT / 'ARCHIVE_PARTS.json').write_bytes(canonical(part_index))
    (OUT / 'ARTIFACT_INVENTORY.json.gz').write_bytes(gzip.compress(inventory_raw, mtime=0))
    (OUT / 'HARDLINK_MAP.json.gz').write_bytes(gzip.compress(canonical(hardlinks), mtime=0))
    summary = {**old_summary,
               'archive':{'bytes':len(archive),'sha256':sha(archive),'parts':'ARCHIVE_PARTS.json'},
               'lossless_packaging':{'original_archive':old_summary['archive'],
                    'unchanged_member_paths_and_bytes':True,'unique_regular_members':len(cache),
                    'same_byte_hardlinks':len(hardlinks),'all_members_independently_read_back':True}}
    (OUT / 'SUMMARY.json').write_bytes(canonical(summary))
    (OUT / 'collect_native_ci.py').write_bytes((ROOT/'collect_native_ci_e3b.py').read_bytes())
    (OUT / 'repack_native_ci.py').write_bytes(Path(__file__).read_bytes())
    verifier = (ROOT / 'publication-native-9435/verify_retained.py').read_text()
    verifier = verifier.replace("assert member.isfile() and member.name not in seen",
        "assert member.name not in seen\n            assert member.isfile() or (member.islnk() and member.linkname in seen)")
    (OUT / 'verify_retained.py').write_text(verifier)
    (OUT / 'README.md').write_text(
        '# Actual-host evidence for the final implementation tree\n\n'
        'These 17 successful CI artifacts bind publication e3b380bdb4d52e3d65c77356a3c09a4c6e3cfbf4 '
        'to exact tree 9530e9feccf0077696d2e94746fda6bfb6854417, identical to original desktop source 3707b871ecbe563233ee9a3b69299fc627408936. '
        'The desktop composition and CI use separately recorded toolchains; these runs are not substituted for each other.\n\n'
        'Every original ZIP size and SHA256 was checked. The complete inventory has 2,133 members: '
        'all 1,983 UTF-8 text/source members are retained byte-for-byte; the 150 native binaries are inventoried by original size and hash. '
        'No downloaded program was executed by the collection tools.\n\n'
        'Equal member contents share backward TAR hardlinks after an exact byte comparison. '
        'All names, sizes and hashes were then independently read back. Run python verify_retained.py in this directory to '
        'verify every part and retained member without extraction or execution. ARCHIVE_PARTS.json gives the ordered gzip TAR parts.\n\n'
        'The actual-host results cover the declared C ABI and stb_divide profiles, unchanged nlohmann/json 3.11.3 and 3.12.0 '
        'through the C++/Hepta bridge, captured C to direct HIA LLVM on Linux x86_64/AArch64, and finite standalone AArch64 execution. '
        'They do not establish general C/C++ translation, DMA/MMIO, arbitrary asynchronous cancellation, crash recovery or whole-language concurrent safety.\n\n'
        'C++ lifecycle totals keep registry retention separate from ordinary live-owner deltas. Cancellation is cooperative at an admitted boundary. '
        'SUMMARY.json records the exact observed counts and scope for each artifact.\n')
    publication=[]
    for p in sorted(OUT.iterdir()):
        raw=p.read_bytes()
        publication.append({'path':'experiments/hia_seven_native_ci_final_20261104/'+p.name,
                            'local_path':str(p),'bytes':len(raw),'sha256':sha(raw),
                            'sha':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
                            'mode':'100644','type':'blob'})
    (OUT/'PUBLICATION_FILES.json').write_bytes(canonical(publication))
    print(json.dumps({'archive_bytes':len(archive),'archive_sha256':sha(archive),
                      'retained_members':len(verified),'hardlinks':len(hardlinks),
                      'files':len(publication),'total_bytes':sum(x['bytes'] for x in publication)}))
if __name__ == '__main__':
    main()

