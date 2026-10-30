"""Restore the independently reviewed originals and verify every member."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import tarfile

parser=argparse.ArgumentParser()
parser.add_argument('--directory',type=Path,required=True)
parser.add_argument('--archive',type=Path,default=Path(__file__).with_name('nested-returned-view-local6b-peer.tar.xz'))
parser.add_argument('--manifest',type=Path,default=Path(__file__).with_name('inputs.json'))
args=parser.parse_args()
expected={r['archive_member']:r for r in json.loads(args.manifest.read_text())['files']}
args.directory.mkdir(parents=True,exist_ok=False)
observed={}
with tarfile.open(args.archive,'r:xz') as archive:
    for member in archive:
        assert member.isfile() and member.name in expected and member.name not in observed
        relative=Path(member.name)
        assert not relative.is_absolute() and '..' not in relative.parts
        row=expected[member.name]
        data=archive.extractfile(member).read()
        sha=hashlib.sha256(data).hexdigest()
        blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
        mode='100755' if member.mode & 0o100 else '100644'
        assert len(data)==row['bytes'] and sha==row['sha256'] and blob==row['git_blob_sha1'] and mode==row['mode']
        output=args.directory/relative
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_bytes(data);output.chmod(0o755 if mode=='100755' else 0o644)
        assert output.read_bytes()==data
        observed[member.name]=sha
assert set(observed)==set(expected)
print(json.dumps({'ok':True,'actual_extracted_members':len(observed),'actual_extracted_bytes':sum(r['bytes'] for r in expected.values()),'native_tests_or_oracles_rerun':0}))
