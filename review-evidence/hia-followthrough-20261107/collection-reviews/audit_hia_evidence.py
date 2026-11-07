from pathlib import Path, PurePosixPath
from hashlib import sha256
import io
import json
import re
import tarfile
import zipfile

BASE=Path('/workspace/scratch/372e7da9bde9')
ROOT=BASE/'evidence-branch/review-evidence/hia-followthrough-20261107'
record=json.loads((BASE/'evidence-staging-record.json').read_text())
patterns={
    'private-key':rb'-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----',
    'github-token':rb'(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})',
    'openai-secret':rb'(?<![A-Za-z0-9_])sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,}',
    'bearer-value':rb'(?i)bearer[ \t]+[A-Za-z0-9._~+/=-]{24,}',
    'aws-access-id':rb'(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])',
    'sqlite-header':rb'\ASQLite format 3\x00',
}
compiled={name:re.compile(rx) for name,rx in patterns.items()}
findings=[]
archives=[]
opaque_format_fixtures=[]
counter={'outer_files':0,'content_items':0,'content_bytes':0}
fixture_base='final-runtime-c81-ci/original-packet/'
truncated_fixture_paths={
    fixture_base+'artifact-13568284012/truncated.zip',
    fixture_base+'rea-zip-preview-c81a938.zip!/truncated.zip',
}
complete_fixture_path=fixture_base+'artifact-13568284012/apk-like-structural-only.zip'

def safe_name(name):
    path=PurePosixPath(name)
    return not path.is_absolute() and '..' not in path.parts

def inspect(name,raw,depth=0):
    assert depth<5
    counter['content_items']+=1
    counter['content_bytes']+=len(raw)
    assert counter['content_bytes']<1024*1024*1024
    for label,rx in compiled.items():
        matches=rx.findall(raw)
        if matches: findings.append({'path':name,'pattern':label,'count':len(matches)})
    leaf=PurePosixPath(name).name.lower()
    if leaf in {'auth.json','config.toml','config.json','credentials.json','state.db'} or leaf.endswith(('.sqlite','.sqlite3')):
        findings.append({'path':name,'pattern':'configuration-or-state-filename','count':1})
    if name in truncated_fixture_paths:
        # This exact CI negative test is intentionally not a readable ZIP.
        # Preserve it verbatim and bind its payload to the separately expanded
        # complete fixture; never suppress arbitrary archive parse failures.
        assert len(raw)==535 and sha256(raw).hexdigest()=='7a4e7e8b74c20c2d3c88034b0a84be53d4d6b2166fd0876c5d34231185e50529'
        complete=(ROOT/complete_fixture_path).read_bytes()
        assert sha256(complete).hexdigest()=='c149f0d9d152dac71a2f026b3540b571470dea6c2a23fcdee1a0c09660d0ab22'
        assert raw==complete[:-1]
        opaque_format_fixtures.append({'path':name,'bytes':len(raw),'sha256':sha256(raw).hexdigest(),
            'reason':'Original intentionally truncated ZIP negative fixture; raw signature scan retained.',
            'complete_equivalent_path':complete_fixture_path,
            'relationship':'exact complete fixture bytes except its final byte',
            'original_bytes_repaired':False})
        return
    members=[]
    if name.endswith(('.tar.gz','.tgz')):
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as ar:
            for member in ar.getmembers():
                assert safe_name(member.name), (name,member.name)
                if member.isdir(): continue
                assert member.isfile(), (name,member.name,'nonregular')
                content=ar.extractfile(member).read()
                assert len(content)==member.size
                members.append({'path':member.name,'bytes':len(content),'sha256':sha256(content).hexdigest()})
                inspect(name+'!/'+member.name,content,depth+1)
    elif name.endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(raw)) as ar:
            assert ar.testzip() is None, name
            for member in ar.infolist():
                assert safe_name(member.filename), (name,member.filename)
                if member.is_dir(): continue
                assert (member.external_attr>>16)&0o170000 != 0o120000
                content=ar.read(member)
                members.append({'path':member.filename,'bytes':len(content),'sha256':sha256(content).hexdigest()})
                inspect(name+'!/'+member.filename,content,depth+1)
    if members:
        archives.append({'path':name,'members':members,'member_count':len(members)})

for relative,expected in sorted(record.items()):
    path=ROOT/relative
    assert path.is_file() and not path.is_symlink(), relative
    raw=path.read_bytes()
    assert (len(raw),sha256(raw).hexdigest())==(expected['bytes'],expected['sha256']),relative
    counter['outer_files']+=1
    inspect(relative,raw)

report={'schema':'hepta.hia.evidence-content-audit.v1','scope':'curated staged evidence only; archive contents included',
        'counts':counter,'archive_count':len(archives),'findings':findings,
        'opaque_format_fixtures':opaque_format_fixtures,
        'patterns_checked':list(patterns),
        'limits':'Signature checks are a supplemental screening step, not a proof that all sensitive content is absent.'}
(BASE/'evidence-content-audit.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
(BASE/'evidence-archive-inventory.json').write_text(json.dumps({'schema':'hepta.hia.evidence-archives.v1','archives':archives,'opaque_format_fixtures':opaque_format_fixtures},indent=2,sort_keys=True)+'\n')
print(json.dumps(report,sort_keys=True))
