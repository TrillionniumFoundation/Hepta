"""Verify exact suppliers and inverse two-manifest provenance adaptation."""
import copy
import hashlib
import json
from pathlib import Path
from verify_typed_fixture_repairs import project_original, verify as verify_fixture_repairs
ROOT=Path(__file__).resolve().parents[1]
PARENT='0594a85f2f1e05ef50a61bf9c5a18ae191499502'
SUPPLIER='653b508336a470151b94f5e1c0448654c4782030'

def identity(data):
    return {'git_blob':hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest(),'sha256':hashlib.sha256(data).hexdigest()}

def verify(root=ROOT):
    verify_fixture_repairs(root)
    doc=json.loads((root/'tools/versioned_typed_components.json').read_bytes())
    if doc['parent']!=PARENT or doc['supplier']!=SUPPLIER:raise ValueError('Unexpected exact suppliers')
    if len(doc['parent_files'])!=281 or len(doc['supplier_files'])!=12:raise ValueError('Incomplete exact-source inventories')
    replaced={'hepta/cli.py','hepta/packages.py'}
    adapted={'tools/store_adt_source_origins.json','tools/typed_stdlib_components.json'}
    if set(doc['originals'])!=replaced|adapted or set(doc['adaptations'])!=adapted:raise ValueError('Unexpected adaptations')
    def check(path,expected):
        if identity(project_original(path,(root/path).read_bytes(),root))!=expected:raise ValueError('Changed source: '+path)
    for path,want in doc['parent_files'].items():
        check(doc['originals'].get(path,path),want)
    for path,want in doc['supplier_files'].items():check(path,want)
    for path,want in doc['adaptations'].items():check(path,want)
    # Compare decoded structures, then independently reserialize the untouched
    # original with its original formatting. Only the named hash slots may differ.
    store='tools/store_adt_source_origins.json';typed='tools/typed_stdlib_components.json'
    old_store=json.loads((root/doc['originals'][store]).read_bytes())
    current=json.loads((root/store).read_bytes())
    expected=copy.deepcopy(old_store)
    for path in replaced:expected['unchanged_parent_inputs'][path]=doc['supplier_files'][path]['sha256']
    if current!=expected:raise ValueError('Store adaptation exceeds two compiler identities')
    current=json.loads((root/typed).read_bytes())
    original=json.loads((root/doc['originals'][typed]).read_bytes())
    expected=copy.deepcopy(original)
    for path in replaced|{store}:expected['unchanged_base'][path]=identity((root/path).read_bytes())
    if current!=expected:raise ValueError('Typed adaptation exceeds three supplier identities')
    for path in adapted:
        data=(root/doc['originals'][path]).read_bytes()
        if (json.dumps(json.loads(data),indent=2)+'\n').encode()!=data:raise ValueError('Original manifest byte recovery failed')
    if len(doc['example_sources'])!=3:raise ValueError('Incomplete example source identity')
    for path,original in doc['example_sources'].items():
        if original not in doc['parent_files']:raise ValueError('Unknown example origin')
        check(path,doc['parent_files'][original])
    # Untouched inherited gates remain active against exactly adapted identities.
    import verify_typed_stdlib_sources,verify_store_adt_sources
    if root==ROOT:
        verify_typed_stdlib_sources.verify();verify_store_adt_sources.verify()
    return {'complete_pass':True,'parent':PARENT,'supplier':SUPPLIER,'unchanged_parent_files':277,'supplier_files':12,'reversible_manifests':2}

if __name__=='__main__':print(json.dumps(verify(),sort_keys=True))
