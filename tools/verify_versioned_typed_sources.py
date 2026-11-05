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


# Hard-pinned #719 originals; current manifests may change only named hash slots.
CONTEXT_ORIGINALS = {
    "hepta/modules.py": {
        "git_blob": "e6b2696e4c6ff1294e6c46ccdf994cc1513d4c19",
        "sha256": "873509b45e7c7a0fcb4ff95e0c8587f6c5c5cfeea65203dec110ca43c2ae8301"
    },
    "tools/store_adt_source_origins.json": {
        "git_blob": "cbd879937bac880c82bb5aceff33dc5fbb0df877",
        "sha256": "e3dcba267a0e71ae5f8fed124a69833e4a1b6be343b4df6adb78905f862ac441"
    },
    "tools/typed_stdlib_components.json": {
        "git_blob": "e51bdd9f2bca39234277ab785ee4bbd008b21012",
        "sha256": "c5853ecb3b2bd8a32d3a8fb507cb259370671a09d24a75000cd162fda59e3054"
    },
    "tools/versioned_typed_components.json": {
        "git_blob": "d3c65e1475ec19e2a6f5a563fccfdf20ac1a021d",
        "sha256": "45ae03d9df024969e414431334126523e7e1d042f95365970f92cfdcc3fc5b0c"
    },
    "tools/verify_versioned_typed_sources.py": {
        "git_blob": "0530ca77179b63d02f784e0a26a3f3281d04f7a3",
        "sha256": "193c3b7d82410b0eb792894eb535940bcbce3200bda4363c1ea0a85a79e1aff8"
    }
}
CONTEXT_GUARD = '            if units[path].package.root != pkg.root:\n                fail("E_MODULE_PACKAGE_CONTEXT", "Module " + str(path) + " is imported under conflicting package roots: "\n                     + str(units[path].package.root) + " and " + str(pkg.root), span)\n'

def verify_context_composition(root):
    originals = {}
    for path, expected in CONTEXT_ORIGINALS.items():
        data = (root / 'tools/typed_context_origins' / path).read_bytes()
        if identity(data) != expected:
            raise ValueError('Changed exact #719 origin: ' + path)
        originals[path] = data
    current = (root / 'hepta/modules.py').read_bytes()
    if current.count(CONTEXT_GUARD.encode()) != 1 or current.replace(CONTEXT_GUARD.encode(), b'', 1) != originals['hepta/modules.py']:
        raise ValueError('Module context correction is not the exact reversible guard')
    store = 'tools/store_adt_source_origins.json'
    typed = 'tools/typed_stdlib_components.json'
    versioned = 'tools/versioned_typed_components.json'
    expected = copy.deepcopy(json.loads(originals[store]))
    expected['unchanged_parent_inputs']['hepta/modules.py'] = identity(current)['sha256']
    if json.loads((root / store).read_bytes()) != expected:
        raise ValueError('Store context adaptation exceeds one identity')
    expected = copy.deepcopy(json.loads(originals[typed]))
    for path in ('hepta/modules.py', store):
        expected['unchanged_base'][path] = identity((root / path).read_bytes())
    if json.loads((root / typed).read_bytes()) != expected:
        raise ValueError('Typed context adaptation exceeds two identities')
    expected = copy.deepcopy(json.loads(originals[versioned]))
    for path in (store, typed):
        expected['adaptations'][path] = identity((root / path).read_bytes())
    if json.loads((root / versioned).read_bytes()) != expected:
        raise ValueError('Versioned context adaptation exceeds two identities')
    return originals

def verify(root=ROOT):
    verify_fixture_repairs(root)
    verify_context_composition(root)
    doc=json.loads((root/'tools/versioned_typed_components.json').read_bytes())
    if doc['parent']!=PARENT or doc['supplier']!=SUPPLIER:raise ValueError('Unexpected exact suppliers')
    if len(doc['parent_files'])!=281 or len(doc['supplier_files'])!=12:raise ValueError('Incomplete exact-source inventories')
    replaced={'hepta/cli.py','hepta/packages.py'}
    adapted={'tools/store_adt_source_origins.json','tools/typed_stdlib_components.json'}
    if set(doc['originals'])!=replaced|adapted or set(doc['adaptations'])!=adapted:raise ValueError('Unexpected adaptations')
    def check(path,expected):
        data=project_original(path,(root/path).read_bytes(),root)
        if path=='hepta/modules.py':data=data.replace(CONTEXT_GUARD.encode(),b'',1)
        if identity(data)!=expected:raise ValueError('Changed source: '+path)
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
    expected['unchanged_parent_inputs']['hepta/modules.py']=identity((root/'hepta/modules.py').read_bytes())['sha256']
    if current!=expected:raise ValueError('Store adaptation exceeds three compiler identities')
    current=json.loads((root/typed).read_bytes())
    original=json.loads((root/doc['originals'][typed]).read_bytes())
    expected=copy.deepcopy(original)
    for path in replaced|{store,'hepta/modules.py'}:expected['unchanged_base'][path]=identity((root/path).read_bytes())
    if current!=expected:raise ValueError('Typed adaptation exceeds four supplier identities')
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
    return {'complete_pass':True,'parent':PARENT,'supplier':SUPPLIER,'unchanged_parent_files':276,'guarded_parent_files':1,'supplier_files':12,'reversible_manifests':2}

if __name__=='__main__':print(json.dumps(verify(),sort_keys=True))
