"""Exact installed-resource successor history and independently declared domains."""
from functools import lru_cache
from hashlib import sha256
import ast
import json
from pathlib import Path

PATH='tests/test_hia_agent_installed_resources.py'
FIXTURE='tests/fixtures/hia_installed_resource_successors.json'
FIXTURE_SHA256='1e67761e9fe72cdb4dba0c725de8b40ca980712406170d07a44358cf24b0319a'

# These declarations were reviewed from their source producers, independently of
# the failed/rebuilt wheel. Keep them explicit so an added packaged member cannot
# silently become its own expected inventory.
NOMINAL_RESOURCES=(
    'examples/hia_bootstrap/core_nominal_report_json.hepta',
    'examples/hia_bootstrap/core_edit/publication_frontend.hepta',
    'examples/hia_bootstrap/core_edit/publication_program.hepta',
    'examples/hia_bootstrap/core_edit/publication_policy.hepta',
    'examples/hia_bootstrap/core_edit/publication_render.hepta',
    'examples/hia_bootstrap/core_edit/publication_assembly.hepta',
    'examples/hia_bootstrap/elf_static_linker.hepta',
    'examples/hia_bootstrap/nominal_constructor_transport_adapters.hepta',
    'examples/hia_bootstrap/nominal_constructor_transport_tail.hepta',
    'examples/hia_bootstrap/nominal_constructor_publication_adapters.hepta',
)
NDU_RESOURCES=(
    'examples/hia_bootstrap/ndu_scalar.hepta',
    'examples/hia_bootstrap/ndu_scalar_packer.hepta',
    'tools/generate_hia_ndu_scalar.py',
    'tools/generate_hia_ndu_scalar_packer.py',
    'tools/hia_ndu_scalar_syscalls.S',
    'tools/build_hia_ndu_scalar.py',
    'tools/generate_hia_sha256.py',
    'tools/generate_hia_native_filter.py',
    'tools/build_hia_default_release.py',
    'tools/hia_wheel_backend.py',
    'hepta/hia_ndu_native.py',
    'hepta/hia_ndu_optimizer.py',
    'hepta/hia_agent_macro_policy.py',
    'hepta/hia_ndu_prepared_ranker.py',
    'hepta/hia_ndu_persistent_ranker.py',
    'tests/test_hia_ndu_scalar_native.py',
)
ASSEMBLY_RESOURCES=(
    'native/default/cli/assembly-render.bin',
    'native/default/cli/assembly-syntax.bin',
    'native/default/cli/assembly-diagnostic.bin',
)
SOURCE_RESOURCES=NOMINAL_RESOURCES+NDU_RESOURCES

def pin(raw):
    return {'bytes':len(raw),'sha256':sha256(raw).hexdigest()}

@lru_cache(maxsize=1)
def _parse(raw):
    if sha256(raw).hexdigest()!=FIXTURE_SHA256:
        raise ValueError('complete installed-resource history differs')
    value=json.loads(raw)
    if value['path']!=PATH or value['schema']!='hepta.hia.installed-resource-successors.v1':
        raise ValueError('invalid installed-resource successor schema')
    names=value['legacy_domain']['names']
    if len(names)!=261 or names!=sorted(set(names)):
        raise ValueError('the full original 261-resource domain differs')
    return value

def records(root=None):
    root=Path(root) if root is not None else Path(__file__).resolve().parents[1]
    return _parse((root/FIXTURE).read_bytes())

def _reverse(data,record):
    if pin(data)!=record['current']:
        raise ValueError('installed-resource successor is not the complete reviewed file')
    original=bytearray()
    end=0
    for change in record['splices']:
        start=change['offset'];before=change['before'].encode();after=change['after'].encode()
        current=end+start-len(original)
        if start<len(original) or data[current:current+len(after)]!=after:
            raise ValueError('installed-resource successor differs at its reviewed splice')
        original.extend(data[end:current]);original.extend(before)
        end=current+len(after)
    original.extend(data[end:])
    original=bytes(original)
    if pin(original)!=record['original']:
        raise ValueError('complete prior installed-resource test differs')
    forward=original
    for change in reversed(record['splices']):
        at=change['offset'];before=change['before'].encode();after=change['after'].encode()
        if forward[at:at+len(before)]!=before:
            raise ValueError('installed-resource forward splice differs')
        forward=forward[:at]+after+forward[at+len(before):]
    if forward!=data:
        raise ValueError('complete installed-resource forward replay differs')
    return original

def reference_source(name,data):
    """Return only exact reviewed successors to the original reference layer."""
    if name!=PATH:return data
    fixture=records()
    original_input=data
    relations=fixture['relations']
    accepted={record['current']['sha256'] for record in relations}
    if sha256(data).hexdigest() not in accepted:return data
    for record in reversed(relations):
        if pin(data)==record['current']:
            data=_reverse(data,record)
    if pin(data)!=fixture['reference_current']:
        raise ValueError('installed-resource source did not reach the exact reference predecessor')
    if data==original_input:
        raise ValueError('installed-resource successor was not replayed')
    return data

def _literal(root,name,symbol):
    tree=ast.parse((Path(root)/name).read_bytes())
    nodes=[node for node in tree.body if isinstance(node,ast.Assign)
        and any(isinstance(target,ast.Name) and target.id==symbol for target in node.targets)]
    if len(nodes)!=1:raise ValueError('one reviewed resource declaration is required: '+symbol)
    return ast.literal_eval(nodes[0].value)

def declared_resources(root):
    root=Path(root)
    if _literal(root,'hepta/hia_nominal_program_native.py','PACKAGE_RESOURCES')!=NOMINAL_RESOURCES:
        raise ValueError('nominal source resource declaration differs from reviewed ten')
    if _literal(root,'hepta/hia_ndu_native.py','SOURCES')!=NDU_RESOURCES:
        raise ValueError('NDU source custody declaration differs from reviewed sixteen')
    for symbol,resource in zip(('ASSEMBLY_RENDER_RESOURCE','ASSEMBLY_SYNTAX_RESOURCE',
                               'ASSEMBLY_DIAGNOSTIC_RESOURCE'),ASSEMBLY_RESOURCES):
        if _literal(root,'hepta/hia_default_native.py',symbol)!='_data/'+resource:
            raise ValueError('assembly resource declaration differs: '+symbol)
    # The setup hook reads the explicit nominal tuple, independently of a wheel.
    setup=ast.parse((root/'setup.py').read_bytes())
    functions=[node for node in setup.body if isinstance(node,ast.FunctionDef)
        and node.name=='nominal_program_resources']
    if len(functions)!=1:raise ValueError('one nominal packaging source hook is required')
    namespace={'ast':ast,'Path':Path,'ROOT':root}
    exec(compile(ast.Module(body=functions,type_ignores=[]),'setup.py','exec'),namespace)
    if namespace['nominal_program_resources'](())!=NOMINAL_RESOURCES:
        raise ValueError('actual source packaging hook changed the nominal domain')
    manifest=json.loads((root/'docs/HIA_SELFHOST_CORE_SUPPORT.json').read_bytes())['source_identity']['files']
    for name in SOURCE_RESOURCES:
        if sha256((root/name).read_bytes()).hexdigest()!=manifest.get(name):
            raise ValueError('reviewed resource is outside the exact source closure: '+name)
    if len(SOURCE_RESOURCES)!=26 or len(set(SOURCE_RESOURCES))!=26:
        raise ValueError('source resource extension has duplicate or missing members')
    return SOURCE_RESOURCES,ASSEMBLY_RESOURCES

def reviewed_inventory(root,legacy_expected):
    fixture=records(root)
    legacy=set(fixture['legacy_domain']['names'])
    if set(legacy_expected)!=legacy:
        raise ValueError('the independently preserved original 261-resource domain differs')
    sources,images=declared_resources(root)
    added=set(sources)|set(images)
    if len(added)!=29 or legacy&added:
        raise ValueError('reviewed resource extension overlaps or changes the original domain')
    return sources,images,legacy|added

def assembly_identity(archive):
    """Tie the three mandatory assembly resources to their original pin slots."""
    values=json.loads(archive.read('hepta/_data/native/default/full_cost/pin.json'))
    if not isinstance(values,list) or len(values)!=18:
        raise ValueError('complete cold reference pin domain differs')
    for index,resource in enumerate(ASSEMBLY_RESOURCES,15):
        raw=archive.read('hepta/_data/'+resource)
        if not raw or sha256(raw).hexdigest()!=values[index]:
            raise ValueError('installed assembly resource differs from its exact native pin')
