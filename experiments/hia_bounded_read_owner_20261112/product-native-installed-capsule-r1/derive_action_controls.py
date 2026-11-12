"""Build new controls from retained successful originals; no product execution."""
import ast
from hashlib import sha1, sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'control'
SOURCE = Path('/workspace/scratch/hia-bounded-product-v80-20261112-r2/checkout')
PREFIX = 'experiments/hia_bounded_read_owner_20261112/product-native-installed-capsule-r1'
CANDIDATE = 'ba714f34b8dcb248c779bb5fc0b9538d9151c685'
TREE = '3489d2047956c1481b2e0593e2fbd32cf273cc70'
TRIGGER = 'codex/hia-bounded-read-v80-native-installed-r1-run-20261112-e26e'
WORK_ROOT = 'hia-bounded-read-v80-native-installed-r1'
NAMES = sorted(['actions_custody.py','actions_verify.py','control-manifest.json','controller.py',
    'diagnostic-targets.json','diagnostics.py','git_binding.py','guardian.py','installed_cases.py',
    'native_driver.py','native_support.py','package_helper.py','prepare_native.py',
    'process_owner_impl.py','source-manifest.json','source_common.py'])

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2)+'\n').encode()

def pin(raw):
    return {'bytes':len(raw),'sha256':sha256(raw).hexdigest(),
            'git_blob_sha1':sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

targets=[]
def add(name,location='root'):
    if any(row['name']==name for row in targets):
        return
    targets.append({'name':name,'location':location})

# Ordered whole-file priorities. Missing/omitted records remain in the index;
# the full closed-process archive retains every original regular file.
for name in ('setup.json','context.json','guard/request.json','guard/guardian.json',
    'GENERATED-SOURCE-AT-TERMINAL.hiaasm','SOURCE-ABI-AT-TERMINAL.json',
    'FINAL.json','evidence/report.json','evidence/finite/acceptance.json',
    'evidence/installation/installed-cases.json','evidence/compiler/report.json',
    'evidence/finite/work/build/manifest.json','evidence/finite/work/build/build.json',
    'evidence/finite/work/original-eight/report.json','evidence/finite/work/original-eight/unittest.log',
    'evidence/installation/package-report.json','evidence/installation/installed-request.json',
    'TERMINAL-ORIGINALS.json','EVIDENCE-INVENTORY.json','public/CUSTODY.json',
    'guard/child.stdout.log','guard/child.stderr.log'):
    add(name)

for group in ('reject','lifetime','permission','filesystem'):
    add('evidence/finite/work/'+group+'/report.json')
for base, labels in (
    ('evidence/processes',('fresh-compiler','finite-gate')),
    ('evidence/finite',('validation',)),
    ('evidence/finite/work',('build','reject','lifetime','permission','filesystem','original-eight')),
    ('evidence/installation',('packaging-tools','sdist','wheel','install','installed-child'))):
    for label in labels:
        for suffix in ('.process-owner.json','.process-owner.json.request.json','.stdout.log','.stderr.log',
                       '.process-owner.json.stdout.log','.process-owner.json.stderr.log','.step.json'):
            add(base+'/'+label+suffix)
for base,labels in (('evidence/compiler',('B1','B2')),
                    ('evidence/finite/work/build',('bounded-read',))):
    for label in labels:
        for suffix in ('.receipt.json','.request.json','.stdout.log','.stderr.log','.input.bin','.output.bin','.image.bin'):
            add(base+'/'+label+suffix)
for name in ('B0.receipt.json','B0.so','linker-version.stdout.log','linker-version.stderr.log',
             'bounded-read.hiaasm','source-entry-abi.json','bounded-read.hia.json',
             'source-before.json','source-after.json'):
    add('evidence/compiler/'+name)
for name in ('source-before.json','source-after.json'):
    add('evidence/'+name)
pop=json.loads((SOURCE/'tools/hia_bounded_read_checks/populations.json').read_bytes())
for group in pop['groups']:
    if group['name']!='original-eight':
        for name in group['expected_ids']:
            add('evidence/finite/work/'+group['name']+'/'+name+'.json')
for name in ('child-policy.json','parent-original.json'):
    add('evidence/finite/work/original-eight/'+name)
for phase in ('prepare','run','finalize'):
    for stream in ('stdout','stderr'):
        add('stage/'+phase+'.'+stream+'.log','stage')
targets_value={'schema':'hepta.hia.bounded-read-small-targets.v1','targets':targets,
    'whole_file_selection_only':True,'complete_artifact_transport_claimed':False,
    'dynamic_PID_CLI_originals':'Retained in typed archive and independently verified as seven exact start/completion pairs; names are not fabricated before the run.',
    'raw_limit':512<<10,'stdout_limit':1<<20,'index_limit':64<<10}
(OUT/'diagnostic-targets.json').write_bytes(wire(targets_value))

for filename in ('controller.py','diagnostics.py'):
    text=(ROOT/'references'/filename).read_text()
    substitutions={
        "experiments/hia_bounded_read_owner_20261112/actions-native-development-r2":PREFIX,
        '0e36619bc65ada7072c1e8a1f1454728036fee4e':CANDIDATE,
        '1d95802c453a006f077eb8735a6939b1957d500b':TREE,
        'codex/hia-bounded-read-native-r4b-run-r2-20261112-e26e':TRIGGER,
        'hia-bounded-read-native-r4b-development-r2':WORK_ROOT,
        "'leaves': 4025":"'leaves': 4051",
        "'candidate_leaves': 4025":"'candidate_leaves': 4051",
        'hia.bounded-read-actions-policy.v1':'hia.bounded-read-product-install-actions-policy.v1',
    }
    for old,new in substitutions.items():
        if filename == 'diagnostics.py' and old == "'candidate_leaves': 4025":
            assert old not in text
            continue
        assert old in text,(filename,old)
        text=text.replace(old,new)
    lines=text.splitlines(keepends=True)
    assert len([x for x in lines if x.startswith('CONTROL_NAMES = ')])==1
    text=''.join('CONTROL_NAMES = set('+repr(NAMES)+')\n' if line.startswith('CONTROL_NAMES = ') else line
                 for line in lines)
    if filename=='controller.py':
        text=text.replace("and policy['fresh_B0_B1_B2'] is True and policy['cold_qualification'] is False,",
            "and policy['fresh_B0_B1_B2'] is True and policy['cold_qualification'] is False\n"
            "            and policy['installed_cases'] == 9 and policy['installed_native_reads'] == 7\n"
            "            and policy['installed_child_seconds'] == 5 and policy['source_resources'] == 105\n"
            "            and policy['source_Python_modules'] == 170,")
        text=text.replace("'installed_qualification_requested': False,", 
            "'development_installation_requested': True, 'installed_case_methods': 9,\n"
            "        'general_installed_resource_suite_requested': False, 'installed_qualification_requested': False,")
        text=text.replace('FINITE_NATIVE_DEVELOPMENT_NOT_COLD_OR_FULL_DOMAIN_QUALIFICATION',
                          'FINITE_NATIVE_AND_OFFLINE_INSTALL_DEVELOPMENT_NOT_COLD_OR_FULL_DOMAIN')
        text=text.replace('BOUNDED_READ_FINITE_NATIVE_ACTIONS_DEVELOPMENT_PASS',
                          'BOUNDED_READ_NATIVE_AND_INSTALL_ACTIONS_DEVELOPMENT_PASS')
    else:
        text=text.replace(" and policy['diagnostic_targets'] == 133", " and policy['diagnostic_targets'] == "+str(len(targets)))
        text=text.replace("== 133", "== "+str(len(targets)))
        text=text.replace("'fixed_targets': 133", "'fixed_targets': "+str(len(targets)))
        text=text.replace('complete fixed 133 diagnostic population differs',
                          'complete fixed '+str(len(targets))+' diagnostic population differs')
        text=text.replace("'all_133_originals_transported'", "'all_fixed_originals_transported'")
    ast.parse(text,filename=filename)
    (OUT/filename).write_text(text)

custody=(ROOT/'references/actions_custody.py').read_text()
start=custody.index('    names = [',custody.index('def capture_terminal'))
end=custody.index('    records, errors = [], []',start)
custody=custody[:start]+'''    import json
    target_raw, _ = read(root / "control/diagnostic-targets.json", 1 << 20)
    target_plan = json.loads(target_raw)
    names = [row["name"].removeprefix("evidence/") for row in target_plan["targets"]
             if row["location"] == "root" and row["name"].startswith("evidence/")]
    require(len(names) == len(set(names)) and names, "fixed terminal source population differs")
'''+custody[end:]
needle='    inventory = None\n'
assert custody.count(needle)==1
custody=custody.replace(needle,'''    abi = None
    try:
        raw, record = read(source / "hepta/hia_bounded_read_abi.json", 16384)
        abi = {"source": record, "copy": create(root / "SOURCE-ABI-AT-TERMINAL.json", raw)}
    except FileNotFoundError:
        abi = {"missing": True}
    except BaseException as error:
        errors.append({"phase": "source_owned_ABI_original", "type": type(error).__name__,
                       "traceback": traceback.format_exc()})
    inventory = None
''')
custody=custody.replace('"errors": errors, "typed_evidence_inventory": inventory, "generated_source_original": generated,',
    '"errors": errors, "typed_evidence_inventory": inventory, "generated_source_original": generated,\n'
    '              "source_owned_ABI_original": abi,')
ast.parse(custody)
(OUT/'actions_custody.py').write_text(custody)

# Every declared owner input in the product builder must be present; this
# restricted AST evaluator reads literal strings/one known prefix, not code.
build=ast.parse((SOURCE/'tools/build_hia_bounded_read.py').read_bytes())
node=next(n.value for n in build.body if isinstance(n,ast.Assign)
    and any(isinstance(t,ast.Name) and t.id=='OWNED_SOURCE_FILES' for t in n.targets))
def literal(n):
    if isinstance(n,ast.Constant) and type(n.value) is str:return n.value
    if isinstance(n,ast.Name) and n.id=='CHECK_ROOT':return 'tools/hia_bounded_read_checks'
    if isinstance(n,ast.Name) and n.id=='SOURCE':return 'examples/hia_bootstrap/bounded_read.hiaasm'
    if isinstance(n,ast.Name) and n.id=='ABI':return 'hepta/hia_bounded_read_abi.json'
    if isinstance(n,ast.BinOp) and isinstance(n.op,ast.Add):return literal(n.left)+literal(n.right)
    if isinstance(n,ast.Tuple):return tuple(literal(x) for x in n.elts)
    raise ValueError(ast.dump(n))
owned=literal(node)
verify=(OUT/'actions_verify.py').read_text()
anchor='    for name, digest in build["owned_source_sha256"].items():\n'
assert verify.count(anchor)==1
verify=verify.replace(anchor,'    require(set(build["owned_source_sha256"]) == set('+repr(owned)+'),\n'
    '            "complete owned build input population differs")\n'+anchor)
(OUT/'actions_verify.py').write_text(verify)
print(json.dumps({'diagnostic_targets':len(targets),'control_members':len(NAMES),'owned_build_inputs':len(owned)}))
