"""Exact-source union of the inherited typed and package inventories plus migration."""
import hashlib,json,os,platform,subprocess,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests'),str(ROOT/'tools')]

def identity():
    return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(ROOT.rglob('*')) if p.is_file() and '__pycache__' not in p.parts and '.git' not in p.parts and p.suffix!='.pyc'}

def main():
    if not __debug__:raise SystemExit('Assertions must remain enabled')
    if sys.argv[1:] not in ([],['--verify-only']):raise SystemExit('Expected no arguments or --verify-only')
    backend=os.environ.get('HEPTA_VERSIONED_TYPED_BACKEND','c')
    if backend not in ('c','rust'):raise SystemExit('Select c or rust')
    for key in ['HEPTA_TYPED_STDLIB_BACKEND','HEPTA_PACKAGE_TEST_BACKEND','HEPTA_BYTES_BACKEND','HEPTA_ORDERING_BACKEND','HEPTA_UTF8_BACKEND','HEPTA_BASE64_BACKEND']:
        if key in os.environ and os.environ[key]!=backend:raise SystemExit('Conflicting backend '+key)
        os.environ[key]=backend
    os.environ['PYTHONDONTWRITEBYTECODE']='1';os.environ['PYTHONPATH']=str(ROOT);os.chdir(ROOT)
    from verify_versioned_typed_sources import verify
    provenance=verify()
    import qualify_typed_stdlib as typed
    tracking=typed.tracking
    if typed.inherited.RUST_REQUIRED or backend=='rust':
        import shutil
        from hepta.backend import find_rustc,toolchain_info
        toolchain=toolchain_info(find_rustc());selected=shutil.which(os.environ.get('RUSTC','rustc'));actual=shutil.which('rustc')
        if not selected or not actual or Path(selected).resolve()!=Path(actual).resolve():raise SystemExit('Selected Rust must be actual pinned compiler on PATH')
        if not subprocess.check_output([selected,'--version'],text=True).startswith('rustc 1.90.0 '):raise SystemExit('Expected pinned Rust 1.90.0')
    else:
        cc=os.environ.get('CC','gcc');toolchain={'requested':cc,'version':subprocess.check_output([cc,'--version'],text=True)}
    rust=typed.inherited.RUST_REQUIRED
    inherited=json.loads((ROOT/'tools'/('typed_stdlib_rust_inventory.json' if rust else 'typed_stdlib_inventory.json')).read_bytes())
    packages=json.loads((ROOT/'tests/package_integration_inventory.json').read_bytes())
    joint=json.loads((ROOT/'tools/versioned_typed_inventory.json').read_bytes())
    package_discovered=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(n) for n in ['tests.test_package_resolution','tests.test_lock_diff','tests.test_package_integration'])
    if [t.id() for t in tracking.flatten(package_discovered)]!=packages[:56]:raise SystemExit('Full resolver/diff/integration discovery mismatch')
    suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromName(n) for n in typed.MODULES)
    suite.addTests(unittest.defaultTestLoader.loadTestsFromNames(packages))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromName('test_versioned_typed'))
    planned=[t.id() for t in tracking.flatten(suite)]
    expected=inherited+packages+joint;count=495 if rust else 487
    if len(inherited)!=(418 if rust else 410) or len(packages)!=65 or len(joint)!=12 or len(set(expected))!=count or expected!=planned:raise SystemExit('Exact union method inventory mismatch')
    if sys.argv[1:]==['--verify-only']:
        print('VERSIONED_TYPED_PREFLIGHT '+json.dumps({'methods':count,'provenance':provenance,'execution':False}));return
    before=identity()
    print('VERSIONED_TYPED_IDENTITY '+json.dumps({'python':sys.version,'platform':platform.platform(),'backend':backend,'toolchain':toolchain,'source_sha256':before,'provenance':provenance},sort_keys=True),flush=True)
    result=unittest.TextTestRunner(verbosity=2,resultclass=tracking.TrackedResult).run(suite)
    good=(result.wasSuccessful() and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses and planned==result.started==result.finished==result.passed and before==identity())
    print('VERSIONED_TYPED_METHODS '+json.dumps({'planned':planned,'started':result.started,'finished':result.finished,'passed':result.passed,'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),'complete_pass':good},sort_keys=True),flush=True)
    if not good:raise SystemExit('Strict union method/source gate failed')
    scripts=['tools/qualify_c_float_int_oracle.py','tools/qualify_c_numeric_adt_oracle.py','tools/qualify_c_array_adt_oracle.py','tools/qualify_c_store_adt_oracle.py','tests/stdlib_bytes_boundary_oracle.py','tests/stdlib_ordering_oracle.py','tools/stdlib_utf8_oracle.py','tools/stdlib_base64_oracle.py','tools/typed_stdlib_oracle.py']
    for script in scripts:subprocess.run([sys.executable,'-B',script],check=True)
    for module in ['tests.package_resolution_oracle','tests.lock_diff_graph_oracle','tests.package_integration_oracle']:subprocess.run([sys.executable,'-B','-m',module],check=True)
    subprocess.run([sys.executable,'-B','tools/versioned_typed_oracle.py','--root',str(ROOT),'--native'],check=True)
    if before!=identity():raise SystemExit('Source changed during oracles')
    print('VERSIONED_TYPED_PASS '+json.dumps({'methods':count,'oracle_scripts':13,'backend':backend,'source_unchanged':True,'whole_project_blockers_closed':False}),flush=True)
if __name__=='__main__':main()
