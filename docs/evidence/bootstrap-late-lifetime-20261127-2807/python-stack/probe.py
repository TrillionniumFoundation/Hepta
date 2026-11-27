from pathlib import Path
import hashlib,sys,types,json,os
root=Path('/home/qian-qi/hia-bootstrap-closure-20261127-2807/src')
os.chdir(root);sys.path.insert(0,str(root))
raw=(root/'tests/hia_service_bootstrap_observer.py').read_bytes()
assert hashlib.sha256(raw).hexdigest()=='2957afe47b6e28dcf0cf38199f8a418a0a7ed73a30c6657743257e5c206085f7'
source=raw.decode()
old='    def late_sink(row):\n        late_stream.write(oracle.canonical(row)+b"\\n")\n'
new='''    diagnostic_stack_stream = output_stream(output/"diagnostic-late-stack.jsonl")
    def late_sink(row):
        late_stream.write(oracle.canonical(row)+b"\\n")
        frame = sys._getframe()
        stack = []
        while frame is not None:
            stack.append({"filename":frame.f_code.co_filename,"function":frame.f_code.co_name,
                          "line":frame.f_lineno,"lasti":frame.f_lasti})
            frame = frame.f_back
        diagnostic_stack_stream.write(oracle.canonical(
            {"row":row,"during_case":current_id,"stack":stack})+b"\\n")
        del frame, stack
'''
changes=((old,new),
 ('"schema":SCHEMA, **support.child_identity(), "lane":lane,','"schema":"hepta.hia.bootstrap-late-stack-diagnostic.v1", **support.child_identity(), "lane":lane,'),
 ('"count":len(done),"ordered_ids":done,"differences":difference_count,','"count":len(done),"ordered_ids":done,"differences":difference_count,"diagnostic_only":True,'),
 ('"status":("CHECKPOINT_ORIGINAL_COMPLETE" if lane=="original" else "CHECKPOINT_CANDIDATE_COMPLETE") if passed else "HOLD",','"status":"DIAGNOSTIC_OBSERVATIONS_COMPLETE" if passed else "HOLD",'))
for old,new in changes:
 assert source.count(old)==1,old
 source=source.replace(old,new,1)
module=types.ModuleType('bootstrap_late_stack_diagnostic')
module.__file__=str(root/'tests/hia_service_bootstrap_observer.py');module.__package__=''
sys.modules[module.__name__]=module
exec(compile(source,'<explicit-external-late-stack-diagnostic>','exec'),module.__dict__)
authority=Path('/run/media/qian-qi/TOSHIBA_DEV_1TB/hia-bootstrap-closure-20261127-2807/isolated-current-v2-full-unselected/originals/authority.json')
pin={'bytes':1055368,'sha256':'1f2f0d06bc4f2a70ec1cac139dee075c2ce9ac62f885b80f1bde1fab9bb50f53'}
lane=sys.argv[1]
raise SystemExit(module.run(lane,authority.parent/'complete-inputs.json',Path(sys.argv[2]),expected=None if lane=='original' else authority,expected_pin=None if lane=='original' else pin))
