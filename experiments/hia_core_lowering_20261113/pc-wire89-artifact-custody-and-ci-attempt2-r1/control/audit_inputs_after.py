import json,sys;from pathlib import Path
root=Path("/home/qq/hia-rewrite-20261113-e26e-r1/pc-wire89-failure-artifact-r1");sys.path.insert(0,str(root/'control'));import source_common as c
q=json.loads((root/'REQUEST.json').read_bytes());rows=[]
for expected in q['inputs']:
 raw,observed=c.read_regular(expected['path'],expected);rows.append(observed)
c.save_json(root/'custody/INPUTS-AFTER-INDEPENDENT.json',{'status':'ALL_FIVE_FROZEN_INPUTS_EXACT','inputs':rows,'reader_r1_note':'The prior independent auditor evaluated equality without assert in its final five-input loop. Its full ZIP/39 selected/B3/compile assertions executed. This supplementary reader enforces the five exact nine-field input pins; original receiver launcher had already enforced them before and after. No product or GET repeated.'})
print(json.dumps({'status':'PASS','inputs':len(rows),'network_GETs':0,'product_runs':0}))
