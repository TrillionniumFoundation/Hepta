"""All 82 prior nominal profiles through the complete explicit importer.

Every valid JSON source is explicitly relabelled as historical nominal-v2.
The retained complete importer determines acceptance, first error, payload and
report independently. This does not grant newer profile operations to legacy.
"""
from importer_panel_support_r3 import Panel,OLD,BASE,compact
import json
import sys
sys.path.insert(0,str(BASE))
from tests.test_hia_program_composite import task_program,stored_loan_program,enum_owner_program
from tests.test_hia_composite_v6_resources import composite_bulk_program,composite_range_task_program
from tests.test_hia_core_upgrade import scalar

panel=Panel('profile-panel-r2',__file__);error=None
try:
    directory=OLD/'development/complete-profile-panel-r2'
    original=json.loads((directory/'summary.json').read_text());assert original['status']=='PASS'
    for row in original['results']:
        path=directory/row['case']/'source-document.json';doc=json.loads(path.read_bytes())
        if type(doc) is dict:doc['schema']='hepta.hia.program.v2'
        panel.run('original-'+row['case'],compact(doc))
    for name,make in [('resources-bulk',composite_bulk_program),('resources-range-task',composite_range_task_program),
                      ('stored',stored_loan_program),('enum',enum_owner_program),('task',task_program)]:
        doc=make();doc['schema']='hepta.hia.program.v2';panel.run(name,compact(doc))
    for index,value in enumerate([None,False,[],{},['hepta.hia.program.v2'],'hepta.hia.composite.v1',2]):
        doc=task_program();doc['schema']=value;panel.run('schema-value-'+str(index),compact(doc),expected_stage=(9,2))
    for index,doc in enumerate([None,False,[],{},['hepta.hia.program.v2'],scalar('hepta.hia.program.v2')]):
        panel.run('root-shape-'+str(index),compact(doc),expected_stage=(9,1))
    doc=task_program();doc['schema']='wrong';doc['receipt']={'trusted':True}
    panel.run('keys-before-version',compact(doc),expected_stage=(9,1))
    raw_cases=[b'',b'{',b'{"x":1,"x":2}',b'1.0',b'1e0',b'NaN',b'Infinity',b'"\\ud800"',
               b'"\\udc00"',b'"\\ud800x"',b'"\xff"',b'"\xed\xa0\x80"',b'{}\xff',
               b'['*65+b'0'+b']'*65,b'0'+b' '*((8<<20)),b'0'+b'\xff'*((8<<20))]
    for index,raw in enumerate(raw_cases):panel.run('raw-boundary-'+str(index),raw)
except BaseException as exc:
    error=exc;raise
finally:panel.close(error)
