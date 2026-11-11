import sys,runpy
from pathlib import Path
f=Path('/tmp/hia-artifact-page-draft')
for name,adapter,expect in [('original','hia_artifact_page_native_before_step_close.py','observe'),('candidate','hia_artifact_page_native.py','fixed')]:
 sys.argv=[str(f/'protocol_boundary_controls.py'),'--source-root','/workspace/scratch/e26ed3e2edcf/hia-native-machine-plan','--wire-manifest','/workspace/scratch/e26ed3e2edcf/wire-entry-development-r1/manifest.json','--adapter',str(f/adapter),'--output',str(f/'lifecycle-controls-r3'/('protocol-'+name+'.json')),'--expect',expect]
 try:runpy.run_path(sys.argv[0],run_name='__main__')
 except SystemExit as e:
  if e.code not in (None,0):raise
