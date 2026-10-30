from __future__ import annotations
import collections,hashlib,json,pathlib,posixpath,tarfile,time
ROOT=pathlib.Path('/workspace/scratch/5567a9db5cf4/hepta-work')
ARCHIVE=pathlib.Path('/tmp/hepta-agent-round4-models/llama-b11669-bin-ubuntu-x64.tar.gz')
RUNNER=ROOT/'experiments/hia_agent_assembly_recovery_20261030/run_recovery.py'
protocol=json.loads((ROOT/'experiments/hia_agent_assembly_v4_20261030/PROTOCOL.json').read_bytes())
expected=protocol['runtime']
started=time.monotonic_ns()
with ARCHIVE.open('rb') as stream: archive_sha=hashlib.file_digest(stream,'sha256').hexdigest()
actual={'path':str(ARCHIVE),'bytes':ARCHIVE.stat().st_size,'sha256':archive_sha}
rows=[];names={};errors=[];total=0
# data_filter is a metadata/path check only; no destination is created and no
# extract/extractall/extractfile call is made.
destination=pathlib.Path('/tmp/hepta-b11669-header-check-never-extracted-'+archive_sha[:16])
if destination.exists(): raise ValueError('The audit-only destination unexpectedly exists')
with tarfile.open(ARCHIVE,'r:gz') as archive:
    for member in archive:
        if len(rows)>=512: raise ValueError('Member limit exceeded during actual header audit')
        normalized=str(pathlib.PurePosixPath(member.name))
        kind=('regular' if member.isfile() else 'directory' if member.isdir() else 'symlink' if member.issym() else 'hardlink' if member.islnk() else 'other')
        entry={'name':member.name,'normalized_name':normalized,'type':kind,'size':member.size,'linkname':member.linkname or None,'mode':member.mode}
        if normalized in names:errors.append({'name':member.name,'reason':'duplicate normalized member'})
        path=pathlib.PurePosixPath(member.name)
        if path.is_absolute() or '..' in path.parts or len(member.name)>1024:errors.append({'name':member.name,'reason':'unsafe member path'})
        if kind=='other':errors.append({'name':member.name,'reason':'unsupported special member'})
        if kind=='regular':
            total+=member.size
            if not 0<=member.size<=128*1024**2 or total>512*1024**2:errors.append({'name':member.name,'reason':'expanded bytes exceed frozen bound'})
        try:
            tarfile.data_filter(member,str(destination));entry['metadata_data_filter_passed']=True
        except Exception as error:
            entry['metadata_data_filter_passed']=False;errors.append({'name':member.name,'reason':type(error).__name__+': '+str(error)})
        names[normalized]=entry;rows.append(entry)
def resolve_member(name):
    current=posixpath.normpath(name);visited=[]
    for _ in range(513):
        if current.startswith('/') or current=='..' or current.startswith('../'):raise ValueError('link escapes the archive root')
        parts=pathlib.PurePosixPath(current).parts;rewritten=False
        for index in range(1,len(parts)+1):
            prefix='/'.join(parts[:index]);entry=names.get(prefix)
            if entry is None: continue
            if entry['type'] in {'symlink','hardlink'}:
                key=(prefix,current)
                if key in visited:raise ValueError('link cycle')
                visited.append(key)
                target=entry['linkname']
                if target.startswith('/'):raise ValueError('absolute archive link')
                anchor=posixpath.dirname(prefix) if entry['type']=='symlink' else ''
                current=posixpath.normpath(posixpath.join(anchor,target,*parts[index:]))
                rewritten=True;break
        if rewritten:continue
        final=names.get(current)
        if final is None:raise ValueError('link target not found in archive members')
        return current,final['type']
    raise ValueError('link resolution exceeded header bound')
links=[]
for entry in rows:
    if entry['type'] in {'symlink','hardlink'}:
        try:
            target,kind=resolve_member(entry['normalized_name'])
            links.append({'name':entry['name'],'type':entry['type'],'linkname':entry['linkname'],'resolved_member':target,'resolved_type':kind,'resolves_inside_to_regular_file':kind=='regular'})
            if kind!='regular':errors.append({'name':entry['name'],'reason':'link did not resolve to an internal regular file'})
        except Exception as error:
            links.append({'name':entry['name'],'type':entry['type'],'linkname':entry['linkname'],'error':str(error)})
            errors.append({'name':entry['name'],'reason':'logical link check: '+str(error)})
server_candidates=[]
for entry in rows:
    if pathlib.PurePosixPath(entry['normalized_name']).name=='llama-server' and entry['type'] in {'regular','symlink','hardlink'}:
        final,kind=resolve_member(entry['normalized_name'])
        if kind=='regular':server_candidates.append({'name':entry['name'],'resolved_regular_member':final})
archive_matches=(actual['bytes'],actual['sha256'])==(expected['bytes'],expected['sha256'])
counts=dict(collections.Counter(entry['type'] for entry in rows))
report={'schema':'hepta.actual.fixed-runtime-archive.header-audit.v1','archive':actual,'expected_runtime':expected,'archive_matches_registered_bytes':archive_matches,'reviewed_runner_sha256':hashlib.sha256(RUNNER.read_bytes()).hexdigest(),'reviewed_runner_accepts_internal_symlink_and_hardlink':True,'frozen_limits':{'members':512,'per_regular_file_bytes':128*1024**2,'total_regular_file_bytes':512*1024**2},'member_count':len(rows),'member_type_counts':counts,'total_regular_file_bytes':total,'largest_regular_file_bytes':max((row['size'] for row in rows if row['type']=='regular'),default=0),'unique_llama_server_candidates':server_candidates,'links':links,'members':rows,'errors':errors,'header_and_internal_link_metadata_compatible_with_current_frozen_extract_runtime':archive_matches and not errors and len(server_candidates)==1,'compatible_with_hypothetical_policy_rejecting_every_symlink_or_hardlink':not links and archive_matches and not errors and len(server_candidates)==1,'runtime_archive_was_extracted':False,'runtime_content_executed':False,'downloaded_new_bytes':False,'frozen_source_modified':False,'destination_created':destination.exists(),'scope':'Read-only SHA and actual logical tar member audit. No member payload is extracted or executed. Internal link graph checks complement tarfile.data_filter metadata checks; this does not claim successful future VM execution, loader compatibility, filesystem extraction or runtime qualification.','wall_ns':time.monotonic_ns()-started}
out=pathlib.Path('/tmp/hepta-b11669-runtime-members-01.json')
with out.open('x') as stream:json.dump(report,stream,indent=2,sort_keys=True);stream.write('\n')
print(json.dumps({key:report[key] for key in ('archive_matches_registered_bytes','reviewed_runner_sha256','member_count','member_type_counts','total_regular_file_bytes','largest_regular_file_bytes','header_and_internal_link_metadata_compatible_with_current_frozen_extract_runtime','compatible_with_hypothetical_policy_rejecting_every_symlink_or_hardlink','errors','links','wall_ns')},indent=2))
print(str(out))
