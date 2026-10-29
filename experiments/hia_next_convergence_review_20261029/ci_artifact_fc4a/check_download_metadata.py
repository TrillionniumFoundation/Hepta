#!/usr/bin/env python3
"""Bind a later metadata receipt to an already-audited unchanged ZIP."""
import argparse
import hashlib
import json
from pathlib import Path

def identity(path):
    path=Path(path);h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1048576),b''):h.update(chunk)
    return {'path':str(path),'bytes':path.stat().st_size,'sha256':h.hexdigest()}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['review','metadata','archive','output']:p.add_argument('--'+name,required=True)
    a=p.parse_args();review=json.loads(Path(a.review).read_text());metadata=json.loads(Path(a.metadata).read_text());actual=identity(a.archive)
    assert review['passed'] is True and actual==review['broad_archive']
    art=metadata['artifact']
    assert actual['bytes']==metadata['downloaded_bytes']==art['size_in_bytes']
    assert actual['sha256']==metadata['downloaded_sha256'] and art['digest']=='sha256:'+actual['sha256']
    assert metadata['metadata_digest_matches'] is True and art['workflow_run']['head_sha']==review['source_public_commit']
    if 'tree' in metadata:assert metadata['tree']==review['expected_tree']
    record={'schema':'hepta.ci.additional-artifact-metadata-review.v1','passed':True,'main_review':identity(a.review),'metadata_receipt':identity(a.metadata),'archive':actual,'artifact_id':art['id'],'workflow_run_id':art['workflow_run']['id'],'source_public_commit':art['workflow_run']['head_sha'],'script':identity(__file__),'archive_reexecuted':False,'native_model_tokenizer_compiler_tests_invoked':False,'network_requested':False,'signed_url_copied':False}
    Path(a.output).write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'passed':True,'artifact_id':record['artifact_id'],'workflow_run_id':record['workflow_run_id'],'output':a.output}))

if __name__=='__main__':main()
