"""Rebuild the lease release products with actual native filter kits.

This is component construction qualification. The final HIA release owner must
still consume the emitted HIASTD01 recipe in the full release/cold gates.
"""
from pathlib import Path
import argparse,fcntl,hashlib,json,os,struct,subprocess,traceback
from tools.build_hia_source_build import _named_source_request
from tools.build_hia_native_store_release import _kit_with_objects
from tools.generate_hia_native_controller_release import BOOT,FILTER_POLICY,WIDE_FILTER
from tools import generate_hia_generation_lease_owner_packer as owner
from tools import generate_hia_generation_lease_native_release as declaration
from tools.qualify_hia_generation_lease_owner import VALUE_ROLES,VALUE_PACKER,VALUE_PROTOCOL

ROOT=Path(__file__).resolve().parents[1]
sha=lambda data:hashlib.sha256(data).hexdigest()
record=lambda data:dict(bytes=len(data),sha256=sha(data))


def main():
    ap=argparse.ArgumentParser()
    for name in ('compiler','owner-build','values','output'):
        ap.add_argument('--'+name,type=Path,required=True)
    ap.add_argument('--write-receipt',action='store_true')
    args=ap.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    report=dict(schema='hepta.hia.generation-lease-native-release-qualification.v1',
                passed=False,full_release_pass=False,production_activated=False,calls=[])
    fds=[]
    def save():
        (args.output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    def seal(name,raw):
        fd=os.memfd_create(name,os.MFD_ALLOW_SEALING);os.write(fd,raw)
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15);assert fcntl.fcntl(fd,fcntl.F_GET_SEALS)==15
        fds.append(fd);return fd
    def run(fd,argv,data):
        p=subprocess.run(['/proc/self/fd/'+str(fd),*argv],pass_fds=(fd,),input=data,
                         capture_output=True,timeout=180,env={'PATH':'','LANG':'C','LC_ALL':'C'})
        report['calls'].append(dict(image_sha256=sha(os.pread(fd,os.fstat(fd).st_size,0)),
                                   argv=argv,input_bytes=len(data),input_sha256=sha(data),
                                   returncode=p.returncode,stdout_bytes=len(p.stdout),
                                   stdout_sha256=sha(p.stdout),stderr_bytes=len(p.stderr)))
        assert p.returncode==0 and not p.stderr,(argv,p.returncode,p.stderr[:1024])
        return p.stdout
    try:
        component_raw=(args.owner_build/'qualification.json').read_bytes()
        component=json.loads(component_raw)
        assert component['schema']=='hepta.hia.generation-lease-owner.qualification.v1'
        assert component['passed'] and component['source_bound_enclosing_owner']
        assert component['build']['value_roles']==len(VALUE_ROLES)==16
        assert component['build']['value_protocol']==VALUE_PROTOCOL.decode('ascii')
        assert not component['final_aggregate_claimed'] and not component['production_activated']
        root=args.compiler.read_bytes()
        assert sha(root)==component['compiler_sha256']
        compiler=seal('lease-source-builder',root)
        imported=args.values.read_bytes()
        expected=component['build']['products']['hia-generation-lease-values.core.bin']
        assert record(imported)==expected
        future=json.loads((ROOT/'docs/HIA_NATIVE_FUTURE_RELEASE_BUILD.json').read_bytes())
        assert future['status']=='PASS','Stage 13 must finish its real Future behavior gate'
        assert future['products']['hia-result-value.core.bin']==expected
        all_rows={row['path']:row for row in component['compile']}
        images={};source_files={}
        for path,row in all_rows.items():
            raw=(ROOT/path).read_bytes()
            assert len(raw)==row['source_bytes'] and sha(raw)==row['source_sha256'],path
            flat=(args.owner_build/(Path(path).stem+'.flat')).read_bytes()
            assert len(flat)==row['flat_bytes'] and sha(flat)==row['flat_sha256'],path
            images[path]=flat;source_files[path]=record(raw)
        helper_names={FILTER_POLICY,WIDE_FILTER,'native_filter_packer.hepta','selfhost.hepta',
                      'source_release_kit.hepta','source_build_packer.hepta'}
        for name in sorted(helper_names):
            path=BOOT+name;raw=(ROOT/path).read_bytes()
            a=run(compiler,['compile'],raw);b=run(compiler,['compile'],raw);assert a==b
            images[path]=a;source_files[path]=record(raw)
            all_rows[path]=dict(path=path,source_bytes=len(raw),source_sha256=sha(raw),
                               flat_bytes=len(a),flat_sha256=sha(a),two_builds_identical=True)
        aliases=('source_build_policy.hepta','selfhost.hepta','source_build_packer.hepta')
        paths=('source_release_kit.hepta','selfhost.hepta','source_build_packer.hepta')
        sources={alias:(ROOT/BOOT/path).read_bytes() for alias,path in zip(aliases,paths,strict=True)}
        bundle=run(compiler,['sources'],_named_source_request(sources))
        composer_bytes=run(compiler,['pack'],bundle);composer=seal('lease-native-kit-composer',composer_bytes)
        kits={};kitfds={}
        for kind,application in (('small','native_filter_packer.hepta'),('wide',WIDE_FILTER)):
            paths=(FILTER_POLICY,'selfhost.hepta',application)
            sources={alias:(ROOT/BOOT/path).read_bytes() for alias,path in zip(aliases,paths,strict=True)}
            frame=run(composer,['build'],_named_source_request(sources,tag=b'HIAKOBJ1'))
            body,objects=_kit_with_objects(frame)
            for alias,path in zip(aliases,paths,strict=True):
                assert objects[alias]==images[BOOT+path]
            kits[kind]=record(body);kitfds[kind]=seal('lease-'+kind+'-filter-kit',body)
        wrappers={};wrapperfds={}
        for name,kind in (('generation_lease_owner_packer','wide'),
                          ('multiversion_runtime_linker','wide'),
                          ('generation_lease_public_lifecycle_packer','small')):
            flat=images[BOOT+name+'.hepta']
            wire=b'HIANPF01'+struct.pack('<2Q',2 if kind=='wide' else 1,len(flat))+flat
            body=run(kitfds[kind],['build'],wire)
            wrappers[name]=record(body);wrapperfds[name]=seal(name,body)
            (args.output/(name+'.filter')).write_bytes(body)
        parts=[images[BOOT+'generation_lease_owner.hepta'],
               images[BOOT+'generation_lease_public_lifecycle.hepta'],imported,
               images[BOOT+'generation_lease_typed_policy.hepta'],images[BOOT+'generation_lease_owner_finalizer.hepta']]
        parts.extend(images[row['path']] for row in owner.CARRIER_SOURCES)
        assert len(parts)==54
        wire=struct.pack('<56Q',owner.MAGIC,54,*map(len,parts))+b''.join(parts)
        obj=run(wrapperfds['generation_lease_owner_packer'],[],wire)
        assert obj==owner.reference_object(parts)
        assert obj==(args.owner_build/'generation-lease-owner.o').read_bytes()
        image=run(wrapperfds['multiversion_runtime_linker'],[],obj)
        assert image==(args.owner_build/'hia-generation-lease-owner.so').read_bytes()
        (args.output/'hia-generation-lease-owner.so').write_bytes(image)
        policy=images[BOOT+'generation_lease_public_lifecycle.hepta']
        frame=struct.pack('<8Q',int.from_bytes(b'HIAGLPK1','little'),1,len(policy),0,0,0,0,0)+policy
        facet=run(wrapperfds['generation_lease_public_lifecycle_packer'],[],frame)
        assert facet==(args.owner_build/'hia-generation-lease-lifecycle.core.bin').read_bytes()
        (args.output/'hia-generation-lease-lifecycle.core.bin').write_bytes(facet)
        for suffix in ('','_handles','_effects','_finalizer'):
            path='tools/hia_generation_lease_owner'+suffix+'_bridge.S'
            source_files[path]=record((ROOT/path).read_bytes())
        for path in ('tools/hia_generation_lease_public_lifecycle_bridge.S',
                     'docs/HIA_NATIVE_FUTURE_RELEASE_BUILD.json'):
            source_files[path]=record((ROOT/path).read_bytes())
        source_files[declaration.OWNER_QUALIFICATION]=record(component_raw)
        excluded={BOOT+name+'.hepta' for name in VALUE_ROLES}|{BOOT+VALUE_PACKER+'.hepta'}
        modules=[row for path,row in sorted(all_rows.items()) if path not in excluded]
        products={name:record((args.output/name).read_bytes()) for name in declaration.PUBLISHED[:2]}
        receipt=dict(schema='hepta.hia.generation-lease-native-release-build.v1',status='PASS',
                     native_construction_passed=True,source_bound_enclosing_owner=True,
                     owner_behavior_passed=True,owner_qualification=record(component_raw),
                     full_release_pass=False,production_activated=False,
                     typed_call_qualified=component['typed_call_qualified'],
                     generation_info_qualified=component['generation_info_qualified'],
                     compiler=record(root),modules=modules,source_files=source_files,
                     native_kit_composer=record(composer_bytes),kits=kits,wrappers=wrappers,
                     value_import=dict(stage=13,name=declaration.VALUE_PRODUCT,**record(imported)),
                     value_profile=dict(protocol=VALUE_PROTOCOL.decode('ascii'),role_count=len(VALUE_ROLES),
                                        packer=BOOT+VALUE_PACKER+'.hepta'),
                     owner_object=record(obj),products=products)
        for path,pin in source_files.items():
            if path!=declaration.OWNER_QUALIFICATION:
                assert record((ROOT/path).read_bytes())==pin,path
        (args.output/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        if args.write_receipt:
            (ROOT/declaration.OWNER_QUALIFICATION).write_bytes(component_raw)
            (ROOT/declaration.RECEIPT).write_text(json.dumps(receipt,indent=2)+'\n')
            recipe,paths,resources=declaration.build_recipe()
            (ROOT/declaration.RECIPE).write_bytes(recipe.binary())
            (args.output/'hia-generation-lease-build.json').write_bytes((ROOT/declaration.RECEIPT).read_bytes())
            report['recipe']=dict(path=declaration.RECIPE,**record(recipe.binary()),
                                  nodes=len(recipe.nodes),handles=recipe.next_handle-1,
                                  published=recipe.published,
                                  registration=declaration.registration(paths,resources,recipe.published))
        report.update(passed=True,products=products,value_import=receipt['value_import'],
                      component_qualification=record(component_raw),
                      actual_native_kits=kits,actual_native_wrappers=wrappers,
                      hia_std_recipe_execution_pending_full_release=True)
        save()
        print('GENERATION_LEASE_NATIVE_RELEASE_PASS',products,flush=True)
    except BaseException:
        report['failure']=traceback.format_exc();save();raise
    finally:
        for fd in fds:os.close(fd)


if __name__=='__main__':
    main()
