"""Author the source-bound GenerationLease owner as native release stage 14.

Stage 13 supplies the already qualified twelve-role Value product. This recipe
binds its bytes and embeds that exact image once; it does not publish a second
Value implementation. All construction, source capture, hashing, packing and
linking in the retained recipe are HIA operations.
"""
from hashlib import sha256
from pathlib import Path
import json
from tools.generate_hia_native_controller_release import ControllerRecipe,BOOT,FILTER_POLICY,WIDE_FILTER
from tools import generate_hia_generation_lease_owner_packer as owner

ROOT=Path(__file__).resolve().parents[1]
RECIPE=BOOT+'release_stage_generation_lease.hiastd'
RECEIPT='docs/HIA_NATIVE_GENERATION_LEASE_RELEASE_BUILD.json'
OWNER_QUALIFICATION='docs/HIA_GENERATION_LEASE_OWNER_QUALIFICATION.json'
VALUE_PRODUCT='hia-result-value.core.bin'
PUBLISHED=('hia-generation-lease-owner.so','hia-generation-lease-lifecycle.core.bin',
           'hia-generation-lease-build.json')


def pin(r,value,record):
    r.node(8,(r.digest(value),r.literal(bytes.fromhex(record['sha256']))))
    r.node(8,(r.length(value),r.q(record['bytes'])))


def build_recipe():
    raw=(ROOT/RECEIPT).read_bytes();receipt=json.loads(raw)
    assert receipt['schema']=='hepta.hia.generation-lease-native-release-build.v1'
    assert receipt['status']=='PASS' and receipt['native_construction_passed']
    assert receipt['source_bound_enclosing_owner'] and receipt['owner_behavior_passed']
    assert receipt['value_import']['stage']==13 and receipt['value_import']['name']==VALUE_PRODUCT
    assert not receipt['full_release_pass'] and not receipt['production_activated']
    paths=sorted(row['path'] for row in receipt['modules'])
    assert len(paths)==len(set(paths))
    assert {BOOT+FILTER_POLICY,BOOT+WIDE_FILTER,BOOT+'native_filter_packer.hepta',
            BOOT+'selfhost.hepta'}<=set(paths)
    r=ControllerRecipe();r.compile_exact(paths)
    pin(r,r.import_product('hia-source-build'),receipt['compiler'])
    for row in receipt['modules']:
        assert row['two_builds_identical'] is True
        pin(r,r.source_views[row['path']],dict(bytes=row['source_bytes'],sha256=row['source_sha256']))
        pin(r,r.compiled[row['path']],dict(bytes=row['flat_bytes'],sha256=row['flat_sha256']))
    for path,record in sorted(receipt['source_files'].items()):
        pin(r,r.source(path),record)
    r.small_builder=r.checked_kit('native_filter_packer.hepta')
    r.wide_builder=r.checked_kit(WIDE_FILTER)
    pin(r,r.small_builder,receipt['kits']['small'])
    pin(r,r.wide_builder,receipt['kits']['wide'])
    wrappers={}
    for name,wide in (('generation_lease_owner_packer',True),
                      ('multiversion_runtime_linker',True),
                      ('generation_lease_public_lifecycle_packer',False)):
        image=r.native_filter(r.compiled[BOOT+name+'.hepta'],wide=wide)
        pin(r,image,receipt['wrappers'][name]);wrappers[name]=image

    def flat(name):
        return r.compiled[BOOT+name+'.hepta']

    values=r.import_product(VALUE_PRODUCT)
    pin(r,values,receipt['value_import'])
    parts=[flat('generation_lease_owner'),flat('generation_lease_public_lifecycle'),values,
           flat('generation_lease_typed_policy'),flat('generation_lease_owner_finalizer')]
    parts.extend(r.compiled[row['path']] for row in owner.CARRIER_SOURCES)
    assert len(parts)==54 and tuple(row['role'] for row in owner.CARRIER_SOURCES)==owner.carrier.ROLES
    wire=r.concat(r.literal(b'HIAGLOP1'),r.q(54),*(r.length(p) for p in parts),*parts)
    obj=r.run(wrappers['generation_lease_owner_packer'],wire,0)
    pin(r,obj,receipt['owner_object'])
    image=r.run(wrappers['multiversion_runtime_linker'],obj,0)
    pin(r,image,receipt['products'][PUBLISHED[0]])
    r.publish(PUBLISHED[0],image,receipt['products'][PUBLISHED[0]]['sha256'])
    policy=flat('generation_lease_public_lifecycle')
    wire=r.concat(r.literal(b'HIAGLPK1'),r.q(1),r.length(policy),r.q(0,0,0,0,0),policy)
    facet=r.run(wrappers['generation_lease_public_lifecycle_packer'],wire,0)
    pin(r,facet,receipt['products'][PUBLISHED[1]])
    r.publish(PUBLISHED[1],facet,receipt['products'][PUBLISHED[1]]['sha256'])
    frozen=r.source(RECEIPT);pin(r,frozen,dict(bytes=len(raw),sha256=sha256(raw).hexdigest()))
    r.publish(PUBLISHED[2],frozen,sha256(raw).hexdigest())
    resources=sorted((set(receipt['source_files'])-set(paths))|{RECEIPT})
    assert tuple(r.published)==PUBLISHED
    assert len(r.nodes)<=8192 and r.next_handle<=2049 and len(r.binary())<=1048576
    return r,paths,resources


def registration(paths,resources,published):
    """Return records for the root's single shared-table integration."""
    rows=['stage\t14\tnative-generation-lease-owner',
          'need\t14\t0\thia-source-build','need\t14\t0\tselfhost.image.bin',
          'need\t14\t13\t'+VALUE_PRODUCT]
    rows += ['compile\t14\tlease-'+str(i//96)+'\t'+Path(path).name+'\t'+path.removeprefix(BOOT)
             for i,path in enumerate(paths)]
    rows += ['kit\t14\t'+FILTER_POLICY+'\tnative_filter_packer.hepta',
             'kit\t14\t'+FILTER_POLICY+'\t'+WIDE_FILTER]
    rows += ['resource\t14\t'+path for path in resources]
    rows += ['output\t14\t'+name for name in published]
    rows += ['framing\t14\t0\tHIAGLOP1\tsource-bound-owned-lease-and-stage13-values']
    return rows


def register_stage(paths,resources,published,*,root=ROOT):
    """Retain the other stages and derive the complete shared-table header."""
    from tools.hia_native_release_dependencies import read_source_table
    table=Path(root)/BOOT/'release_stage_sources.tsv'
    lines=table.read_text('ascii').splitlines()
    if not lines or len(lines[0].split('\t'))!=3 or lines[0].split('\t')[0]!='stage':
        raise ValueError('missing native release source table header')
    records=[line for line in lines[1:] if int(line.split('\t')[1])!=14]
    before=[line for line in records if int(line.split('\t')[1])<14]
    after=[line for line in records if int(line.split('\t')[1])>14]
    records=before+registration(paths,resources,published)+after
    stages=max(int(line.split('\t')[1]) for line in records)
    outputs=sum(line.startswith('output\t') for line in records)
    raw=('\n'.join([f'stage\t{stages}\t{outputs}',*records])+'\n').encode('ascii')
    read_source_table(raw)
    if len(raw)>262144:
        raise ValueError('native release source table exceeds its retained byte budget')
    table.write_bytes(raw)


def main():
    r,paths,resources=build_recipe();(ROOT/RECIPE).write_bytes(r.binary())
    register_stage(paths,resources,r.published)
    print(json.dumps(dict(recipe=RECIPE,bytes=len(r.binary()),nodes=len(r.nodes),
                          handles=r.next_handle-1,source_count=len(paths),
                          registration=registration(paths,resources,r.published)),indent=2))


if __name__=='__main__':
    main()
