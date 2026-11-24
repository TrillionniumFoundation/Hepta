"""External byte-level qualification for a native Worker source authority.

The expected identity is computed from the explicit captured source-pin map,
not from the native result. The native ELF receives a sealed HIAWID01 request;
no callback or host-language implementation participates in its execution.
This checks the identity component and recipe capture set, not final install.
"""
from pathlib import Path
from hashlib import sha256
import argparse,fcntl,json,os,struct,subprocess,time,sys


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def inventory(rows):
    return b'HIASPI01'+struct.pack('<Q',len(rows))+b''.join(
        struct.pack('<Q',len(path))+pin+path for path,pin in rows)


def frame(parts,mode=1):
    return b'HIAWID01'+struct.pack('<2Q',mode,len(parts))+b''.join(struct.pack('<Q',len(p))+p for p in parts)


def replacement(data,at,value):
    return data[:at]+struct.pack('<Q',value)+data[at+8:]


def qualify(args):
    source=args.source.resolve(strict=True);sys.path.insert(0,str(source))
    from tools.hia_native_worker_source_authority import load_native_source_authority,checked_paths,path_table
    output=args.output.absolute();output.mkdir(mode=0o700)
    paths=load_native_source_authority(args.authority)
    table=args.table.read_bytes();assert table==path_table(paths)
    source_pins=json.loads(args.source_pins.read_bytes())
    assert set(source_pins)==set(paths)
    rows=[(p.encode(),bytes.fromhex(source_pins[p])) for p in paths]
    expected=sha256(json.dumps(source_pins,sort_keys=True,separators=(',',':')).encode()).digest()
    actual_inventory=inventory(rows)
    image=args.executable.read_bytes()
    captured={str(p):sha256(p.read_bytes()).hexdigest() for p in
              (args.authority,args.table,args.source_pins,args.executable)}
    fd=os.memfd_create('qualified-native-worker-identity',os.MFD_ALLOW_SEALING)
    at=0
    while at<len(image):
        n=os.write(fd,image[at:]);assert n>0;at+=n
    fcntl.fcntl(fd,1033,15);assert fcntl.fcntl(fd,1034)==15
    report={'schema':'hepta.hia.native-worker-identity-qualification.v1','success':False,
            'scope':'Explicit native authority identity component; final publication is a separate gate',
            'captured':captured,'paths':len(paths),'worker_identity_sha256':expected.hex(),
            'native_cases':[],'author_refusals':[],'started_ns':time.time_ns()}
    started=time.monotonic()
    def save():
        (output/'qualification.json').write_bytes(encoded(report))
    def run(name,data,answer=None,argv=('build',)):
        t=time.monotonic();r=subprocess.run(['/proc/self/fd/'+str(fd),*argv],input=data,capture_output=True,
             cwd=output,env={'PATH':''},pass_fds=(fd,),timeout=30)
        good=r.returncode==(16 if answer is None else 0) and not r.stderr and r.stdout==(b'' if answer is None else answer)
        row={'name':name,'input_bytes':len(data),'input_sha256':sha256(data).hexdigest(),
             'rc':r.returncode,'stdout_bytes':len(r.stdout),'stdout_sha256':sha256(r.stdout).hexdigest(),
             'stderr_bytes':len(r.stderr),'seconds':time.monotonic()-t,'passed':good}
        report['native_cases'].append(row)
        if not good:
            (output/(name+'.input')).write_bytes(data);(output/(name+'.stdout')).write_bytes(r.stdout)
            (output/(name+'.stderr')).write_bytes(r.stderr)
            if answer is not None:(output/(name+'.expected')).write_bytes(answer)
            save();raise AssertionError(row)
        return r.stdout
    try:
        base=frame([actual_inventory,table])
        run('complete-native-authority',base,expected)
        for position in sorted({0,len(rows)//2,len(rows)-1}):
            changed=list(rows);p,pin=changed[position];changed[position]=(p,bytes([pin[0]^1])+pin[1:])
            changed_map={p.decode():v.hex() for p,v in changed}
            changed_expected=sha256(json.dumps(changed_map,sort_keys=True,separators=(',',':')).encode()).digest()
            assert changed_expected!=expected
            run('changed-selected-pin-'+str(position),frame([inventory(changed),table]),changed_expected)
            run('missing-selected-'+str(position),frame([inventory(rows[:position]+rows[position+1:]),table]))
            duplicate=sorted(rows+[rows[position]])
            run('duplicate-selected-'+str(position),frame([inventory(duplicate),table]))
        extra=(b'zzzz/native-unused.hepta',bytes(range(32)))
        run('valid-unselected-source',frame([inventory(sorted(rows+[extra])),table]),expected)
        run('unselected-pin-is-not-selected',frame([inventory(sorted(rows+[(extra[0],bytes(reversed(range(32))))])),table]),expected)
        padded=rows+[(('zzzz/p%04d.hepta'%n).encode(),sha256(struct.pack('<Q',n)).digest()) for n in range(4096-len(rows))]
        run('original-4096-inventory-count',frame([inventory(sorted(padded)),table]),expected)
        run('original-4097-inventory-refusal',frame([inventory(sorted(padded+[(b'zzzz/z.hepta',b'Z'*32)])),table]))
        boundary=list(rows);remaining=1048576-len(inventory(boundary));number=0
        while remaining:
            size=min(4095,remaining-40)
            if remaining-40-size in range(1,60):size-=60-(remaining-40-size)
            assert size>=20,(remaining,size)
            prefix=('zzzz/q%04d/'%number).encode();path=prefix+b'a'*(size-len(prefix)-6)+b'.hepta'
            assert len(path)==size
            boundary.append((path,sha256(path).digest()));remaining-=40+size;number+=1
        exact=inventory(sorted(boundary));assert len(exact)==1048576
        run('original-exact-1MiB-inventory',frame([exact,table]),expected)
        run('original-1MiB-plus-one-refusal',frame([exact+b'X',table]))
        for name,changed in [
            ('inventory-empty',b''),('inventory-header-short',actual_inventory[:15]),
            ('inventory-magic',b'X'+actual_inventory[1:]),('inventory-zero-count',replacement(actual_inventory,8,0)),
            ('inventory-count-overflow',replacement(actual_inventory,8,(1<<64)-1)),
            ('inventory-reversed',inventory(list(reversed(rows)))),('inventory-trailing',actual_inventory+b'X'),
            ('inventory-truncated',actual_inventory[:-1]),('path-zero',replacement(actual_inventory,16,0)),
            ('path-size-4096',replacement(actual_inventory,16,4096)),
            ('path-size-overflow',replacement(actual_inventory,16,(1<<64)-1)),
        ]:run(name,frame([changed,table]))
        for code in (0,10,13,31,34,92,127,128,255):
            run('unselected-bad-path-byte-'+str(code),frame([inventory(sorted(rows+[(b'zzzz/'+bytes([code])+b'.hepta',b'X'*32)])),table]))
        for name,changed in [('table-truncated',table[:-1]),('table-trailing',table+b'X'),
                             ('table-pin',table[:32]+bytes([table[32]^1])+table[33:]),
                             ('table-count',replacement(table,8,len(paths)-1))]:
            run(name,frame([actual_inventory,changed]))
        for size in (0,1,7,8,15,16,23,24,31,32,len(base)-1):run('request-truncated-'+str(size),base[:size])
        for name,changed in [('request-magic',b'X'+base[1:]),('request-trailing',base+b'X'),
                            ('request-mode',replacement(base,8,3)),('request-parts-zero',replacement(base,16,0)),
                            ('request-parts-one',replacement(base,16,1)),('request-parts-three',replacement(base,16,3)),
                            ('request-size-overflow',replacement(base,24,(1<<64)-1))]:run(name,changed)
        run('missing-build-argv',base,argv=())
        run('extra-build-argv',base,argv=('build','extra'))
        for n in (0,1,31,32,255,65536):
            value=bytes(i&255 for i in range(n));run('hex-'+str(n),frame([value],mode=2),value.hex().encode())
        run('hex-original-over-budget',frame([b'X'*65537],mode=2))
        for name,value in [('empty',[]),('duplicate',['a.hepta','a.hepta']),('unsorted',['b.hepta','a.hepta']),
            ('absolute',['/a.hepta']),('dot',['./a.hepta']),('parent',['a/../b.hepta']),('double-slash',['a//b.hepta']),
            ('git',['.git/a.hepta']),('python',['hepta/a.py']),('rust',['rust/a.rs']),('quote',['a".hepta']),
            ('backslash',['a\\b.hepta']),('newline',['a\n.hepta']),('non-ascii',['é.hepta']),('not-text',[1]),
            ('over-count',['a%04d.hepta'%n for n in range(4097)]),('path-over-budget',['a'*4090+'.hepta'])]:
            try:checked_paths(value)
            except (ValueError,TypeError):report['author_refusals'].append(name)
            else:raise AssertionError(('author accepted invalid authority',name))
        assert {str(p):sha256(p.read_bytes()).hexdigest() for p in
                (args.authority,args.table,args.source_pins,args.executable)}==captured
        report.update(success=True,native_case_count=len(report['native_cases']),
                      author_refusal_count=len(report['author_refusals']),seconds=time.monotonic()-started,
                      input_custody_unchanged=True,complete_map_matches_independent_hash=True)
        save();return report
    finally:
        os.close(fd)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','authority','source-pins','table','executable','output'):
        p.add_argument('--'+name,type=Path,required=True)
    r=qualify(p.parse_args());print(json.dumps({k:r[k] for k in ('success','native_case_count','author_refusal_count','seconds')},sort_keys=True))


if __name__=='__main__':main()
