import os,pathlib,subprocess,shutil,json,time,hashlib
base=pathlib.Path("/home/qian-qi/hia-cell-current-native-20261127-2ac5/mount-preparation-probe-v1")
free=os.statvfs(base.parent).f_bavail*os.statvfs(base.parent).f_frsize
assert free>256*1024*1024,free
os.umask(0o077)
base.mkdir()
scratch=base/"shared-memory";scratch.mkdir()
original_ns=os.readlink("/proc/self/ns/mnt")
inner="""import os,sys,pathlib,json,subprocess
scratch=pathlib.Path(sys.argv[1]); original=sys.argv[2]
assert os.readlink('/proc/self/ns/mnt')!=original
p=subprocess.run(['/usr/bin/mount','--bind',str(scratch),'/dev/shm'],capture_output=True,text=True)
print(json.dumps({'mount_returncode':p.returncode,'mount_stdout':p.stdout,'mount_stderr':p.stderr}))
if p.returncode: raise SystemExit(p.returncode)
leaf=pathlib.Path('/dev/shm/hia-cell-owned-namespace-probe');leaf.write_bytes(b'owned namespace only\\n')
assert leaf.read_bytes()==(scratch/leaf.name).read_bytes()
assert leaf.stat().st_ino==(scratch/leaf.name).stat().st_ino
print(json.dumps({'status':'PRIVATE_MOUNT_PASS','namespace':os.readlink('/proc/self/ns/mnt'),'physical_device':leaf.stat().st_dev,'original_namespace':original}))
leaf.unlink()
"""
exe=shutil.which("unshare")
start=time.monotonic()
p=subprocess.run([exe,"--user","--map-root-user","--mount","--propagation","private","--","/usr/bin/python3","-c",inner,str(scratch),original_ns],capture_output=True,timeout=30) if exe else None
result={"unshare":exe,"free_before":free,"original_namespace":original_ns,"seconds":time.monotonic()-start,"returncode":p.returncode if p else None,"stdout":p.stdout.decode(errors="replace") if p else "","stderr":p.stderr.decode(errors="replace") if p else ""}
assert os.readlink("/proc/self/ns/mnt")==original_ns
(base/"result.json").write_text(json.dumps(result,indent=2)+"\n")
print(json.dumps(result))
