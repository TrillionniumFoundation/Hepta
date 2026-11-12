"""Bounded development subject accounting and failure-preserving final receipts.

New source only. A strict successful-return measurement is not a claim that
Python can asynchronously interrupt every blocked metadata or stdout write.
The enclosing original common.run still owns the whole process-group deadline.
"""
from pathlib import Path
import json,os,resource,signal,stat,time,traceback
from hashlib import sha256

def save(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")

def identity(path):
    path=Path(path).absolute()
    before=path.lstat()
    assert stat.S_ISREG(before.st_mode) and not path.is_symlink(),str(path)
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        first=os.fstat(fd);assert stat.S_ISREG(first.st_mode)
        assert (first.st_dev,first.st_ino,first.st_size,stat.S_IMODE(first.st_mode))==(
            before.st_dev,before.st_ino,before.st_size,stat.S_IMODE(before.st_mode))
        chunks=[]
        while True:
            raw=os.read(fd,1<<20)
            if not raw:break
            chunks.append(raw)
        last=os.fstat(fd)
    finally:os.close(fd)
    raw=b"".join(chunks)
    after=path.lstat()
    shape=lambda info:(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,
                       info.st_ctime_ns,stat.S_IMODE(info.st_mode))
    assert shape(first)==shape(last)==shape(after),str(path)
    assert len(raw)==first.st_size
    row=dict(path=str(path),bytes=len(raw),sha256=sha256(raw).hexdigest(),
             mode=stat.S_IMODE(first.st_mode))
    return row,raw

def cpu_total():
    own=resource.getrusage(resource.RUSAGE_SELF)
    children=resource.getrusage(resource.RUSAGE_CHILDREN)
    return own.ru_utime+own.ru_stime+children.ru_utime+children.ru_stime

class Subject:
    def __init__(self,out,scope):
        self.started_ns=time.monotonic_ns()
        resource.setrlimit(resource.RLIMIT_CPU,(90,90))
        resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        self.out=Path(out).absolute();self.out.mkdir(parents=True,exist_ok=False)
        self.scope=scope;self.pins={};self.primary=None;self.errors=[]
        self.report=dict(status="INCOMPLETE",scope=scope,old_results_inherited=False,
            target_claim="none until this exact new subject completes",
            installed=False,cold=False)
        self.previous_alarm=signal.signal(signal.SIGALRM,self._timeout)
        signal.alarm(180)
    def _timeout(self,signum,frame):
        raise TimeoutError("original development subject 180-second wall deadline")
    def capture(self,path,expected=None):
        row,raw=identity(path)
        if expected is not None:assert row["sha256"]==expected,(row,expected)
        old=self.pins.get(row["path"])
        if old is None:self.pins[row["path"]]=(row,raw)
        else:assert old==(row,raw),row["path"]
        return raw
    def failure(self,error,label="primary"):
        item=dict(label=label,error_class=type(error).__name__,error=str(error),
                  traceback="".join(traceback.format_exception(error)))
        self.errors.append(item)
        if self.primary is None:self.primary=error
        else:
            try:self.primary.add_note(label+": "+repr(error))
            except BaseException:pass
        self.report["status"]="FAIL"
        self.report["failures"]=list(self.errors)
    def attempt(self,label,fn):
        try:return fn()
        except BaseException as error:self.failure(error,label);return None
    def measure(self,label):
        item=dict(cpu_seconds=cpu_total(),wall_seconds=(time.monotonic_ns()-self.started_ns)/1e9,
                  cpu_success_exclusive=90,wall_success_exclusive=180,
                  includes_parent_and_reaped_children=True)
        self.report[label]=item
        if item["cpu_seconds"]>=90 or item["wall_seconds"]>=180:
            self.failure(AssertionError("original aggregate 90 CPU / 180 wall budget: "+repr(item)),label)
        return item
    def freeze(self):
        before=[];after=[]
        for number,(original,raw) in enumerate(self.pins.values()):
            target=self.out/"source"/str(number)/Path(original["path"]).name
            def copy_one(target=target,original=original,raw=raw):
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(raw);target.chmod(original["mode"])
                copied,copied_raw=identity(target)
                assert copied_raw==raw and copied["sha256"]==original["sha256"]
                assert copied["mode"]==original["mode"]
                before.append(dict(original,snapshot=str(target.relative_to(self.out))))
            self.attempt("source-copy:"+original["path"],copy_one)
            def check_one(original=original,raw=raw):
                current,current_raw=identity(original["path"])
                same=current==original and current_raw==raw
                after.append(dict(current,same=same))
                assert same,original["path"]
            self.attempt("source-after:"+original["path"],check_one)
        self.attempt("source-before-receipt",lambda:save(self.out/"source-before.json",before))
        self.attempt("source-after-receipt",lambda:save(self.out/"source-after.json",after))
        unchanged=len(before)==len(self.pins)==len(after) and all(row["same"] for row in after)
        self.report["source_pins_unchanged"]=unchanged
        if not unchanged:self.failure(AssertionError("incomplete or changed source custody"),"source-custody")
    def _sync(self):
        if self.primary is not None:self.report["status"]="FAIL"
        self.report["failures"]=list(self.errors)
        self.report["actual_limits"]=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
            address=list(resource.getrlimit(resource.RLIMIT_AS)),
            core=list(resource.getrlimit(resource.RLIMIT_CORE)))
    def finish(self,success):
        self.attempt("freeze",self.freeze)
        if self.primary is None and self.report["status"]!=success:
            self.failure(AssertionError("subject did not reach "+success),"missing-success")
        # Even a delivered alarm or a metadata failure during finalization
        # remains a recorded first failure. Each later write/check is isolated.
        self.attempt("pre-output-measure",lambda:self.measure("pre_output_budget"))
        self.attempt("pre-output-sync",self._sync)
        self.attempt("summary-first-write",lambda:save(self.out/"summary.json",self.report))
        self.attempt("summary-first-stdout",lambda:print(json.dumps(self.report,sort_keys=True),flush=True))
        self.attempt("post-output-measure",lambda:self.measure("post_output_budget"))
        self.attempt("post-output-sync",self._sync)
        # Persist the post-output measurement on successful paths as well.
        self.attempt("summary-post-output-write",lambda:save(self.out/"summary.json",self.report))
        self.attempt("post-persist-measure",lambda:self.measure("post_persist_budget"))
        self.attempt("post-persist-sync",self._sync)
        self.attempt("summary-final-write",lambda:save(self.out/"summary.json",self.report))
        before_return=self.attempt("return-measure",lambda:self.measure("return_budget"))
        self.attempt("return-sync",self._sync)
        if self.primary is not None:
            self.attempt("summary-failure-write",lambda:save(self.out/"summary.json",self.report))
            self.attempt("summary-failure-stdout",lambda:print(json.dumps(self.report,sort_keys=True),flush=True))
        self.attempt("disable-owned-alarm",lambda:signal.alarm(0))
        self.attempt("restore-alarm-handler",lambda:signal.signal(signal.SIGALRM,self.previous_alarm))
        if self.primary is not None:
            # A cleanup error after the first FAIL write still gets a final
            # attempt at the same failure receipt without replacing its cause.
            self.attempt("final-failure-sync",self._sync)
            self.attempt("final-failure-receipt",lambda:save(self.out/"summary.json",self.report))
            raise self.primary
        assert self.report["status"]==success and before_return is not None
        assert before_return["cpu_seconds"]<90 and before_return["wall_seconds"]<180
        return self.report
