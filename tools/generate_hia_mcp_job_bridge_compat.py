"""Original system Jobctl wire requests for optional native_jobs profiles.

The administrator-installed HIA Jobctl owns privilege, systemd, process custody,
terminal publication and cleanup. This bridge owns the same durable local job
and serializes only the original fixed start/status/read requests.
"""
from tools.generate_hia_mcp_job_bridge_common import authored

TEXT = dict(
    start='{"op":"start","job_id":',
    status='{"op":"status","job_id":',
    read='{"op":"read","job_id":',
    executable=',"executable":',args=',"args":',cwd=',"cwd":',
    env=',"env":',stdin=',"stdin":',timeout=',"timeout_seconds":',
    resources=',"nice":0,"cpu_quota_percent":100,"memory_max_bytes":',
    out_offset=',"stdout_offset":',err_offset=',"stderr_offset":',
    limit=',"limit":16384',
)

SOURCE = r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    if get(w, SYSTEM_JOBCTL) == 0 or get(w, NATIVE_JOBS_CONFIGURED) != 0:
        return 0
    if phase == 0:
        at = text_start(w, CHILD_IN)
        at = qslot(w, at, S_JOB_ID)
        at = text_executable(w, at)
        at = qslot(w, at, S_EXECUTABLE)
        at = text_args(w, at)
        at = cp(w, S_ARGS, at)
        at = text_cwd(w, at)
        at = qslot(w, at, S_CWD)
        at = text_env(w, at)
        at = cp(w, S_ENV, at)
        at = text_stdin(w, at)
        at = qslot(w, at, S_WORKER)
        at = text_timeout(w, at)
        at = cp(w, S_TIMEOUT, at)
        at = text_resources(w, at)
        at = cp(w, S_MEMORY, at)
        at = text_close(w, at)
        at = text_newline(w, at)
        if at > CHILD_OUT:
            return 0
        return child(w, 3, 12, 11, at - CHILD_IN, 8388608, 8388608, 20000000000, NONE)
    if phase == 10:
        reading = get(w, 1904) == 2
        if reading:
            at = text_read(w, CHILD_IN)
        else:
            at = text_status(w, CHILD_IN)
        at = qslot(w, at, S_JOB_ID)
        if reading:
            at = text_out_offset(w, at)
            at = decimal(w, at, get(w, 1936))
            at = text_err_offset(w, at)
            at = decimal(w, at, get(w, 1944))
            at = text_limit(w, at)
        at = text_close(w, at)
        at = text_newline(w, at)
        return child(w, 3, 203, 11, at - CHILD_IN, 8388608, 8388608, 20000000000, NONE)
    return 0
'''


def source():
    return authored(SOURCE, text=TEXT)
