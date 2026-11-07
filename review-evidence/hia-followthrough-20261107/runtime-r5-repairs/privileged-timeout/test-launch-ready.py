
import select, subprocess
fixture_popen = subprocess.Popen
def launch_fixture_ready(*args, **kwargs):
    child = fixture_popen(*args, **kwargs)
    if not select.select([child.stdout], [], [], 10)[0]:
        child.kill()
        child.wait(timeout=5)
        raise RuntimeError("fixture stdout was not ready within 10 seconds")
    return child
subprocess.Popen = launch_fixture_ready
