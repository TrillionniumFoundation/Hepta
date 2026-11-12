"""Execute the exact retained finite control file in an isolated child."""
from pathlib import Path
import runpy
import sys

source = Path(sys.argv[1]).resolve(strict=True)
control = Path(__file__).resolve().parent / 'finite_controls.py'
sys.path.insert(0, str(source))
sys.argv = [str(control), *sys.argv[2:]]
runpy.run_path(str(control), run_name='__main__')
