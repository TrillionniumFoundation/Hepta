"""Generate the complete HIA machine-plan control owner."""
from pathlib import Path
import sys
if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.generate_hia_machine_plan_control import document, main
if __name__ == '__main__':
    main()
