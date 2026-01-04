import sys
from pathlib import Path

# Ensure src directory is importable for tests
ROOT = Path(__file__).resolve().parents[1]
src_path = ROOT / "src"
if src_path.exists():
    sys.path.insert(0, str(src_path))
