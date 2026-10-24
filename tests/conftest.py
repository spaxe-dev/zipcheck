import pathlib
import sys

# Allow running the test suite from a fresh checkout without installing the
# package first (CI and `pip install -e .` work either way).
SRC = pathlib.Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
