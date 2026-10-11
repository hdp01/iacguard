import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The Lambda modules import each other flatly (``import rules``) because that
# is how they resolve inside the Lambda package, so the tests put the lambda
# directory itself on the path rather than treating it as a package.
sys.path.insert(0, str(ROOT / "lambda"))
# The app lives at the project root.
sys.path.insert(0, str(ROOT))
