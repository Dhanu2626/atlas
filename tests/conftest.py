"""Makes `atlas/` importable from every test file without each one repeating a
sys.path hack — `import contracts`, `from atlas_service.ml... import ...`, and
`from bank_service... import ...` all work directly once this loads."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
