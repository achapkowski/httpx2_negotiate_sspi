from __future__ import annotations

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

project = "httpx2-negotiate-sspi"
author = "achapkowski"

extensions = ["sphinx.ext.autodoc"]
autodoc_mock_imports = ["pywintypes", "sspi", "sspicon", "win32security"]
autoclass_content = "init"

html_theme = "sphinx_rtd_theme"
