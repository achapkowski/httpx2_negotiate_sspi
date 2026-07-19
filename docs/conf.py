from __future__ import annotations

from pathlib import Path
import runpy
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_version_ns = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "httpx2_negotiate_sspi" / "__version__.py")
)

project = "httpx2-negotiate-sspi"
author = "achapkowski"
version = release = _version_ns["__version__"]

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.viewcode",
]
autodoc_mock_imports = ["pywintypes", "sspi", "sspicon", "win32security"]
autoclass_content = "init"
autodoc_member_order = "bysource"
autodoc_typehints = "description"

html_theme = "sphinx_rtd_theme"
