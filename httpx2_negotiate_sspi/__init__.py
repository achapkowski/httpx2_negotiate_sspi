"""HTTP Negotiate authentication for ``httpx2`` using Windows SSPI."""

from __future__ import annotations

from .api import HttpNegotiateAuth  # noqa
from .__version__ import __version__  # noqa

__all__ = ['HttpNegotiateAuth', '__version__']
