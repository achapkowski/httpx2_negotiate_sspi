"""HTTP Negotiate authentication for ``httpx2`` using Windows SSPI.

The public API is centered on :class:`httpx2_negotiate_sspi.HttpNegotiateAuth`,
an :class:`httpx2.Auth` implementation for Windows clients that need
Kerberos or NTLM negotiation against HTTP services.
"""

from __future__ import annotations

from .api import HttpNegotiateAuth  # noqa
from .__version__ import __version__  # noqa

__all__ = ["HttpNegotiateAuth", "__version__"]
