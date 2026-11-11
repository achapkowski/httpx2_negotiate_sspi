httpx2-negotiate-sspi
=====================

HTTP Negotiate (Kerberos/NTLM) authentication for ``httpx2`` on **Windows,
Linux and macOS** via `pyspnego <https://github.com/jborean93/pyspnego>`_.

The package uses Windows SSPI on Windows and GSSAPI/Kerberos on Linux and
macOS. The name mentions ``sspi`` for historical reasons.

Supported features:

- Kerberos single sign-on with SSPI (Windows) or the ticket cache (Linux/macOS)
- NTLM with explicit credentials on all platforms
- Mutual authentication enforcement (CWE-295 mitigation, **on by default**)
- Extended Protection for Authentication via RFC 5929 TLS channel binding
- Async support without blocking the event loop

.. toctree::
   :maxdepth: 2
   :caption: Contents

   getting-started
   usage
   api
   troubleshooting
   contributing
