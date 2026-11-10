Contributing and Development
============================

Local setup
-----------

Install development and documentation dependencies:

.. code-block:: console

   python -m pip install -e .[dev,doc]

On Linux/macOS, ``pyspnego[kerberos]`` is installed automatically via the
platform marker in ``pyproject.toml``. System Kerberos libraries must be
present first (see :doc:`getting-started`).

Validation commands
-------------------

.. code-block:: console

   python -m coverage run -m unittest discover -s tests
   python -m coverage report -m --fail-under=100
   python -m sphinx -W -b html docs docs/_build/html
   python -m build

The coverage threshold is 100 %. Integration test files
(``test_integration_iis.py``, ``test_integration_kerberos.py``,
``integration_server.py``) are excluded from the report via
``[tool.coverage.run] omit`` in ``pyproject.toml`` because they require a
live IIS server or Kerberos KDC.

Architecture overview
---------------------

The project exposes one main auth class,
:class:`httpx2_negotiate_sspi.HttpNegotiateAuth`, which implements the
generator-based contract required by :class:`httpx2.Auth`.

``auth_flow``
   Shared handshake state machine used by both sync and async clients. Yields
   the first request, checks for a ``401``, then delegates to
   ``_retry_using_http_Negotiate_auth`` for scheme-specific token exchange.

``sync_auth_flow``
   Thin wrapper that reads request and response bodies before advancing the
   shared handshake, then drives it with a ``while True`` loop.

``async_auth_flow``
   Same as ``sync_auth_flow`` but runs SSPI/GSSAPI calls and DNS lookups in
   ``asyncio.to_thread`` so the event loop is never blocked. Uses a sentinel
   to avoid ``StopIteration`` propagating through ``asyncio.to_thread``
   (PEP 479).

``_retry_using_http_Negotiate_auth``
   Performs the scheme-specific SPNEGO token exchange for ``Negotiate`` or
   ``NTLM``. Handles multi-leg handshakes (up to ``_MAX_HANDSHAKE_ROUNDS``
   rounds) and calls ``_finalize_mutual_auth`` on the first non-401 response.

``_finalize_mutual_auth``
   Consumes the server's final token and enforces mutual authentication by
   checking ``ctx.complete`` and the ``mutual_auth`` context attribute flag
   (CWE-295 mitigation).

``_make_context``
   Creates a pyspnego client context, selecting ``use_sspi`` on Windows and
   ``use_gssapi`` on Linux/macOS for SSO, or ``NegotiateOptions(0)`` for
   explicit credentials.

``_cert_hash_name`` / ``_der_signature_oid``
   Pure-Python DER parser that extracts the ``signatureAlgorithm`` OID from a
   peer certificate to select the RFC 5929 §4.1 channel-binding hash.

Testing strategy
----------------

The test suite uses two files:

``tests/test_api.py``
   Broad behavioral tests: sync/async flows, explicit credentials, delegation,
   TLS channel binding, DNS canonicalization, cookie propagation, and
   challenge-sequence handling. Patches ``spnego.client`` with a
   ``FakeContext`` class.

``tests/test_mutual_auth.py``
   Targeted tests for security-sensitive code paths: mutual authentication
   enforcement (single-leg and multi-leg), NTLM without the ``mutual_auth``
   flag, credential/hostname options, RFC 5929 channel binding hash selection,
   DER parser edge cases, the round-limit guard, and async equivalents of the
   mutual-auth cases. Also covers ``MissingBackendTest`` for SSPI/GSSAPI
   unavailability hints.

Integration tests (CI only)
   ``test_integration_iis.py`` runs against a real IIS server on
   GitHub-hosted Windows runners (``IIS_TEST_URL`` env var required).
   ``test_integration_kerberos.py`` runs against a local KDC on GitHub-hosted
   Ubuntu runners (``KRB_TEST_URL`` env var required). Both are skipped
   locally.

Documentation workflow
----------------------

Documentation builds with Sphinx from the ``docs/`` directory. Warnings are
treated as errors (``-W`` flag). Pull requests upload the rendered HTML as a
``docs-html`` artifact for review.

Credits
-------

This project was inspired by
`requests-negotiate-sspi <https://github.com/brandond/requests-negotiate-sspi>`_.
