Contributing and Development
============================

Local setup
-----------

Install development and documentation dependencies:

.. code-block:: console

   python -m pip install -e .[dev,doc]

Validation commands
-------------------

Run the existing automated checks:

.. code-block:: console

   python -m coverage run -m unittest discover -s tests
   python -m coverage report -m --fail-under=100
   python -m sphinx -W -b html docs docs/_build/html
   python -m build

Architecture overview
---------------------

The project exposes one main auth class,
:class:`httpx2_negotiate_sspi.HttpNegotiateAuth`, which implements the
generator-based contract required by :class:`httpx2.Auth`.

``auth_flow``
   Shared handshake state machine used by both sync and async clients.

``sync_auth_flow`` and ``async_auth_flow``
   Thin wrappers that read request and response bodies before advancing the
   shared SSPI handshake so retry requests can be replayed safely.

``_retry_using_http_Negotiate_auth``
   Performs the scheme-specific SSPI token exchange for ``Negotiate`` or
   ``NTLM``.

Testing strategy
----------------

The test suite in ``/home/runner/work/httpx2_negotiate_sspi/httpx2_negotiate_sspi/tests/test_api.py``
uses stub Windows modules and patched SSPI objects so the package behavior can
be validated outside a real Windows SSPI environment.

The tests cover:

- sync and async auth flows
- explicit credentials and delegation flags
- TLS channel binding behavior
- DNS canonicalization fallback
- cookie propagation across retries
- Kerberos final-token handling
- malformed NTLM challenge handling

Documentation workflow
----------------------

Documentation builds with Sphinx from the ``docs/`` directory. The repository's
documentation workflows run ``python -m sphinx -W -b html docs docs/_build/html``
so warnings fail the build.

Pull requests also run the docs workflow and upload the rendered HTML as a
``docs-html`` workflow artifact so contributors can review the generated
documentation for a change set.

Credits
-------

This project was inspired by ``requests-negotiate-sspi``. See
``/home/runner/work/httpx2_negotiate_sspi/httpx2_negotiate_sspi/INSPIREDBY.MD``
for the original attribution note.
