httpx2-negotiate-sspi
=====================

HTTP Negotiate authentication for ``httpx2`` using Windows SSPI.

This package supports Kerberos and NTLM authentication, including channel
binding tokens from the TLS peer certificate exposed by ``httpx2`` response
extensions.

Usage
-----

Synchronous client:

.. code-block:: python

   import httpx2
   from httpx2_negotiate_sspi import HttpNegotiateAuth

   with httpx2.Client(auth=HttpNegotiateAuth()) as client:
       response = client.get('https://iis.contoso.com')

Asynchronous client:

.. code-block:: python

   import httpx2
   from httpx2_negotiate_sspi import HttpNegotiateAuth

   async with httpx2.AsyncClient(auth=HttpNegotiateAuth()) as client:
      response = await client.get('https://iis.contoso.com')

Options
-------

``HttpNegotiateAuth`` accepts optional credentials and service-principal
configuration.

API Reference
-------------

.. automodule:: httpx2_negotiate_sspi

.. autoclass:: httpx2_negotiate_sspi.HttpNegotiateAuth
   :members:

.. py:data:: httpx2_negotiate_sspi.__version__
   :type: str

   Package version. ``pyproject.toml`` reads this value from
   ``httpx2_negotiate_sspi.__version__.__version__`` when building the
   distribution.