API Reference
=============

Package
-------

.. automodule:: httpx2_negotiate_sspi

Core auth implementation
------------------------

.. automodule:: httpx2_negotiate_sspi.api
   :no-members:

.. autoclass:: httpx2_negotiate_sspi.api.MutualAuthenticationError
   :show-inheritance:

   Raised when :attr:`~httpx2_negotiate_sspi.HttpNegotiateAuth.mutual_authentication`
   is ``True`` and the server does not send a valid final authentication token,
   or sends one that fails validation.

   This is a subclass of :exc:`httpx2.HTTPError`. Callers that need to
   distinguish a mutual-authentication failure from other HTTP errors can catch
   this exception specifically:

   .. code-block:: python

      from httpx2_negotiate_sspi import HttpNegotiateAuth
      from httpx2_negotiate_sspi.api import MutualAuthenticationError
      import httpx2

      try:
          with httpx2.Client(auth=HttpNegotiateAuth()) as client:
              client.get("https://example.com")
      except MutualAuthenticationError:
          # Server did not prove its identity
          raise
      except httpx2.HTTPError:
          # Other HTTP-layer error
          raise

.. autoclass:: httpx2_negotiate_sspi.HttpNegotiateAuth
   :members:
   :member-order: bysource

Version
-------

.. py:data:: httpx2_negotiate_sspi.__version__
   :type: str

   Package version string. ``pyproject.toml`` reads this value from
   ``httpx2_negotiate_sspi.__version__.__version__`` when building the
   distribution.
