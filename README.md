![PyPI Python Version](https://img.shields.io/pypi/pyversions/httpx2-negotiate-sspi)
![Pepy Total Downloads](https://img.shields.io/pepy/dt/httpx2-negotiate-sspi)

httpx2-negotiate-sspi
=====================

`httpx2-negotiate-sspi` provides HTTP Negotiate authentication for
`httpx2` on Windows through the SSPI APIs exposed by `pywin32`.

It supports:

- Kerberos and NTLM challenge handling
- Single sign-on with the current Windows logon session
- Explicit credentials when default credentials are not appropriate
- Extended Protection for Authentication via TLS channel binding tokens

Platform support
----------------

This package is intended for **Windows** clients. It depends on Windows SSPI
through `pywin32`, and its authentication flow is designed for services that
advertise `Negotiate` or `NTLM` via `WWW-Authenticate`.

Installation
------------

```console
pip install httpx2-negotiate-sspi
```

Quick start
-----------

Use the logged-in Windows account for single sign-on:

```python
import httpx2
from httpx2_negotiate_sspi import HttpNegotiateAuth

with httpx2.Client(auth=HttpNegotiateAuth()) as client:
    response = client.get("https://iis.contoso.com")
    response.raise_for_status()
```

Async clients use the same auth object:

```python
import asyncio

import httpx2

from httpx2_negotiate_sspi import HttpNegotiateAuth


async def main() -> None:
    async with httpx2.AsyncClient(auth=HttpNegotiateAuth()) as client:
        response = await client.get("https://iis.contoso.com")
        response.raise_for_status()


asyncio.run(main())
```

Common configuration
--------------------

Explicit credentials:

```python
import getpass

import httpx2
from httpx2_negotiate_sspi import HttpNegotiateAuth

auth = HttpNegotiateAuth(
    "svc-http-client",
    getpass.getpass(),
    "CONTOSO",
)

with httpx2.Client(auth=auth) as client:
    response = client.get("https://iis.contoso.com")
```

Explicit SPN service and host override:

```python
from httpx2_negotiate_sspi import HttpNegotiateAuth

auth = HttpNegotiateAuth(service="HTTP", host="adfs.contoso.com")
```

Delegation-enabled authentication:

```python
from httpx2_negotiate_sspi import HttpNegotiateAuth

auth = HttpNegotiateAuth(delegate=True)
```

Configuration reference
-----------------------

`HttpNegotiateAuth` accepts these options:

- `username`: User name for explicit credentials. Default: `None`.
- `password`: Password for explicit credentials. Default: `None`.
- `domain`: NT domain name used with explicit credentials. Default: `"."`
  for the local machine account namespace.
- `service`: Kerberos service class used when constructing the SPN.
  Default: `"HTTP"`.
- `host`: Explicit SPN host override. When omitted, the request host is used
  and may be canonicalized through DNS per challenged request.
- `delegate`: Enables `ISC_REQ_DELEGATE` so the server may receive delegated
  credentials. Default: `False`.

Behavior notes
--------------

- If both `username` and `password` are omitted, the current Windows logon
  credentials are used.
- If `host` is omitted, the SPN host is derived per request and the library
  attempts DNS canonicalization. If canonicalization fails, it falls back to
  the original request host.
- When the `httpx2` transport exposes an SSL object, the library sends a TLS
  channel binding token derived from the peer certificate. This is required by
  some services that enforce Extended Protection for Authentication.
- If the outgoing request already contains an `Authorization` header, the
  Negotiate flow does not overwrite it.

Troubleshooting
---------------

- If you keep receiving `401 Unauthorized`, confirm the server is advertising
  `Negotiate` or `NTLM` and that the account has permission to access the
  service.
- If Kerberos works only with an explicit `host`, verify that DNS
  canonicalization is resolving the expected SPN.
- If a service requires Extended Protection, make sure the request is using
  TLS and that the transport exposes the peer certificate to `httpx2`.
- If you are authenticating as another account, provide both `username` and
  `password`; specifying only one value leaves default credentials in use.

Documentation and development
-----------------------------

- Documentation: https://achapkowski.github.io/httpx2_negotiate_sspi
- Source: https://github.com/achapkowski/httpx2_negotiate_sspi
- Issues: https://github.com/achapkowski/httpx2_negotiate_sspi/issues

To work on the project locally:

```console
python -m pip install -e .[dev,doc]
python -m coverage run -m unittest discover -s tests
python -m coverage report -m --fail-under=100
python -m sphinx -W -b html docs docs/_build/html
```

Credits
-------

This package was inspired by
[`requests-negotiate-sspi`](https://github.com/brandond/requests-negotiate-sspi).
