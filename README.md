![PyPI Python Version](https://img.shields.io/pypi/pyversions/httpx2-negotiate-sspi)
![Pepy Total Downloads](https://img.shields.io/pepy/dt/httpx2-negotiate-sspi)

httpx2-negotiate-sspi
=====================

`httpx2-negotiate-sspi` provides HTTP Negotiate (Kerberos/NTLM) authentication
for `httpx2` on **Windows, Linux and macOS** through the `pyspnego` library.

The package name mentions `sspi` for historical reasons; it now uses
`pyspnego` and works on all major platforms.

It supports:

- Kerberos single sign-on with SSPI (Windows) or the ticket cache (Linux/macOS)
- NTLM with explicit credentials on all platforms
- Extended Protection for Authentication via RFC 5929 TLS channel binding
- Mutual authentication enforcement (CWE-295 mitigation)

Platform support
----------------

| Platform    | Backend | Requirement                                    |
|-------------|---------|------------------------------------------------|
| Windows     | SSPI    | `sspilib` (installed automatically)            |
| Linux/macOS | GSSAPI  | system Kerberos libs (installed automatically) |

Installation
------------

```console
pip install httpx2-negotiate-sspi
```

On Linux/macOS, system Kerberos libraries must also be present:

```console
# Ubuntu / Debian
sudo apt install libkrb5-dev

# macOS
brew install krb5
```

Then obtain a ticket before making requests:

```console
kinit user@DOMAIN.COM
```

Quick start
-----------

Default use — single sign-on with the logged-in account:

```python
import httpx2
from httpx2_negotiate_sspi import HttpNegotiateAuth

with httpx2.Client(auth=HttpNegotiateAuth()) as client:
    response = client.get("https://iis.contoso.com")
    response.raise_for_status()
```

Async clients use the same auth object (SSPI/GSSAPI calls run in a worker
thread so the event loop is not blocked):

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

NTLM with explicit credentials — set ``mutual_authentication=False`` because
NTLM cannot prove the server's identity:

```python
import httpx2
from httpx2_negotiate_sspi import HttpNegotiateAuth

auth = HttpNegotiateAuth(
    username="svc-http-client",
    password="hunter2",
    domain="CONTOSO",
    mutual_authentication=False,
)
with httpx2.Client(auth=auth) as client:
    response = client.get("https://intranet.contoso.com")
```

Explicit SPN host override:

```python
from httpx2_negotiate_sspi import HttpNegotiateAuth

auth = HttpNegotiateAuth(host="adfs.contoso.com")
```

Enable DNS canonicalization when you need CNAME following:

```python
from httpx2_negotiate_sspi import HttpNegotiateAuth

auth = HttpNegotiateAuth(canonicalize_hostname=True)
```

Security
--------

**Always use HTTPS.** HTTP Negotiate authenticates only the initial handshake;
it does not protect the content of subsequent requests or responses. On plain
HTTP there is also no TLS channel binding, which makes relay attacks easier.
The library logs a warning when the request URL scheme is `http`.

Mutual authentication
---------------------

By default, `mutual_authentication=True`. The auth flow raises
`MutualAuthenticationError` (a subclass of `httpx2.HTTPError`) when the server
does not send a valid final authentication token.

**NTLM cannot prove the server's identity.** Set `mutual_authentication=False`
when you know the endpoint only supports NTLM:

```python
auth = HttpNegotiateAuth(mutual_authentication=False)
```

SPN and hostname canonicalization
----------------------------------

The SPN is constructed as `<service>/<host>`, e.g. `HTTP/server.contoso.com`.

- If `host=` is provided, it is always used as-is.
- If `canonicalize_hostname=False` (the default), `request.url.host` is used
  directly. This is safer: DNS canonicalization follows CNAME records, and an
  attacker who controls DNS can choose the SPN.
- If `canonicalize_hostname=True`, the host is resolved through
  `socket.getaddrinfo(..., AI_CANONNAME)`. The original host is used as a
  fallback if DNS fails.

Channel binding
---------------

When the `httpx2` transport exposes an SSL object, the library automatically
includes a `tls-server-end-point` channel binding token (RFC 5929). This
prevents authentication relay attacks and is required by servers that enforce
Extended Protection for Authentication.

The hash algorithm follows RFC 5929 §4.1: use the hash of the certificate's
signature algorithm, promoting MD5 and SHA-1 to SHA-256.

Limitations
-----------

- **HTTPS required for content protection.** HTTP Negotiate authenticates only
  the handshake. Content is not protected on plain HTTP, and channel binding
  is not available.
- **NTLM needs the same TCP connection.** The NTLM handshake is stateful.
  If the connection is closed between the first and second request, the
  authentication will fail.
- **No fallback from Negotiate to NTLM.** The library tries `Negotiate` first
  and then `NTLM` if the server advertises both. It does not fall back from
  Negotiate to NTLM if Negotiate fails to start.
- **Delegation risk.** Only enable `delegate=True` when the remote service is
  trusted to act on the user's behalf (e.g., double-hop scenarios). Delegation
  allows the server to impersonate the user to other services.
- **CI tests NTLM and channel binding, not real Kerberos (IIS job).** The
  Windows IIS job on GitHub-hosted runners is not domain-joined, so it tests
  NTLM. The Linux job runs a real KDC and tests Kerberos.

Configuration reference
-----------------------

| Parameter                 | Type     | Default | Description                                              |
|---------------------------|----------|---------|----------------------------------------------------------|
| `username`                | str      | None    | Username for explicit credentials                        |
| `password`                | str      | None    | Password for explicit credentials                        |
| `domain`                  | str      | `'.'`   | NT domain (`.` = local account). Prepended to username.  |
| `service`                 | str      | `'HTTP'`| Kerberos service class for the SPN                       |
| `host`                    | str      | None    | Explicit SPN host override                               |
| `delegate`                | bool     | False   | Enable ISC_REQ_DELEGATE / GS2 delegation                 |
| `mutual_authentication`   | bool     | **True**| Require the server to prove its identity (**BREAKING**)  |
| `canonicalize_hostname`   | bool     | **False**| Follow CNAME records via DNS (**BREAKING**)             |

Troubleshooting
---------------

- If you receive `401 Unauthorized`, confirm the server advertises `Negotiate`
  or `NTLM` and the account has permission to access the service.
- If `MutualAuthenticationError` is raised with an NTLM server, set
  `mutual_authentication=False`.
- If Kerberos works only with an explicit `host`, verify that the SPN
  registered in Active Directory matches the host you are connecting to.
- On Linux, run `kinit user@REALM` and confirm `klist` shows a valid ticket.
- If a service requires Extended Protection, make sure you are using HTTPS and
  the transport exposes the peer certificate to `httpx2`.
- If `canonicalize_hostname=False` (the default) causes SPN mismatches,
  consider setting `host=` explicitly or enabling `canonicalize_hostname=True`.

Documentation and development
-----------------------------

- Documentation: https://achapkowski.github.io/httpx2_negotiate_sspi
- Source: https://github.com/achapkowski/httpx2_negotiate_sspi
- Issues: https://github.com/achapkowski/httpx2_negotiate_sspi/issues

```console
python -m pip install -e .[dev,doc]
python -m coverage run -m unittest discover -s tests
python -m coverage report -m --fail-under=90
python -m sphinx -W -b html docs docs/_build/html
```

Credits
-------

This package was inspired by
[`requests-negotiate-sspi`](https://github.com/brandond/requests-negotiate-sspi).
