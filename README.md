
![PyPI Python Version](https://img.shields.io/pypi/pyversions/httpx2-kerberos)
![Pepy Total Downloads](https://img.shields.io/pepy/dt/httpx2-kerberos)




httpx2-negotiate-sspi
=====================

An implementation of HTTP Negotiate authentication for httpx2. This
module provides single-sign-on using Kerberos or NTLM using the Windows
SSPI interface.

This module supports Extended Protection for Authentication (aka Channel
Binding Hash), which makes it usable for services that require it,
including Active Directory Federation Services.

Installation
------------

```python
pip install httpx2-kerberos
```

Usage
-----

```python
import httpx2
from httpx2_negotiate_sspi import HttpNegotiateAuth

with httpx2.Client(auth=HttpNegotiateAuth()) as client:
  response = client.get('https://iis.contoso.com')
```

Async clients use the same auth object:

```python
import httpx2
from httpx2_negotiate_sspi import HttpNegotiateAuth

async with httpx2.AsyncClient(auth=HttpNegotiateAuth()) as client:
  response = await client.get('https://iis.contoso.com')
```

Options
-------

  - `username`: Username.  
    Default: None

  - `password`: Password.  
    Default: None

  - `domain`: NT Domain name.  
    Default: '.' for local account.

  - `service`: Kerberos Service type for remote Service Principal
    Name.  
    Default: 'HTTP'

  - `host`: Host name for Service Principal Name.  
    Default: Extracted from request URI

  - `delegate`: Indicates that the user's credentials are to be delegated to the server.
    Default: False


If username and password are not specified, the user's default
credentials are used. This allows for single-sign-on to domain resources
if the user is currently logged on with a domain account.
