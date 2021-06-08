RIPE NCC CDS scanner
====================

This utility implements support for automated DNSSEC delegation
trust maintenance for the reverse DNS zones delegated by RIPE database.
It implements scanning for CDS records according to [RFC
7344](https://tools.ietf.org/html/rfc7344) and [RFC
8078](https://tools.ietf.org/html/rfc8078).

Only trust anchor update and remove is supported. Bootstrapping from
insecure to secure is not supported.

It reads a [dump of DOMAIN objects](https://ftp.ripe.net/ripe/dbase/split/ripe.db.domain.gz) from the RIPE database. Only domain objects
containing `ds-rdata:` attributes are processed.

CDS records are scanned using default resolver of the host, which MUST be
DNSSEC-aware and DNSSEC validating. The utility outputs RPSL-like file listing
objects that should be modified in the RIPE database. Since the scanner works
with *dummyfied* objects, output cannot be directly pushed into the Database.
Instead, it has to be used as a diff-file for a GET-modify-PUT operation on the
database.

DNSSEC algorithm support
------------------------

The utility requires all DNS responses from the resolver to carry the `AD` flag
to prove they have been properly validated by it. It also does some extra
validations mandated by RFC 7344. These are done using
[dnspython](https://www.dnspython.org/). The list of supported algorithms is
therefore limited by their support in the resolver and the library.

In theory, the requirement for the `AD` flag could be relaxed since the extra
validations provide similar level of trust. This would allow proper operation
even with algorithms unsupported by the resolver.

Installation and usage
----------------------

This package can be installed using [`pip`](https://pypi.org/project/pip/),
preferably into its own
[`virtualenv`](https://docs.python.org/3/tutorial/venv.html).

    $ python3 -m venv rcdss-venv
    $ source rcdss-venv/bin/activate
    (rcdss-venv)$ pip install rcdss
    (rcdss-venv)$ rcdss --help
