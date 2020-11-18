RIPE NCC CDS scanner
====================

This software implements support for automated DNSSEC delegation
trust maintenance for the reverse DNS zones delegated by RIPE database.
It implements scanning of CDS records according to [RFC
7344](https://tools.ietf.org/html/rfc7344) and [RFC
8078](https://tools.ietf.org/html/rfc8078).

Only trust anchor update and remove is supported. Going from
insecure to secure is not supported.

It reads a dump of DOMAIN objects from the RIPE database. Only domain objects
containing `ds-rdata` attributes are processed.

CDS records are scanned using OS resolver, which MUST be DNSSEC-aware and
DNSSEC validating. The utility outputs RPSL-like file with all objects that
should be modified in the RIPE database. Those objects are however not complete
and cannot be pushed directly to the RIPE database.
