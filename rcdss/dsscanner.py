import datetime
import random
from collections import defaultdict

import dns
import dns.resolver
import dns.dnssec

from .log import logger
from .stats import record, Event


def do_cds_scan(obj):
    """
    Scan for CDS records for given parsed database objects.
    Compare the DS set and return modified database object if
    change is necessarry.
    Otherwise, return None
    """
    domain = obj.get("domain").lower()
    if not domain.endswith("."):
        domain += "."
    logger.info(f"Processing domain: {domain}")

    cds = query_dns(domain)
    if cds is None:
        record(domain, Event.DNS_FAILURE)
        return None
    if cds.rrset is None:
        record(domain, Event.NO_CDS)
        return None
    dnskeyset = query_dns(domain, "DNSKEY")
    if dnskeyset is None or dnskeyset.rrset is None:
        record(domain, Event.DNS_FAILURE)
        return None
    record(domain, Event.HAVE_CDS)
    ds_rdataset = {s.lower() for s in obj.get("ds-rdata", [])}
    logger.debug(f" DS rdataset: {ds_rdataset}")
    cds_rdataset = {rd.to_text().lower() for rd in cds}
    logger.debug(f"CDS rdataset: {cds_rdataset}")
    if cds_rdataset == ds_rdataset:
        record(domain, Event.CDS_NOOP)
        logger.info(f"No change requested for {domain}")
    else:
        if not check_inception_date(obj, cds):
            record(domain, Event.OLD_SIG)
            logger.warning(f"CDS signature inception too old for {domain}")
            return None
        if not check_signed_by_KSK(cds, ds_rdataset, dnskeyset):
            record(domain, Event.NOT_SIGNED_BY_KSK)
            logger.warning(
                f"CDS of {domain} not properly "
                f"signed by current KSK",
            )
            return None
        obj["old-ds-rdata"] = obj.pop("ds-rdata")
        if is_delete_cds(cds):
            record(domain, Event.CDS_DELETE)
            obj["reason"] = "DNSSEC delegation deleted by CDS record"
            logger.info(f"DS deletion requested for {domain}")
        elif not check_CDS_continuity(cds, dnskeyset):
            record(domain, Event.CDS_CONTINUITY_ERR)
            logger.warning(
                f"DNSKEY of {domain} not properly "
                f"signed by CDS records",
            )
            return None
        else:
            record(domain, Event.CDS_UPDATE_PENDING)
            logger.info(f"DS should be updated for {domain}")
            obj["ds-rdata"] = list(cds_rdataset)
            obj["reason"] = "Updated by CDS record"
        return obj


def query_dns(domain, rdtype="CDS"):
    """Make a query to the local resolver. Return answer object."""
    default_resolver = dns.resolver.get_default_resolver()
    # We use separate resolver instance per query
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = default_resolver.nameservers
    if default_resolver.rotate:
        random.shuffle(resolver.nameservers)
    resolver.flags = dns.flags.RD
    resolver.use_edns(0, dns.flags.DO, 1200)
    try:
        return resolver.resolve(domain, rdtype, raise_on_no_answer=False)
    except dns.resolver.NoNameservers:
        # Is this a DNSSEC failure?
        try:
            resolver.flags |= dns.flags.CD
            resolver.resolve(domain, rdtype, raise_on_no_answer=False)
            logger.warning(f"Bogus DNSSEC for domain: {domain}")
            record(domain, Event.DNS_BOGUS)
        except dns.exception.DNSException as e:
            logger.warning(f"Non-DNSSEC related exception: {e}")
            record(domain, Event.DNS_LAME)
    except dns.resolver.Timeout:
        logger.warning(f"DNS timeout for domain: {domain}")
        record(domain, Event.DNS_TIMEOUT)
    except dns.exception.DNSException as e:
        logger.warning(f"DNS exception: {e}")


def get_rrsigset(response):
    """Return Rdataset of RRSIGs covering queried RRTYPE"""
    return response.find_rrset(
        response.answer,
        response.question[0].name,
        response.question[0].rdclass,
        dns.rdatatype.RRSIG,
        response.question[0].rdtype,
    )


def is_delete_cds(cds):
    """
    Return True if CDSset contains one and only
    CDS record using DNSSEC Delete Algorithm (RFC 8078 section-4)
    """
    return (
        len(cds) == 1 and
        cds[0].key_tag == 0 and
        cds[0].algorithm == 0 and
        cds[0].digest_type == 0 and
        cds[0].digest == b'\x00'
    )


def check_inception_date(obj, cds):
    """
    Check whether the oldest DNSSEC signature inception is newer
    than the last-modified attribute of the domain object.

    As per RFC 7344 section-6.2, we MUST ensure that previous
    versions of the CDS RRset do not overwrite more recent versions.
    This is an easy way to accomplish it without having to store
    a new state anywhere.
    """
    lm = obj.get("last-modified")
    lm = datetime.datetime.strptime(lm, "%Y-%m-%dT%H:%M:%SZ")
    lm = lm.replace(tzinfo=datetime.timezone.utc)
    rrsigs = get_rrsigset(cds.response)
    # There can be more signatures. We will look for the oldest.
    inception = min([
        datetime.datetime.fromtimestamp(
            sig.inception,
            datetime.timezone.utc,
        ) for sig in rrsigs
    ])
    logger.debug(f"Inception: {inception}, last modified: {lm}")
    return inception > lm


def filter_dnskey_set(dnskeyset, dsset):
    """
    Return a set of DNSKEYs with only keys
    matching fingerprints in the dsset.
    """
    s = set()
    for dnskey in dnskeyset:
        key_id = dns.dnssec.key_id(dnskey)
        for ds in dsset:
            if ds.key_tag != key_id:
                continue
            try:
                if ds == dns.dnssec.make_ds(
                    dnskeyset.name,
                    dnskey,
                    ds.digest_type,
                ):
                    s.add(dnskey)
            except dns.dnssec.UnsupportedAlgorithm:
                pass
    return s


def check_signed_by_KSK(cds, ds_rdataset, dnskeyset):
    """
    Check if the CDS is actually signed by a key contained in the
    current DS RRSET as per RFC 7344 section 4.1
    """
    dsset = {
        dns.rdata.from_text(
            dns.rdataclass.IN, dns.rdatatype.DS,
            rdata,
        ) for rdata in ds_rdataset
    }
    keyset = filter_dnskey_set(dnskeyset, dsset)
    try:
        dns.dnssec.validate(
            cds.rrset,
            get_rrsigset(cds.response),
            {cds.name: keyset},
        )
        return True
    except dns.dnssec.ValidationFailure:
        return False


def check_CDS_continuity(cds, dnskeyset):
    """
    Check if the CDS, when applied, will not break the current delegation
    as per RFC 7344 section 4.1

    In a nutshell this means that at least one of the CDS rdata must be
    used to sign zone's DNSKEY record for each signature algorithm present.
    """
    dssets = defaultdict(set)
    for ds in (
        dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.DS,
            rdata.to_text(),
        ) for rdata in cds.rrset
    ):
        dssets[ds.algorithm].add(ds)
    try:
        for alg, dsset in dssets.items():
            logger.debug(
                "Validating CDS continuity for algorithm %s.",
                dns.dnssec.algorithm_to_text(alg),
            )
            keyset = filter_dnskey_set(dnskeyset, dsset)
            dns.dnssec.validate(
                dnskeyset.rrset,
                get_rrsigset(dnskeyset.response),
                {cds.name: keyset},
            )
        return True
    except dns.dnssec.ValidationFailure:
        return False
