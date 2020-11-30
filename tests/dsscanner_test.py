import dns
import dns.rdtypes.ANY.CDS
from rcdss import dsscanner


def test_query_dns():
    a = dsscanner.query_dns("ripe.net", "SOA")
    assert a is not None


def test_check_inception_date():
    obj = {"last-modified": "1970-01-01T00:00:00Z"}
    # We query for SOA to make sure it is always there
    cds = dsscanner.query_dns("ripe.net", "SOA")
    assert dsscanner.check_inception_date(obj, cds)
    obj = {"last-modified": "2100-01-01T00:00:00Z"}
    assert not dsscanner.check_inception_date(obj, cds)


def test_is_delete_cds():
    rds = dns.rrset.RRset("example.", dns.rdataclass.IN, dns.rdatatype.CDS)
    assert not dsscanner.is_delete_cds(rds)
    rd = dns.rdtypes.ANY.CDS.CDS(
        dns.rdataclass.IN, dns.rdatatype.CDS,
        0, 0, 0, b"\0",
    )
    rds.add(rd)
    assert dsscanner.is_delete_cds(rds)
    rds = dns.rrset.RRset("example.", dns.rdataclass.IN, dns.rdatatype.CDS)
    rd2 = dns.rdtypes.ANY.CDS.CDS(
        dns.rdataclass.IN, dns.rdatatype.CDS,
        0, 0, 0, b"0",
    )
    rds.add(rd2)
    assert not dsscanner.is_delete_cds(rds)
    rds.add(rd)
    assert not dsscanner.is_delete_cds(rds)


def test_filter_dnskey_set():
    # Example from RFC 4034 section 5.4
    dskey_example_com_dnskey = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        """256 3 5 ( AQOeiiR0GOMYkDshWoSKz9Xz
                         fwJr1AYtsmx3TGkJaNXVbfi/
                         2pHm822aJ5iI9BMzNXxeYCmZ
                         DRD99WYwYqUSdjMmmAphXdvx
                         egXd/M5+X7OrzKBaMbCVdFLU
                         Uh6DhweJBjEVv5f2wwjM9Xzc
                         nOf+EPbtG9DMBmADjFDc2w/r
                         ljwvFw==
                         ) ;  key id = 60485""",
    )
    dskey_example_com_ds = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.DS,
        """60485 5 1 ( 2BB183AF5F22588179A53B0A
            98631FAD1A292118 )""",
    )
    # RFC 4034 section 2.3
    example_com_dnskey = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
        """256 3 5 ( AQPSKmynfzW4kyBv015MUG2DeIQ3
                         Cbl+BBZH4b/0PY1kxkmvHjcZc8no
                         kfzj31GajIQKY+5CptLr3buXA10h
                         WqTkF7H6RfoRqXQeogmMHfpftf6z
                         Mv1LyBUgia7za6ZEzOJBOztyvhjL
                         742iU/TpPSEDhm2SNKLijfUppn1U
                         aNvv4w==  )""",
    )
    unknown_ds = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.DS,
        """60485 5 1 ( 2BB183AF5F22DEADBEEFCAFE
            98631FAD1A292118 )""",
    )
    keyset = dns.rrset.RRset(
        dns.name.from_text("dskey.example.com."),
        dns.rdataclass.IN,
        dns.rdatatype.DNSKEY,
    )
    keyset.add(dskey_example_com_dnskey)
    keyset.add(example_com_dnskey)
    dsset = dns.rrset.RRset(
        dns.name.from_text("dskey.example.com."),
        dns.rdataclass.IN,
        dns.rdatatype.DS,
    )
    dsset.add(unknown_ds)
    dsset.add(dskey_example_com_ds)
    filtered = dsscanner.filter_dnskey_set(keyset, dsset)
    assert dskey_example_com_dnskey in filtered
    assert example_com_dnskey not in filtered
