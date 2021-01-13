from rcdss import rpsl

testobject = """\
domain:         83.204.91.in-addr.arpa
descr:          CDS test
notify:         ondrej.caletka@ripe.net
nserver:        flexi.oskarcz.net
nserver:        auron.oskarcz.eu
admin-c:        DUMY-RIPE
tech-c:         DUMY-RIPE
zone-c:         DUMY-RIPE
ds-rdata:       39498 13 2 9FA8FB7A9D59BEE035502284202A544D8A6590180
+ACD68490190121AB6EE3F0C
mnt-by:         OC-RIPE-MNT
created:        2020-11-10T19:57:33Z
last-modified:  2020-11-10T21:03:20Z
source:         RIPE
remarks:        ****************************
remarks:        * THIS OBJECT IS MODIFIED
remarks:        * Please note that all data that is
 generally regarded as personal
remarks:        * data has been removed from this object.
remarks:        * To view the original object,
 please query the RIPE Database at:
remarks:        * http://www.ripe.net/whois
remarks:        ****************************
""".splitlines()


def test_parse_rpsl_object():
    o = rpsl.parse_rpsl_object(testobject)
    assert o["domain"] == "83.204.91.in-addr.arpa"
    assert o["nserver"] == ["flexi.oskarcz.net", "auron.oskarcz.eu"]
    assert o["last-modified"] == "2020-11-10T21:03:20Z"


def test_parse_rpsl_objects():
    testdoc = testobject + ["\n"] + testobject
    objs = list(rpsl.parse_rpsl_objects(testdoc))
    assert len(objs) == 2
    assert objs[0] == objs[1]
    assert objs[0]["domain"] == "83.204.91.in-addr.arpa"
    assert objs[0]["ds-rdata"] == [
        "39498 13 2 9FA8FB7A9D59BEE03550"
        "2284202A544D8A6590180ACD6849019"
        "0121AB6EE3F0C",
    ]


def test_write_rpsl_object():
    o = next(rpsl.parse_rpsl_objects(testobject))
    r = rpsl.write_rpsl_object(o)
    assert r == (
        """\
domain:         83.204.91.in-addr.arpa
descr:          CDS test
nserver:        flexi.oskarcz.net
nserver:        auron.oskarcz.eu
ds-rdata:       39498 13 2 9FA8FB7A9D59BEE035502284202A5""" +
        """44D8A6590180ACD68490190121AB6EE3F0C
created:        2020-11-10T19:57:33Z
last-modified:  2020-11-10T21:03:20Z
"""
    )
