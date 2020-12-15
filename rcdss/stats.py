
from enum import Enum, auto
from collections import defaultdict

_RECORDS = defaultdict(list)


class Event(Enum):
    HAVE_CDS = auto()
    NO_CDS = auto()
    OLD_SIG = auto()
    NOT_SIGNED_BY_KSK = auto()
    CDS_DELETE = auto()
    CDS_CONTINUITY_ERR = auto()
    CDS_UPDATE_PENDING = auto()
    CDS_NOOP = auto()


def record(domain: str, event: Event):
    """Record an event during processing a domain name"""
    _RECORDS[event].append(domain)


def report_counts():
    """Return simple report of recorded events"""
    output = []
    for name, event in Event.__members__.items():
        count = len(_RECORDS[event])
        output.append(f"{name:<20} {count}")
    return "\n".join(output)
