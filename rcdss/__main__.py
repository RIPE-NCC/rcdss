
import sys
import gzip
import json
import threading
from queue import Queue, Empty
try:
    from queue import SimpleQueue
except ImportError:  # Python 3.6 lacks SimpleQueue
    SimpleQueue = Queue

import click
import dns.resolver
import dns.inet

from .dsscanner import do_cds_scan
from .log import setup_logger, logger
from .stats import report_counts, report_domains
from . import rpsl
from . import __version__


def setup_resolvers(nss):
    default_resolver = dns.resolver.get_default_resolver()
    nameservers = []
    for ns in nss:
        if dns.inet.is_address(ns):
            nameservers.append(ns)
        else:
            for rdtype in ["AAAA", "A"]:
                r = dns.resolver.resolve(ns, rdtype, raise_on_no_answer=False)
                nameservers.extend(a.address for a in r)
    default_resolver.nameservers = nameservers
    logger.debug("Configured DNS resolvers: %s", ", ".join(nameservers))

    # If more than one nameserver is specified, then we probably want
    # to use them all, not just the first one.
    if len(nss) > 1:
        default_resolver.rotate = True


def scanThread(inq, outq):
    while True:
        obj = inq.get()
        o = do_cds_scan(obj)
        if o:
            outq.put(o)
        inq.task_done()


@click.command()
@click.option(
    "--input", "-i", "input_", type=click.Path(exists=True, dir_okay=False, ),
    help="Read latin1 encoded file containing domain objects, "
         "optionally compressed with Gzip, instead of standard input",
)
@click.option(
    "--output", "-o", type=click.File("w", atomic=True, lazy=False),
    default=sys.stdout, help="Output RPSL-like file "
    "[default: stdout]",
)
@click.option(
    "--logfile", "-l", type=click.Path(dir_okay=False, writable=True,),
    help="Log file, automatically rotated",
)
@click.option(
    "--verbose", "-v", count=True,
    help="Increase verbosity (use twice for debug info)",
)
@click.option(
    "--threads", "-t", default=15, type=click.IntRange(1), show_default=True,
    help="Number of scanning threads", metavar="INT",
)
@click.option(
    "--ns", multiple=True, help="Use this nameserver"
    " (may be used multiple times)", metavar="ADDR",
)
@click.option(
    "--dump-stats", type=click.File("w", atomic=True,),
    help="Dump domain stats to a JSON file",
)
@click.version_option(__version__)
def main(input_, output, logfile, verbose, threads, ns, dump_stats):
    """
    Scan for CDS record for given DOMAIN objects.
    """
    setup_logger(logfile, verbose)

    if input_ is None:
        inf = sys.stdin
    elif input_.lower().endswith(".gz"):
        inf = gzip.open(input_, "rt", encoding="latin1")
    else:
        inf = open(input_, "rt", encoding="latin1")

    if ns:
        setup_resolvers(ns)

    inq = Queue()
    outq = SimpleQueue()

    for _ in range(threads):
        threading.Thread(
            target=scanThread,
            args=(inq, outq,),
            daemon=True,
        ).start()

    for obj in filter(
        lambda obj: "ds-rdata" in obj,
        rpsl.parse_rpsl_objects(inf),
    ):
        inq.put(obj)

    inq.join()
    try:
        while True:
            o = outq.get_nowait()
            print(rpsl.write_rpsl_object(o), file=output)
    except Empty:
        pass
    logger.info("Finished. Here are some stats:\n%s", report_counts())
    if dump_stats:
        json.dump(
            {k.name: v for k, v in report_domains().items()},
            dump_stats,
            indent=4,
        )


if __name__ == "__main__":
    main()
