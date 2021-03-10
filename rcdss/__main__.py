
import sys
import gzip
import json

import click

from .dsscanner import do_cds_scan
from .log import setup_logger, logger
from .stats import report_counts, report_domains
from . import rpsl
from . import __version__


@click.command()
@click.option(
    "--input", "-i", "input_", type=click.Path(exists=True, dir_okay=False, ),
    help="Read latin1 encoded file containing domain objects, "
         "optionally compressed with Gzip, instead of standard input",
)
@click.option(
    "--output", "-o", type=click.File("w"),
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
    "--dump-stats", type=click.File("w"),
    help="Dump domain stats to a JSON file",
)
@click.version_option(__version__)
def main(input_, output, logfile, verbose, dump_stats):
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

    for obj in rpsl.parse_rpsl_objects(inf):
        if "ds-rdata" not in obj:
            continue
        o = do_cds_scan(obj)
        if o is not None:
            print(rpsl.write_rpsl_object(o), file=output)
    logger.info("Finished. Here are some stats:\n%s", report_counts())
    if dump_stats:
        json.dump(
            {k.name: v for k, v in report_domains().items()},
            dump_stats,
            indent=4,
        )


if __name__ == "__main__":
    main()
