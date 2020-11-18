
import sys
import logging
import shelve

import click

from .dsscanner import do_cds_scan
from .log import logger, log_format
from . import rpsl
from . import __version__


@click.command()
@click.option(
    "--shelf", "-s",
    type=click.Path(file_okay=True, readable=True),
    help="Shelve file to read, have precedence over -i",
)
@click.option(
    "--infile", "-i", type=click.File("r"),
    default=sys.stdin, help="Input RPSL file if no shelf "
    "file is provided",
)
@click.option(
    "--outfile", "-o", type=click.File("w"),
    default=sys.stdout, help="Path of the output file",
)
@click.version_option(__version__)
def main(shelf, infile, outfile):
    """
    Scan for CDS record for given DOMAIN objects.
    """
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(log_format)
    logger.addHandler(handler)
    if shelf is not None:
        s = shelve.open(shelf)
        infile = (line for obj in s.values() for line in (obj + ["\n"]))
    for obj in rpsl.parse_rpsl_objects(infile):
        o = do_cds_scan(obj)
        if o is not None:
            print(rpsl.write_rpsl_object(o), file=outfile)


if __name__ == "__main__":
    main()
