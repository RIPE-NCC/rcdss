
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
    help="Shelf file to read, have precedence over -i",
)
@click.option(
    "--input", "-i", "input_", type=click.File("r"),
    default=sys.stdin, help="Input RPSL file if no shelf "
    "file is provided [default: stdin]",
)
@click.option(
    "--output", "-o", type=click.File("w"),
    default=sys.stdout, help="Output RPSL-like file "
    "[default: stdout]",
)
@click.version_option(__version__)
def main(shelf, input_, output):
    """
    Scan for CDS record for given DOMAIN objects.
    """
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(log_format)
    logger.addHandler(handler)
    if shelf is not None:
        s = shelve.open(shelf)
        input_ = (line for obj in s.values() for line in (obj + ["\n"]))
    for obj in rpsl.parse_rpsl_objects(input_):
        o = do_cds_scan(obj)
        if o is not None:
            print(rpsl.write_rpsl_object(o), file=output)


if __name__ == "__main__":
    main()
