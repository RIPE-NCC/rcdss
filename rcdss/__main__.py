
import sys
import logging

from .dsscanner import do_cds_scan
from .log import logger, log_format
from . import rpsl


def main():
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(log_format)
    logger.addHandler(handler)
    for obj in rpsl.parse_rpsl_objects(sys.stdin):
        o = do_cds_scan(obj)
        if o is not None:
            print(rpsl.write_rpsl_object(o))


if __name__ == "__main__":
    main()
