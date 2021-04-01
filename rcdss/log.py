import logging
import logging.handlers


logger = logging.getLogger(__name__)


def setup_logger(logfile, verbose):
    if verbose > 1:
        logger.setLevel(logging.DEBUG)
    elif verbose == 1:
        logger.setLevel(logging.INFO)
    if logfile is not None:
        handler = logging.handlers.TimedRotatingFileHandler(
            filename=logfile,
            when='midnight',
            backupCount=30,
        )
    else:
        handler = logging.StreamHandler()
    log_format = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    handler.setFormatter(log_format)
    logger.addHandler(handler)
