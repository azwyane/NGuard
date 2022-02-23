import logging
import sys
LOG_TEMPLATE = "%(levelname)s %(asctime)s - %(message)s"

def logger(logpath):
    logging.basicConfig(
                        format = LOG_TEMPLATE,
                        level = logging.INFO,
                        handlers=[
                                    logging.FileHandler(logpath),
                                    logging.StreamHandler(sys.stdout)
                                ],
                        )
    return logging.getLogger()