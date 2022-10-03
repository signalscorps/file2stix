"""
Provides logging framework for logging errors
"""

import io
import os
import logging
import shutil

logger = logging.getLogger(__name__)


STIX2_LOGS_FOLDER = os.path.abspath("logs")
if os.path.exists(STIX2_LOGS_FOLDER) == False:
    os.makedirs(STIX2_LOGS_FOLDER)
ERROR_STREAM = io.StringIO()

# Error logger
error_logger = logging.getLogger("ERROR_LOGGER")
error_logger.setLevel(logging.INFO)

sh = logging.StreamHandler(ERROR_STREAM)
sh.setLevel(logging.INFO)
formatter = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s")
sh.setFormatter(formatter)

error_logger.addHandler(sh)


def store_error_logs_in_file(bundle_id):
    # Store error logs, if any
    if ERROR_STREAM.getvalue():
        log_file_path = os.path.join(STIX2_LOGS_FOLDER, f"{bundle_id}.txt")
        logger.warning(
            "The script ran into some errors during this run, please check the log file at %s",
            log_file_path,
        )
        with open(log_file_path, "w") as fd:
            ERROR_STREAM.seek(0)
            shutil.copyfileobj(ERROR_STREAM, fd)
