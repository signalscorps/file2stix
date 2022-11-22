"""
Given an SDO object with pattern, this package
returns the corresponding SCO object
"""

import logging

from pattern2sco.get_sco_object import get_sco_objects

__appname__ = "pattern2sco"

# Setup logger for file2stix
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Customize console logging
ch = logging.StreamHandler()  # Logger output will be output to stderr
ch.setLevel(logging.INFO)
formatter = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s")
ch.setFormatter(formatter)

logger.addHandler(ch)