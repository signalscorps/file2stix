"""
Obstracts CLI tool.
"""

import logging

__appname__ = "obsctracts-cli"

# Setup logger for obstracts CLI
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Customize console logging
ch = logging.StreamHandler()  # Logger output will be output to stderr
ch.setLevel(logging.INFO)
formatter = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s")
ch.setFormatter(formatter)

logger.addHandler(ch)