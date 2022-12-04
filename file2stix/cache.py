"""
Handles the obstracts cache, which stores
MITRE CTI and MISP warning list dataset
"""

import logging
import os
import subprocess

logger = logging.getLogger(__name__)


class Cache:
    MITRE_CTI_GITHUB_URL = "https://github.com/mitre/cti"
    MITRE_CTI_FOLDER_NAME = "cti"
    MITRE_CTI_CAPEC_FOLDER_NAME = "cti-capec"
    MITRE_CTI_ATTACK_FOLDER_NAME = "cti-attack"

    def __init__(self, cache_folder_path):
        self.cache_folder_path = cache_folder_path
        if not os.path.isdir(cache_folder_path):
            logger.info("Creating cache folder %s", cache_folder_path)
            os.makedirs(cache_folder_path)

        self.cti_folder_path = os.path.join(
            self.cache_folder_path, Cache.MITRE_CTI_FOLDER_NAME
        )

    def update_mitre_cti_database(self, mitre_attack_version=None):
        if os.path.isdir(self.cti_folder_path):
            logger.info("Pulling latest changes from %s", Cache.MITRE_CTI_GITHUB_URL)
        else:
            logger.info("Cloning latest changes from %s", Cache.MITRE_CTI_GITHUB_URL)
            subprocess.run(
                f"git -C {self.cache_folder_path} clone {Cache.MITRE_CTI_GITHUB_URL}".split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        subprocess.run(
            f"git -C {self.cti_folder_path} fetch --tags".split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if mitre_attack_version != None:
            subprocess.run(
                f"git -C {self.cti_folder_path} checkout {mitre_attack_version}".split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        else:
            subprocess.run(
                f"git -C {self.cti_folder_path} checkout master".split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

    def is_mitre_cti_database_in_cache(self):
        return os.path.isdir(self.cti_folder_path)
