"""
Handles the obstracts cache, which stores
MITRE CTI and MISP warning list dataset
"""

import git
import logging
import os

logger = logging.getLogger(__name__)

class Cache:
    MITRE_CTI_GITHUB_URL = "https://github.com/mitre/cti"
    MITRE_CTI_FOLDER_NAME = "cti"

    def __init__(self, cache_folder_path):
        self.cache_folder_path = cache_folder_path
        if not os.path.isdir(cache_folder_path):
            logger.info("Creating cache folder %s", cache_folder_path)
            os.makedirs(cache_folder_path)

        self.cti_folder_path = os.path.join(self.cache_folder_path, Cache.MITRE_CTI_FOLDER_NAME)
    
    def update_mitre_cti_database(self):
        if os.path.isdir(self.cti_folder_path):
            logger.info("Pulling latest changes from %s", Cache.MITRE_CTI_GITHUB_URL)
            g = git.cmd.Git(self.cti_folder_path)
            g.pull()
        else:
            logger.info("Cloning latest changes from %s", Cache.MITRE_CTI_GITHUB_URL)
            git.Repo.clone_from(Cache.MITRE_CTI_GITHUB_URL, self.cti_folder_path)

    def is_mitre_cti_database_in_cache(self):
        return os.path.isdir(self.cti_folder_path)