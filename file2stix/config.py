"""
Stores the config of file2stix-cli tool
"""
from dataclasses import dataclass
from stix2 import Identity

@dataclass
class Config:
    input_file_path: str
    custom_extraction_file: str
    cache_folder: str = "file2stix-cache"
    update_mitre_cti_database: bool = False
    tlp_level: str = "WHITE"
    user_identity_file: str = "stix_templates/identity.yml"
    identity: Identity = None
    