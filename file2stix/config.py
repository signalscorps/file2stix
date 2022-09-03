"""
Stores the config of file2stix-cli tool
"""
from dataclasses import dataclass
from stix2 import Identity, ExtensionDefinition
from typing import List


@dataclass
class Config:
    input_file_path: str = None
    output_json_file_path: str = None
    custom_extraction_file: str = None
    cache_folder: str = "file2stix-cache"

    tlp_level: str = "WHITE"
    user_identity_file: str = "stix_templates/identity.yml"
    identity: Identity = None

    misp_extension_definition_file: str = "stix_templates/extension-definition.yml"
    misp_extension_definition: ExtensionDefinition = None
    misp_custom_warning_list_file: str = None
    misp_custom_warning_list: dict = None

    update_mitre_cti_database: bool = False
    ignore_observables_list: List = None
