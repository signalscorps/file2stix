"""
Stores the config of file2stix-cli tool
"""
from dataclasses import dataclass
from stix2 import Identity, ExtensionDefinition, MarkingDefinition, TLP_WHITE
from typing import List
from pathlib import Path
import os

FILE2STIX_FOLDER = Path(os.path.abspath(__file__)).parent
STIX_TEMPLATES_FOLDER = FILE2STIX_FOLDER / "stix_templates"

DEFAULT_USER_IDENTITY_FILE = STIX_TEMPLATES_FOLDER / "file2stix-identity.yml"

@dataclass
class Config:
    input_file_path: str = None
    output_json_file_path: str = None
    custom_extraction_file: str = None
    cache_folder: str = "file2stix-cache"

    tlp_level: MarkingDefinition = TLP_WHITE
    user_identity_file: str = DEFAULT_USER_IDENTITY_FILE
    identity: Identity = None

    misp_extension_definition_file: str = STIX_TEMPLATES_FOLDER / "extension-definition.yml"
    misp_extension_definition: ExtensionDefinition = None
    misp_custom_warning_list_file: str = None
    misp_custom_warning_list: dict = None

    update_mitre_cti_database: bool = False
    ignore_observables_list: List = None
    defang_observables: bool = False
 
    backend: str = None
