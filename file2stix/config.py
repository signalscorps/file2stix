"""
Stores the config of file2stix-cli tool
"""
from dataclasses import dataclass
from stix2 import Identity, ExtensionDefinition, MarkingDefinition, TLP_WHITE
from typing import List
from pathlib import Path
import os
from file2stix.observables_stix_store import ObservablesStixStore

FILE2STIX_FOLDER = Path(os.path.abspath(__file__)).parent
STIX2_OBJECTS_FOLDER = FILE2STIX_FOLDER / "stix2-objects"
STIX2_OBJECTS_STORE = ObservablesStixStore(STIX2_OBJECTS_FOLDER)


@dataclass
class Config:
    input_file_path: str = None
    output_json_file_path: str = None
    custom_extraction_file: str = None
    cache_folder: str = "file2stix-cache"

    extraction_mode: str = "analysis"
    tlp_level: MarkingDefinition = TLP_WHITE
    identity: Identity = None

    cve_extension_definition = STIX2_OBJECTS_STORE.get_object("NVD CVEs")

    misp_extension_definition: ExtensionDefinition = STIX2_OBJECTS_STORE.get_object(
        "MISP Warning Lists"
    )
    misp_custom_warning_list_file: str = None
    misp_custom_warning_list: dict = None

    update_mitre_cti_database: bool = False
    ignore_observables_list: List = None
    defang_observables: bool = False

    backend: str = None
