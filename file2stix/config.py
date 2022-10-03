"""
Stores the config of file2stix-cli tool
"""
from dataclasses import dataclass
from stix2 import Identity, ExtensionDefinition, MarkingDefinition, TLP_WHITE, ExternalReference
from typing import List
from pathlib import Path
import os
from file2stix.observables_stix_store import ObservablesStixStore

FILE2STIX_FOLDER = Path(os.path.abspath(__file__)).parent
STIX2_OBJECTS_FOLDER = FILE2STIX_FOLDER / "stix2-objects"
STIX2_OBJECTS_STORE = ObservablesStixStore(STIX2_OBJECTS_FOLDER)


@dataclass
class Config:
    # File-handling related options
    input_file_path: str = None
    output_json_file_path: str = None
    output_preprocessed_file: str = None
    custom_extraction_file: str = None
    cache_folder: str = "file2stix-cache"
    update_mitre_cti_database: bool = False

    # STIX2 Report related options
    identity: Identity = STIX2_OBJECTS_STORE.get_object("file2stix")
    tlp_level: MarkingDefinition = TLP_WHITE
    extraction_mode: str = "analysis"
    confidence: int = None

    # Observable related options
    ignore_observables_list: List = None
    defang_observables: bool = False
    ignore_warninglist_observables: bool = False

    # MISP extension and warning list options
    misp_extension_definition: ExtensionDefinition = STIX2_OBJECTS_STORE.get_object(
        "MISP Warning Lists"
    )
    misp_custom_warning_list_file: str = None
    misp_custom_warning_list: dict = None
    cve_extension_definition = STIX2_OBJECTS_STORE.get_object("NVD CVEs")

    # Miscellaneous options
    fail_on_errors: bool = False
    branding_external_ref = ExternalReference(
        source_name="file2stix",
        description="This object was created using file2stix from the Signals Corps.",
        url="https://github.com/signalscorps/file2stix",
    )
    backend: str = None