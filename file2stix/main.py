"""
Implements a command line interface, which takes in a text file
and outputs observables found (in STIX format).
"""

import logging
import os
import pytz
import sys
import textract
import json
import yaml
from bs4 import BeautifulSoup
from datetime import datetime
from pathlib import Path
from stix2 import Report, Relationship, Identity, ExtensionDefinition, TLP_WHITE
from pymispwarninglists.api import WarningList

from file2stix import __appname__
from file2stix.cache import Cache
from file2stix.config import Config
from file2stix.extract_observables import ExtractStixObservables
from file2stix.helper import inheritors, nested_dict_values
from file2stix.observables_stix_store import ObservablesStixStore
from file2stix.observables import Observable, CustomObservable, CPEObservable

logger = logging.getLogger(__name__)


class IdentityError(Exception):
    pass


def get_text_from_xml_or_html(input_file_path):
    """
    Extracts only text content from the xml document
    """
    with open(input_file_path, "r") as f:
        soup = BeautifulSoup(f, "xml")

    text_list = soup.find_all(text=True)
    return "".join(text_list)


def get_text_from_json(input_file_path):
    with open(input_file_path, "r") as f:
        data = json.load(f)

    values = list(nested_dict_values(data))
    return "\n".join([str(value) for value in values])


def get_text_from_markdown(input_file_path):
    with open(input_file_path, "r") as f:
        soup = BeautifulSoup(f, "lxml")

    text_list = soup.find_all(text=True)
    return "".join(text_list)


class ObservableList:
    def __init__(self):
        # General set of stix observables
        self.stix_observables = {}

        # Stix observables which are dictionaries
        self.dict_stix_observables = {}

        # Custom stix observables by the user
        self.custom_stix_observables = {}

    def __str__(self):
        return f"ObservablesList({self.stix_observables}, {self.dict_stix_observables}, {self.custom_stix_observables})"


def main(config: Config):
    cache = Cache(config.cache_folder)

    # Set user identity
    if config.tlp_level != TLP_WHITE:
        try:
            with open(config.user_identity_file) as f:
                identity_config = yaml.safe_load(f)
            config.identity = Identity(**identity_config)
        except:
            raise IdentityError(
                "Identity config file is not present or is in incorrect format."
            )
    try:
        with open(config.misp_extension_definition_file) as f:
            misp_extension_definition_config = yaml.safe_load(f)
        config.misp_extension_definition = ExtensionDefinition(
            **misp_extension_definition_config
        )
    except Exception as ex:
        logger.warning(
            "Failed to load MISP extension definition file at %s",
            config.misp_extension_definition_file,
        )
        logger.debug("Exception caught when init MISP extension: %s", ex)

    if config.misp_custom_warning_list_file:
        try:
            with open(config.misp_custom_warning_list_file) as f:
                misp_custom_warning_list = json.load(f)
            WarningList(
                misp_custom_warning_list
            )  # Just to validate if the format is correct
            config.misp_custom_warning_list = misp_custom_warning_list
        except Exception as ex:
            logger.warning(
                "Failed to load MISP custom warning list file at %s",
                config.misp_custom_warning_list_file,
            )
            logger.debug(
                "Exception caught when parsing MISP custom warning list: %s", ex
            )

    # Update MITRE ATT&CK and CAPEC database
    if config.update_mitre_cti_database == True:
        cache.update_mitre_cti_database()

    if config.input_file_path == None:
        logger.info("No input file given. Exiting...")
        logger.info("Run '%s --help' for usage instructions", __appname__)
        sys.exit(0)

    input_file_path = config.input_file_path
    file_name, file_extension = os.path.splitext(input_file_path)
    input = None

    # Handle some file extensions specially
    if file_extension in (".xml", ".html"):
        input = get_text_from_xml_or_html(input_file_path)
    elif file_extension == ".json":
        input = get_text_from_json(input_file_path)
    elif file_extension == ".md":
        input = get_text_from_markdown(input_file_path)
    elif file_extension in (".yml", ".yaml", ".yara", ".yar"):
        input = Path(input_file_path).read_text()
    else:
        input = textract.process(input_file_path).decode("UTF-8")

    logger.info("Reading input file %s ...", input_file_path)

    stix_store = ObservablesStixStore()

    # Iterate over each observable and extract them from input file
    observables_list = ObservableList()
    for observable in inheritors(Observable):
        if (
            config.ignore_observables_list != None
            and observable in config.ignore_observables_list
        ):
            logger.info("%s is ignored from extraction", observable.__name__)
            continue
        for extracted_stix_observable in ExtractStixObservables(
            observable, input, cache, config
        ):
            stix_observable_object = extracted_stix_observable

            # Check if observable already present in `stix_store`
            if config.tlp_level == TLP_WHITE and hasattr(
                extracted_stix_observable, "name"
            ):
                stix_observable_object = stix_store.get_object(
                    extracted_stix_observable.name,
                    config.tlp_level.id,
                )

                # Don't create a new version for CPE Observable
                if stix_observable_object != None and observable != CPEObservable:
                    stix_observable_object = stix_observable_object.new_version(
                        modified=pytz.utc.localize(datetime.utcnow())
                    )
                else:
                    stix_observable_object = extracted_stix_observable

            if observable == CustomObservable:
                observables_list.custom_stix_observables[
                    stix_observable_object.name
                ] = stix_observable_object
                logger.debug("Extracted observable: %s", stix_observable_object.name)
            elif isinstance(stix_observable_object, dict):
                observables_list.dict_stix_observables[
                    stix_observable_object["name"]
                ] = stix_observable_object
                logger.debug("Extracted observable: %s", stix_observable_object["name"])
            else:
                observables_list.stix_observables[
                    stix_observable_object.name
                ] = stix_observable_object
                logger.debug("Extracted observable: %s", stix_observable_object.name)

        # Hacky logging, but I don't want to complicate just getting pretty_name
        logger.info(
            "Extracted all observables of type %s", observable(None, config).pretty_name
        )

    if (
        not observables_list.stix_observables
        and not observables_list.custom_stix_observables
    ):
        logger.warning("No Obseravbles extracted. Hence, not creating STIX report")
        return

    # Below code is bit redundant, but doesn't lead to errors so will keep it
    object_refs = (
        [stix_object.id for stix_object in observables_list.stix_observables.values()]
        + [
            custom_stix_object.id
            for custom_stix_object in observables_list.custom_stix_observables.values()
        ]
        + [
            dict_stix_object["id"]
            for dict_stix_object in observables_list.dict_stix_observables.values()
        ]
    )
    report = Report(
        name="File converted: " + os.path.split(input_file_path)[1],
        report_types=["threat_report"],
        published=datetime.now(),
        object_refs=object_refs,
        created_by_ref=config.identity,
        allow_custom=True,
        object_marking_refs=config.tlp_level,
    )

    # Create Relationship SROs
    relationship_sros = []
    for stix_observable in observables_list.stix_observables.values():
        relationship_sro = Relationship(
            relationship_type="default-extract",
            source_ref=report.id,
            target_ref=stix_observable.id,
            created_by_ref=config.identity,
            object_marking_refs=config.tlp_level,
        )
        relationship_sros.append(relationship_sro)

    for stix_observable in observables_list.dict_stix_observables.values():
        relationship_sro = Relationship(
            relationship_type="default-extract",
            source_ref=report.id,
            target_ref=stix_observable["id"],
            created_by_ref=config.identity,
            allow_custom=True,
            object_marking_refs=config.tlp_level,
        )
        relationship_sros.append(relationship_sro)

    for stix_observable in observables_list.custom_stix_observables.values():
        relationship_sro = Relationship(
            relationship_type="custom-extract",
            source_ref=report.id,
            target_ref=stix_observable.id,
            created_by_ref=config.identity,
            object_marking_refs=config.tlp_level,
        )
        relationship_sros.append(relationship_sro)

    stix_objects = [config.identity] if config.identity else []
    if config.misp_extension_definition != None:
        stix_objects += [config.misp_extension_definition]

    # Group all stix objects and store in STIX filestore and bundle
    stix_objects += (
        [config.tlp_level]
        + list(observables_list.stix_observables.values())
        + list(observables_list.dict_stix_observables.values())
        + list(observables_list.custom_stix_observables.values())
        + relationship_sros
    )

    object_refs = []
    for stix_object in stix_objects:
        if stix_object != config.tlp_level:
            if hasattr(stix_object, "id"):
                object_refs.append(stix_object.id)
            else:
                object_refs.append(stix_object["id"])

    report = report.new_version(
        object_refs = object_refs
    )

    stix_objects += [report]

    stix_store.store_objects_in_filestore(stix_objects)

    stix_bundle_file_path = stix_store.store_objects_in_bundle(
        stix_objects, config.output_json_file_path
    )
    logger.info("Stored STIX report bundle at %s", stix_bundle_file_path)

    logger.info(
        "If you found file2stix useful, try Stixify which offers many additional features including; report discovery, observable management, intelligence sharing, export via a TAXII 2.1 server, and much more.\n\nhttps://www.stixify.com"
    )

    return stix_bundle_file_path
