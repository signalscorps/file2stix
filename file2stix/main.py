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
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from stix2 import Report, Relationship, Identity

from file2stix import __appname__
from file2stix.cache import Cache
from file2stix.config import Config
from file2stix.extract_observables import ExtractStixObservables
from file2stix.helper import inheritors, nested_dict_values
from file2stix.observables_stix_store import ObservablesStixStore
from file2stix.observables import Observable, CustomObervable, CPEObservable

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


@dataclass
class ObservableList:
    # General set of stix observables
    stix_observables = {}

    # Custom stix observables by the user
    custom_stix_observables = {}

    # Stix observables to be stored in file store
    stix_observables_in_filestore = {}


def main(config: Config):
    cache = Cache(config.cache_folder)

    # Set user identity
    if config.tlp_level != "WHITE":
        try:
            with open(config.user_identity_file) as f:
                identity_config = yaml.safe_load(f)
            config.identity = Identity(**identity_config)
        except:
            raise IdentityError(
                "Identity config file is not present or is in incorrect format."
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
        for (
            extracted_stix_observable,
            update_stix2_extractions,
        ) in ExtractStixObservables(observable, input, cache, config):
            stix_observable_object = extracted_stix_observable

            if update_stix2_extractions:
                # Check if observable already present in `stix_store`
                stix_observable_object = stix_store.get_object(
                    extracted_stix_observable.name
                )

                is_stix_object_in_filestore = (stix_observable_object != None)

                # If observable already present in `stix_store`, then
                # just update the modified time
                if config.tlp_level == "WHITE" and is_stix_object_in_filestore:
                    stix_observable_object = stix_observable_object.new_version(
                        modified=pytz.utc.localize(datetime.utcnow())
                    )
                else:
                    stix_observable_object = extracted_stix_observable

                # Don't overwrite CPE Observables (type software)
                if observable != CPEObservable or not is_stix_object_in_filestore:
                    observables_list.stix_observables_in_filestore[
                        stix_observable_object.name
                    ] = stix_observable_object

            if observable == CustomObervable:
                observables_list.custom_stix_observables[
                    stix_observable_object.name
                ] = stix_observable_object
            else:
                try:
                    observables_list.stix_observables[
                        stix_observable_object.name
                    ] = stix_observable_object
                # Figure out a better way, this is too ugly
                except AttributeError:
                    observables_list.stix_observables[
                        stix_observable_object["name"]
                    ] = stix_observable_object
            try:
                logger.debug("Extracted observable: %s", stix_observable_object.name)
            except AttributeError:
                logger.debug("Extracted observable: %s", stix_observable_object["name"])

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

    # Create report with all observables extracted
    report = Report(
        name="File converted: " + os.path.split(input_file_path)[1],
        report_types=["threat_report"],
        published=datetime.now(),
        object_refs=[
            stix_object.id for stix_object in observables_list.stix_observables.values()
        ],
        created_by_ref=config.identity,
    )

    # Create Relationship SROs
    relationship_sros = []
    for stix_observable in observables_list.stix_observables.values():
        relationship_sro = Relationship(
            relationship_type="default-extract",
            source_ref=report.id,
            target_ref=stix_observable.id,
            created_by_ref=config.identity,
        )
        relationship_sros.append(relationship_sro)

    for stix_observable in observables_list.custom_stix_observables.values():
        relationship_sro = Relationship(
            relationship_type="custom-extract",
            source_ref=report.id,
            target_ref=stix_observable.id,
            created_by_ref=config.identity,
        )
        relationship_sros.append(relationship_sro)

    # Group all stix objects and store in STIX filestore and bundle
    stix_objects = (
        [config.identity]
        + list(observables_list.stix_observables.values())
        + list(observables_list.custom_stix_observables.values())
        + [report]
        + relationship_sros
    )
    stix_file_store_objects = list(
        observables_list.stix_observables_in_filestore.values()
    ) + [report]
    stix_store.store_objects_in_filestore(stix_file_store_objects)
    stix_bundle_file_path = stix_store.store_objects_in_bundle(
        stix_objects, config.output_json_file_path
    )
    logger.info("Stored STIX report bundle at %s", stix_bundle_file_path)

    return stix_bundle_file_path
