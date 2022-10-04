"""
Implements a command line interface, which takes in a text file
and outputs observables found (in STIX format).
"""

import logging
import os
from enum import Enum

import sys
import textract
import json
import yaml
from datetime import datetime
from pathlib import Path
from stix2 import Report, Relationship, TLP_WHITE, Sighting, ObservedData, Filter
from stix2.exceptions import ExtraPropertiesError
from pymispwarninglists.api import WarningList

from pattern2sco.custom_objects import Cryptocurrency, CreditCard, IBAN, UserAgent

from file2stix.backends import arangodb
from file2stix import __appname__
from file2stix.cache import Cache
from file2stix.config import Config, STIX2_OBJECTS_STORE
from file2stix.extract_observables import ExtractStixObservables
from file2stix.helper import (
    inheritors,
    get_text_from_html,
    get_text_from_json,
    get_text_from_markdown,
    get_text_from_xml,
    update_stix_object,
)
from file2stix.observables_stix_store import ObservablesStixStore
from file2stix.observables import (
    Observable,
    CustomObservable,
    CPEObservable,
    CVEObservable,
    SIGMARuleObservable,
)
from file2stix.error_handling import store_error_logs_in_file

logger = logging.getLogger(__name__)


class Backends(Enum):
    ARANGO = "arangodb"


class ScoObjectContainer:
    def __init__(self, sco_objects):
        self.sco_objects = sco_objects
        self.observed_count = 1


class ObservableList:
    def __init__(self):
        # General set of stix observables
        self.stix_observables = {}

        # Stix observables which are dictionaries
        self.dict_stix_observables = {}

        # Custom stix observables by the user
        self.custom_stix_observables = {}

        # Custom dict stix observables by the user
        self.custom_dict_stix_observables = {}

        # SCO observables
        self.sco_observables = {}

        # Extension definition objects
        self.extension_definition_objects = {}

    def __str__(self):
        return f"ObservablesList({self.stix_observables}, {self.dict_stix_observables}, {self.custom_stix_observables}, {self.custom_dict_stix_observables})"


def main(config: Config):
    cache = Cache(config.cache_folder)

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
    if file_extension == ".xml":
        input = get_text_from_xml(input_file_path)
    elif file_extension == ".html":
        input = get_text_from_html(input_file_path)
    elif file_extension == ".json":
        input = get_text_from_json(input_file_path)
    elif file_extension == ".md":
        input = get_text_from_markdown(input_file_path)
    # elif file_extension in (".yml", ".yaml"):
    #     input = get_text_from_yaml(input_file_path)
    elif file_extension in (".yara", ".yar", ".yml", ".yaml"):
        input = Path(input_file_path).read_text()
    else:
        input = textract.process(input_file_path).decode("UTF-8")

    if config.output_preprocessed_file:
        with open(config.output_preprocessed_file, "w") as f:
            f.write(input)

    logger.info("Reading input file %s ...", input_file_path)

    # Create report early, because we need to use it's created and modified time
    report = Report(
        name="File converted: " + os.path.split(input_file_path)[1],
        report_types=["threat_report"],
        published=datetime.now(),
        object_refs=[config.identity],
        created_by_ref=config.identity,
        allow_custom=True,
        object_marking_refs=config.tlp_level,
        external_references=config.branding_external_ref,
    )

    stix_store = ObservablesStixStore()

    observables_list = ObservableList()

    # Iterate over each observable and extract them from input file
    for observable in inheritors(Observable):
        if (
            config.ignore_observables_list != None
            and observable in config.ignore_observables_list
        ):
            logger.info("%s is ignored from extraction", observable.__name__)
            continue
        for stix_observable_objects in ExtractStixObservables(
            observable, input, cache, config
        ):
            extracted_stix_observable = stix_observable_objects["stix_observable"]

            # Below case is possible if extracted observable fails last-minute checks
            if extracted_stix_observable == None:
                continue

            stix_observable_object = extracted_stix_observable

            # Check if observable already present in `stix_store`
            if hasattr(extracted_stix_observable, "name"):
                confidence = None
                if hasattr(extracted_stix_observable, "confidence"):
                    confidence = extracted_stix_observable.confidence

                identity_id = None
                if config.tlp_level != TLP_WHITE:
                    identity_id = extracted_stix_observable.created_by_ref

                extensions = None
                if hasattr(extracted_stix_observable, "extensions"):
                    extensions = extracted_stix_observable.extensions

                stix_observable_object = stix_store.get_object(
                    extracted_stix_observable.name,
                    stix_object_identity=identity_id,
                    tlp_level=config.tlp_level.id,
                    confidence=confidence,
                    extensions=extensions,
                )

                # Don't create a new version for CPE Observable
                if stix_observable_object != None and observable != CPEObservable:
                    stix_observable_object = stix_observable_object.new_version(
                        modified=report.modified
                    )
                else:
                    stix_observable_object = extracted_stix_observable
                    if (
                        hasattr(extracted_stix_observable, "created")
                        and observable != CPEObservable
                    ):
                        # if condition above to avoid dict observables
                        try:
                            stix_observable_object = update_stix_object(
                                extracted_stix_observable,
                                created=report.created,
                                modified=report.modified,
                            )
                        except ExtraPropertiesError:
                            logger.debug(
                                "Unable to update created and modified time in stix2 observable."
                                "Ignoring this exception since it's most likely a MITRE observable."
                            )

            observable_id = None
            if isinstance(stix_observable_object, dict):
                observable_id = stix_observable_object["id"]
            else:
                observable_id = stix_observable_object.id

            if (
                isinstance(stix_observable_object, dict)
                and observable == CustomObservable
            ):
                observables_list.custom_dict_stix_observables[
                    stix_observable_object["name"]
                ] = stix_observable_object
                logger.debug("Extracted observable: %s", stix_observable_object["name"])
            elif observable == CustomObservable:
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

            # Add respective SCO objects if present
            if observable != CPEObservable:
                sco_objects = stix_observable_objects["sco_objects"]
                if observable_id in observables_list.sco_observables:
                    observables_list.sco_observables[observable_id].observed_count += 1
                else:
                    observables_list.sco_observables[
                        observable_id
                    ] = ScoObjectContainer(sco_objects)

            # Add respective extension definitions if present
            for sco_object in stix_observable_objects["sco_objects"]:
                if isinstance(sco_object, Cryptocurrency):
                    observables_list.extension_definition_objects[
                        "extension-definition--532ae28d-137b-4b89-afb7-9cf9b504191b"
                    ] = STIX2_OBJECTS_STORE.get_object_by_id(
                        "extension-definition--532ae28d-137b-4b89-afb7-9cf9b504191b"
                    )
                if isinstance(sco_object, Cryptocurrency):
                    observables_list.extension_definition_objects[
                        "extension-definition--532ae28d-137b-4b89-afb7-9cf9b504191b"
                    ] = STIX2_OBJECTS_STORE.get_object_by_id(
                        "extension-definition--532ae28d-137b-4b89-afb7-9cf9b504191b"
                    )
                if isinstance(sco_object, CreditCard):
                    observables_list.extension_definition_objects[
                        "extension-definition--abd6fc0e-749e-4e6c-a20c-1faa419f5ee4"
                    ] = STIX2_OBJECTS_STORE.get_object_by_id(
                        "extension-definition--abd6fc0e-749e-4e6c-a20c-1faa419f5ee4"
                    )
                if isinstance(sco_object, IBAN):
                    observables_list.extension_definition_objects[
                        "extension-definition--349c1029-4052-4635-a064-263cb17290ea"
                    ] = STIX2_OBJECTS_STORE.get_object_by_id(
                        "extension-definition--349c1029-4052-4635-a064-263cb17290ea"
                    )
                if isinstance(sco_object, UserAgent):
                    observables_list.extension_definition_objects[
                        "extension-definition--6cea4dc9-9517-44b8-b021-ae82e2f1de43"
                    ] = STIX2_OBJECTS_STORE.get_object_by_id(
                        "extension-definition--6cea4dc9-9517-44b8-b021-ae82e2f1de43"
                    )

            if observable == CPEObservable:
                observables_list.extension_definition_objects[
                    "extension-definition--6c453e0f-9895-498f-a273-2e2dda473377"
                ] = STIX2_OBJECTS_STORE.get_object_by_id(
                    "extension-definition--6c453e0f-9895-498f-a273-2e2dda473377"
                )
            if observable == CVEObservable:
                observables_list.extension_definition_objects[
                    "extension-definition--b2b5f2cd-49e6-4091-a0e0-c0bb71543e23"
                ] = STIX2_OBJECTS_STORE.get_object_by_id(
                    "extension-definition--b2b5f2cd-49e6-4091-a0e0-c0bb71543e23"
                )
            if observable == SIGMARuleObservable:
                observables_list.extension_definition_objects[
                    "extension-definition--94f4bdb6-7f39-4d0a-b103-f787026963a6"
                ] = STIX2_OBJECTS_STORE.get_object_by_id(
                    "extension-definition--94f4bdb6-7f39-4d0a-b103-f787026963a6"
                )

            if (
                hasattr(stix_observable_object, "extensions")
                and config.misp_extension_definition.id
                in stix_observable_object.extensions
            ):
                observables_list.extension_definition_objects[
                    config.misp_extension_definition.id
                ] = config.misp_extension_definition

        # Hacky logging, but I don't want to complicate just getting pretty_name
        logger.info(
            "Extracted all observables of type %s", observable(None, config).pretty_name
        )

    if (
        not observables_list.stix_observables
        and not observables_list.custom_stix_observables
    ):
        logger.warning("No Observables extracted. Hence, not creating STIX report")
        store_error_logs_in_file(report.created.strftime("%d-%m-%Y-%H:%M:%S"))
        return

    # Create Relationship SROs
    relationship_sros = []
    for stix_observable in observables_list.stix_observables.values():
        relationship_sro = Relationship(
            relationship_type="default-extract-from",
            created=report.created,
            modified=report.modified,
            source_ref=stix_observable.id,
            target_ref=report.id,
            created_by_ref=config.identity,
            object_marking_refs=config.tlp_level,
            external_references=config.branding_external_ref,
        )
        relationship_sros.append(relationship_sro)

    for stix_observable in observables_list.dict_stix_observables.values():
        relationship_sro = Relationship(
            relationship_type="default-extract-from",
            created=report.created,
            modified=report.modified,
            source_ref=stix_observable["id"],
            target_ref=report.id,
            created_by_ref=config.identity,
            object_marking_refs=config.tlp_level,
            allow_custom=True,
            external_references=config.branding_external_ref,
        )
        relationship_sros.append(relationship_sro)

    for stix_observable in observables_list.custom_stix_observables.values():
        relationship_sro = Relationship(
            relationship_type="custom-extract-from",
            created=report.created,
            modified=report.modified,
            source_ref=stix_observable.id,
            target_ref=report.id,
            created_by_ref=config.identity,
            object_marking_refs=config.tlp_level,
            external_references=config.branding_external_ref,
        )
        relationship_sros.append(relationship_sro)

    for stix_observable in observables_list.custom_dict_stix_observables.values():
        relationship_sro = Relationship(
            relationship_type="custom-extract-from",
            created=report.created,
            modified=report.modified,
            source_ref=stix_observable["id"],
            target_ref=report.id,
            created_by_ref=config.identity,
            object_marking_refs=config.tlp_level,
            allow_custom=True,
            external_references=config.branding_external_ref,
        )
        relationship_sros.append(relationship_sro)

    observed_datas = []
    sco_object_ids_seen_so_far = set()
    sco_objects_seen_so_far = []

    for (
        stix_observable_id,
        sco_object_container,
    ) in observables_list.sco_observables.items():

        sco_objects = sco_object_container.sco_objects
        temp_observed_datas = []
        for sco_object in sco_objects:

            if sco_object.id in sco_object_ids_seen_so_far:
                continue
            sco_object_ids_seen_so_far.add(sco_object.id)
            sco_objects_seen_so_far.append(sco_object)

            relationship_sro = Relationship(
                relationship_type="pattern-contains",
                created=report.created,
                modified=report.modified,
                source_ref=stix_observable_id,
                target_ref=sco_object.id,
                created_by_ref=config.identity,
                object_marking_refs=config.tlp_level,
                external_references=config.branding_external_ref,
            )
            relationship_sros.append(relationship_sro)

            if (
                config.extraction_mode == "observed"
                or config.extraction_mode == "sighting"
            ):
                observed_data = ObservedData(
                    created=report.created,
                    modified=report.modified,
                    created_by_ref=config.identity,
                    first_observed=report.created,
                    last_observed=report.created,
                    number_observed=sco_object_container.observed_count,
                    object_refs=[sco_object],
                    object_marking_refs=config.tlp_level,
                    external_references=config.branding_external_ref,
                )
                temp_observed_datas.append(observed_data)

        observed_datas += temp_observed_datas

        if config.extraction_mode == "sighting":
            sighting_sro = Sighting(
                created=report.created,
                modified=report.modified,
                created_by_ref=config.identity,
                sighting_of_ref=stix_observable_id,
                observed_data_refs=temp_observed_datas,
                object_marking_refs=config.tlp_level,
                external_references=config.branding_external_ref,
            )
            relationship_sros.append(sighting_sro)

    # Group all stix objects and store in STIX filestore and bundle
    stix_observable_objects = (
        [config.identity]
        + [config.tlp_level]
        + list(observables_list.stix_observables.values())
        + list(observables_list.dict_stix_observables.values())
        + list(observables_list.custom_stix_observables.values())
        + list(observables_list.custom_dict_stix_observables.values())
        + sco_objects_seen_so_far
        + observed_datas
        + relationship_sros
        + list(observables_list.extension_definition_objects.values())
    )

    # Build object_refs for report
    object_refs = []
    for stix_object in stix_observable_objects:
        if hasattr(stix_object, "id"):
            object_refs.append(stix_object.id)
        else:
            try:
                object_refs.append(stix_object["id"])
            except Exception:
                print(stix_object)
                raise

    # Update object_refs in report
    report = update_stix_object(report, object_refs=object_refs, allow_custom=True)
    stix_observable_objects += [report]

    stix_store.store_objects_in_filestore(stix_observable_objects)

    bundle_id, stix_bundle_file_path = stix_store.store_objects_in_bundle(
        stix_observable_objects, config.output_json_file_path
    )
    logger.info("Stored STIX report bundle at %s", stix_bundle_file_path)

    store_error_logs_in_file(report.created.strftime("%d-%m-%Y-%H:%M:%S"))

    if config.backend:
        backends_func = {
            Backends.ARANGO.value: arangodb.start_saving_to_arango(config.backend)
        }
        with open(config.backend, "r") as stream:
            data = yaml.safe_load(stream)
        backends_func.get(data.get("backend"))

    logger.info(
        "If you found file2stix useful, try Stixify features including; report discovery, observable management, intelligence sharing, export via a TAXII 2.1 server... Discover more at: https://www.stixify.com"
    )

    return stix_bundle_file_path
