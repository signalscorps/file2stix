"""
Implements a command line interface, which takes in a text file
and outputs observables found (in STIX format).
"""

import logging
import os
import pytz
import sys
from datetime import datetime
from pathlib import Path
from stix2 import Report

from obstracts_cli.cache import Cache
from obstracts_cli.config import Config
from obstracts_cli.extract_observables import ExtractStixObservables
from obstracts_cli.helper import inheritors
from obstracts_cli.observables_stix_store import ObservablesStixStore
from obstracts_cli.observables import Observable

logger = logging.getLogger(__name__)


def main(config: Config):
    cache = Cache(config.cache_folder)

    # Update MITRE ATT&CK and CAPEC database
    if config.update_mitre_cti_database == True:
        cache.update_mitre_cti_database()

    if config.input_file_path == None:
        logger.info("No input file given. Exiting...")
        sys.exit(0)

    input_file_path = config.input_file_path
    # Add a new line at EOF, to avoid edge cases
    input = Path(input_file_path).read_text() + "\n"
    logger.info("Reading input file %s ...", input_file_path)

    stix_store = ObservablesStixStore()

    # Iterate over each observable and extract them from input file
    stix_observables = {}
    stix_observables_in_filestore = {}
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

                # If observable already present in `stix_store`, then
                # just update the modified time
                if stix_observable_object != None:
                    stix_observable_object = stix_observable_object.new_version(
                        modified=pytz.utc.localize(datetime.utcnow())
                    )
                else:
                    stix_observable_object = extracted_stix_observable
                
                stix_observables_in_filestore[stix_observable_object.name] = stix_observable_object

            stix_observables[stix_observable_object.name] = stix_observable_object
            logger.debug("Extracted observable: %s", stix_observable_object.name)

        # Hacky logging, but I don't want to complicate just getting pretty_name
        logger.info(
            "Extracted all observables of type %s", observable(None).pretty_name
        )

    if not stix_observables:
        logger.warning("No Obseravbles extracted. Hence, not creating STIX report")
        return

    # Create report with all observables extracted
    report = Report(
        name=os.path.abspath(input_file_path),
        report_types=["threat_report"],
        published=datetime.now(),
        object_refs=[stix_object.id for stix_object in stix_observables.values()],
    )

    # Group all stix objects and store in STIX filestore and bundle
    stix_objects = list(stix_observables.values()) + [report]
    stix_file_store_objects = list(stix_observables_in_filestore.values()) + [report]
    stix_store.store_objects_in_filestore(stix_file_store_objects)
    stix_bundle_file_path = stix_store.store_objects_in_bundle(stix_objects)
    logger.info("Stored STIX report bundle at %s", stix_bundle_file_path)

    return stix_bundle_file_path


if __name__ == "__main__":
    main()
