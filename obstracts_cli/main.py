"""
Implements a command line interface, which takes in a text file
and outputs observables found (in STIX format).
"""

import argparse
import logging
import os
import pytz
from datetime import datetime
from pathlib import Path
from stix2 import Report

from obstracts_cli.extract_observables import observables_map, ExtractStixObservables
from obstracts_cli.observables_stix_store import ObservablesStixStore

# NOTE: Move this to __init__.py, when __init__.py is added
# Configure logging module
logging.basicConfig(format="[%(levelname)s] : %(message)s")
logging.getLogger().setLevel(logging.INFO)

def main():
    arg_parser = argparse.ArgumentParser(
        prog="extract_observables",
        usage="%(prog)s <input-text-file>",
        description="Extract observables from input file and store it in a STIX bundle",
    )
    arg_parser.add_argument(
        "Input",
        type=str,
        help="Input text file from which observables will be extracted.",
    )

    # Read input from file
    args = arg_parser.parse_args()
    input_file_path = os.path.abspath(args.Input)
    logging.info("Reading input file %s ...", input_file_path)
    # Add a new line at EOF, to avoid edge cases
    input = Path(input_file_path).read_text() + "\n"

    stix_store = ObservablesStixStore()

    # Iterate over each observable and extract them from input file
    stix_observables = {}
    for observable, pattern in observables_map.items():
        for extracted_observable, stix_observable_object in ExtractStixObservables(
            observable, pattern, input
        ):
            # Check if observable already present in `stix_store`
            old_stix_object = stix_store.get_object(extracted_observable)

            # If observable already present in `stix_store`, then
            # just update the modified time
            if old_stix_object != None:
                stix_observable_object = old_stix_object.new_version(
                    modified=pytz.utc.localize(datetime.utcnow())
                )

            # Storing in a dictionary to avoid duplicate indicators
            # for the same matching string
            stix_observables[extracted_observable] = stix_observable_object
        logging.info("Extracted all observables of type %s", observable)

    # Create report with all observables extracted
    report = Report(
        name=os.path.abspath(input_file_path),
        report_types=["threat_report"],
        published=datetime.now(),
        object_refs=[stix_object.id for stix_object in stix_observables.values()],
    )

    # Group all stix objects and store in STIX filestore and bundle
    stix_objects = list(stix_observables.values()) + [report]
    stix_store.store_objects_in_filestore(stix_objects)
    stix_bundle_file_path = stix_store.store_objects_in_bundle(stix_objects)
    logging.info("Stored STIX report bundle at %s", stix_bundle_file_path)

if __name__ == "__main__":
    main()