"""
Implements a command line interface, which takes in a text file
and outputs observables found (in STIX format).
"""

import argparse
from datetime import datetime
import json
import logging
import os
from pathlib import Path
from stix2 import (
    Bundle,
    Report,
    FileSystemStore,
    Location,
)
from stix2.base import STIXJSONEncoder

from extract_observables import observables_map, ExtractStixObservables

# NOTE: Move this to __init__.py, when __init__.py is added
# Configure logging module
logging.basicConfig(format="[%(levelname)s] : %(message)s")

STIX2_EXTRACTIONS_FOLDER = "stix2_extractions"
STIX2_REPORTS_FOLDER = "stix2_reports"

if __name__ == "__main__":
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
    input_file_path = args.Input
    # Add a new line at EOF, to avoid edge cases
    input = Path(input_file_path).read_text() + "\n"

    # Iterate over each observable and extract them from input file
    stix_observables = {}
    for observable, pattern in observables_map.items():
        for extracted_observable, stix_observable_object in ExtractStixObservables(
            observable, pattern, input
        ):
            stix_observables[extracted_observable] = stix_observable_object

    # Create report with all observables extracted
    report = Report(
        name=os.path.abspath(input_file_path),
        report_types=["threat_report"],
        published=datetime.now(),
        object_refs=[stix_object.id for stix_object in stix_observables.values()],
    )

    # Group all stix objects
    stix_objects = list(stix_observables.values()) + [report]

    # Store stix objects in filestore
    if os.path.exists(STIX2_EXTRACTIONS_FOLDER) == False:
        os.makedirs(STIX2_EXTRACTIONS_FOLDER)
    fs = FileSystemStore(STIX2_EXTRACTIONS_FOLDER)
    fs.add(stix_objects)

    # Create a STIX bundle of all the STIX objects
    BundleOfAllObjects = Bundle(*stix_objects, allow_custom=True)
    if os.path.exists(STIX2_REPORTS_FOLDER) == False:
        os.makedirs(STIX2_REPORTS_FOLDER)
    stix_bundle_path = os.path.join(
        STIX2_REPORTS_FOLDER, f"{BundleOfAllObjects.id}.json"
    )
    with open(stix_bundle_path, "w") as f:
        f.write(json.dumps(BundleOfAllObjects, cls=STIXJSONEncoder, indent=4))
