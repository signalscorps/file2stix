"""
Implements a command line interface, which takes in a text file
and outputs observables found (in STIX format).
"""

import argparse
from datetime import datetime
import json
import logging
import os
import pycountry
from pathlib import Path
from stix2 import (
    Indicator,
    Bundle,
    Vulnerability,
    ExternalReference,
    Report,
    FileSystemStore,
    Location,
)
from stix2.base import STIXJSONEncoder
from stix2.exceptions import InvalidValueError

from extract_observables import observables_map, ExtractPatterns

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
        for match in ExtractPatterns(pattern, input):
            try:
                if observable == "cve":
                    vulnerability = Vulnerability(
                        name=match,
                        external_references=ExternalReference(
                            source_name="cve", external_id=match
                        ),
                    )
                    stix_observables[match] = vulnerability
                elif observable.startswith("location"):
                    # TODO: This is a hack, think of a neater approach
                    # Strip leading and trailing spaces
                    match = match.strip()

                    # Find country iso
                    country_iso = match
                    if len(match) != 2 and not match.isupper():
                        country = pycountry.countries.get(name=match)
                        if country != None:
                            country_iso = country.alpha_2

                    location = Location(name=f"Country: {match}", country=country_iso)
                    stix_observables[match] = location
                else:
                    indicator = Indicator(
                        type="indicator",
                        name=match,
                        pattern_type="stix",
                        pattern=f"[ {observable} = '{match}' ]",
                        indicator_types=["malicious-activity"],
                    )
                    # Storing in a dictionary to avoid duplicate indicators
                    # for the same matching string
                    stix_observables[match] = indicator
            except InvalidValueError as error:
                logging.warning(
                    "Got InvalidValueError when creating SDO object for %s observable. "
                    "Extracted observable is: %s",
                    observable,
                    match,
                )
                # TODO: We should probably log this, for now ignoring since it dirties the output.
                # logging.exception(error)

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
