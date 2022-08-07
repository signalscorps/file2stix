"""
Implements a command line interface, which takes in a text file
and outputs observables found (in STIX format).
"""

import argparse
from datetime import datetime
import json
from pathlib import Path
from os import path
from stix2 import Indicator, Bundle, Vulnerability, ExternalReference, Report, FileSystemStore
from stix2.base import STIXJSONEncoder

from extract_observables import observables_map, ExtractPatterns

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
    input = Path(input_file_path).read_text()

    # Iterate over each observable and extract them from input file
    stix_observables = {}
    for observable, pattern in observables_map.items():
        for match in ExtractPatterns(pattern, input):
            if observable == "cve":
                vulnerability = Vulnerability(
                    name=match,
                    external_references=ExternalReference(
                        source_name="cve", external_id=match
                    ),
                )
                stix_observables[match] = vulnerability
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

    # Create report with all observables extracted
    report = Report(
        name=input_file_path,
        report_types=["threat_report"],
        published=datetime.now(),
        object_refs=[stix_object.id for stix_object in stix_observables.values()],
    )

    # Group all stix objects
    stix_objects = list(stix_observables.values()) + [report]

    # Store stix objects in filestore
    fs = FileSystemStore("stix2_extractions")
    fs.add(stix_objects)

    # Create a STIX bundle of all the STIX objects
    BundleOfAllObjects = Bundle(*stix_objects, allow_custom=True)
    stix_bundle_path = path.join("stix2_reports", f"{BundleOfAllObjects.id}.json")
    with open(stix_bundle_path, "w") as f:
        f.write(json.dumps(BundleOfAllObjects, cls=STIXJSONEncoder, indent=4))
