import argparse
import json
from pathlib import Path
from stix2 import Indicator, Bundle, Vulnerability, ExternalReference
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
    stix_objects = {}
    for observable, pattern in observables_map.items():
        for match in ExtractPatterns(pattern, input):
            if observable == "cve":
                vulnerability = Vulnerability(
                    name=match,
                    external_references=ExternalReference(
                        source_name="cve", external_id=match
                    ),
                )
                stix_objects[match] = vulnerability
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
                stix_objects[match] = indicator

    # Create a STIX bundle of all the indicators
    BundleOfAllObjects = Bundle(*list(stix_objects.values()), allow_custom=True)
    with open(BundleOfAllObjects.id + ".json", "w") as f:
        f.write(json.dumps(BundleOfAllObjects, cls=STIXJSONEncoder, indent=4))
