"""
Parse CLI arguments and pass to pattern2sco.get_sco_object
"""

import argparse
import pattern2sco

from pattern2sco.main import main

def cli():
    arg_parser = argparse.ArgumentParser(
        prog=pattern2sco.__appname__,
        description="Extract observables from input file and store it in a STIX bundle",
        allow_abbrev=False,
    )

    arg_parser.add_argument(
        "--pattern",
        action="store",
        type=str,
        help="input file path from which observables will be extracted",
    )

    args = arg_parser.parse_args()

    main(args.pattern)

if __name__ == "__main__":
    cli()
