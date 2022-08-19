"""
Parse CLI arguments and pass to obstracts_cli.main
"""
import argparse
import os

import obstracts_cli
from obstracts_cli.config import Config
from obstracts_cli.main import main

def cli():
    arg_parser = argparse.ArgumentParser(
        prog=obstracts_cli.__appname__,
        usage="%(prog)s <input-text-file>",
        description="Extract observables from input file and store it in a STIX bundle",
    )
    arg_parser.add_argument(
        "Input text file",
        type=str,
        help="Input text file from which observables will be extracted.",
    )

    # Read input from file
    args = arg_parser.parse_args()
    input_file_path = os.path.abspath(args.Input)

    # Build config object
    config = Config(input_file_path)

    # Call main
    main(config)
