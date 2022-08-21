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
        description="Extract observables from input file and store it in a STIX bundle",
        allow_abbrev=False,
    )

    arg_parser.add_argument(
        "--input-file",
        action="store",
        type=str,
        help="input file path from which observables will be extracted",
    )

    arg_parser.add_argument(
        "--cache-folder",
        action="store",
        type=str,
        help="cache folder path where MITRE ATT&K, CAPEC and MISP warning list will be stored",
        default=Config.cache_folder,
    )

    arg_parser.add_argument(
        "--update-mitre-cti-database",
        action="store_true",
        help="update MITRE ATT&CK and CAPEC database",
        default=Config.update_mitre_cti_database
    )

    arg_parser.add_argument(
        "--custom-extraction-file",
        action="store",
        help="path to file with custom extraction logix",
    )

    args = arg_parser.parse_args()
    
    input_file_path = os.path.abspath(args.input_file) if args.input_file != None else None

    # Build config object
    config = Config(
        input_file_path = input_file_path,
        cache_folder = os.path.abspath(args.cache_folder),
        update_mitre_cti_database = args.update_mitre_cti_database,
        custom_extraction_file=args.custom_extraction_file
    )

    # Call main
    main(config)

if __name__ == "__main__":
    cli()
