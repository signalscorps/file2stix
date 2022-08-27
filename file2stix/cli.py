"""
Parse CLI arguments and pass to file2stix_cli.main
"""
import argparse
import os

import file2stix
from file2stix.config import Config
from file2stix.main import main


def cli():
    arg_parser = argparse.ArgumentParser(
        prog=file2stix.__appname__,
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
        default=Config.cache_folder,
        help="cache folder path where MITRE ATT&K, CAPEC and MISP warning list will be stored (default: %(default)s)",
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

    arg_parser.add_argument(
        "--tlp-level",
        action="store",
        choices=["WHITE", "AMBER"],
        default=Config.tlp_level,
        help="choose TLP level of report (default: %(default)s)",
    )

    arg_parser.add_argument(
        "--user-identity-file",
        action="store",
        default=Config.user_identity_file,
        help="path to user identity config file (in yml format)",
    )

    args = arg_parser.parse_args()
    
    input_file_path = os.path.abspath(args.input_file) if args.input_file != None else None

    # Build config object
    config = Config(
        input_file_path = input_file_path,
        cache_folder = os.path.abspath(args.cache_folder),
        update_mitre_cti_database = args.update_mitre_cti_database,
        custom_extraction_file=args.custom_extraction_file,
        tlp_level=args.tlp_level,
        user_identity_file=args.user_identity_file,
    )

    # Call main
    main(config)

if __name__ == "__main__":
    cli()
