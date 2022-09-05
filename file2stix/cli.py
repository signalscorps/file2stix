"""
Parse CLI arguments and pass to file2stix_cli.main
"""
import argparse
import os

import file2stix
from file2stix.config import Config
from file2stix.main import main
from file2stix.observables import get_observable_class_from_name


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
        "--output-json-file",
        action="store",
        type=str,
        help="output json file path into which extracted observables will be stored",
    )

    arg_parser.add_argument(
        "--cache-folder",
        action="store",
        type=str,
        default=Config.cache_folder,
        help="cache folder path where MITRE ATT&K and CAPEC warning list will be stored (default: %(default)s)",
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
        choices=["WHITE", "GREEN", "AMBER", "RED"],
        default=Config.tlp_level,
        help="choose TLP level of report (default: %(default)s)",
    )

    arg_parser.add_argument(
        "--user-identity-file",
        action="store",
        default=Config.user_identity_file,
        help="path to user identity config file (in yml format)",
    )

    arg_parser.add_argument(
        "--ignore-observable-prefix",
        action="store",
        help="comma-separated prefixes of observables to be ignored from extraction",
    )

    arg_parser.add_argument(
        "--misp-custom-warning-list-file",
        action="store",
        help="path to MISP custom warning list file",
    )

    args = arg_parser.parse_args()
    
    input_file_path = os.path.abspath(args.input_file) if args.input_file != None else None

    output_json_file_path = os.path.abspath(args.output_json_file) if args.output_json_file != None else None

    ignore_observables_list = None
    if args.ignore_observable_prefix != None:
        ignore_observables_list = get_observable_class_from_name(args.ignore_observable_prefix.split(","))

    # Build config object
    config = Config(
        input_file_path = input_file_path,
        output_json_file_path = output_json_file_path,
        cache_folder = os.path.abspath(args.cache_folder),
        update_mitre_cti_database = args.update_mitre_cti_database,
        custom_extraction_file=args.custom_extraction_file,
        tlp_level=args.tlp_level,
        user_identity_file=args.user_identity_file,
        ignore_observables_list=ignore_observables_list,
        misp_custom_warning_list_file=args.misp_custom_warning_list_file,
    )

    # Call main
    main(config)

if __name__ == "__main__":
    cli()
