"""
Parse CLI arguments and pass to file2stix_cli.main
"""
import argparse
import logging
import os
import yaml
import sys
from stix2 import TLP_WHITE, TLP_AMBER, TLP_GREEN, TLP_RED, Identity

import file2stix
import file2stix.backends.arangodb
from file2stix.backends import arangodb
from file2stix.config import Config, STIX2_OBJECTS_STORE
from file2stix.main import main, Backends
from file2stix.observables import get_observable_class_from_name

logger = logging.getLogger(__name__)


class IdentityError(Exception):
    pass


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
        "--output-processed-input-file",
        action="store",
        type=str,
        help="Output the given input file after file2stix preprocesses it"
    )

    arg_parser.add_argument(
        "--cache-folder",
        action="store",
        type=str,
        default=Config.cache_folder,
        help="Cache folder path where MITRE ATT&CK and CAPEC warning list will be stored (default: %(default)s)",
    )

    arg_parser.add_argument(
        "--update-mitre-cti-database",
        action="store_true",
        default=Config.update_mitre_cti_database,
        help="Update MITRE ATT&CK and CAPEC database",
    )

    arg_parser.add_argument(
        "--custom-extraction-file",
        action="store",
        help="Path to file with custom extraction logic",
    )

    arg_parser.add_argument(
        "--tlp-level",
        action="store",
        choices=["WHITE", "GREEN", "AMBER", "RED"],
        default="WHITE",
        help="Choose TLP level of report (default: %(default)s)",
    )

    arg_parser.add_argument(
        "--user-identity-file",
        action="store",
        help="Path to a custom user STIX Identity config file (in yml format)",
    )

    arg_parser.add_argument(
        "--ignore-observable-prefix",
        action="store",
        help="Comma-separated prefixes of observables to be ignored from extraction",
    )

    arg_parser.add_argument(
        "--misp-custom-warning-list-file",
        action="store",
        help="Path to custom warning list file in MISP Warning List format",
    )

    arg_parser.add_argument(
        "--defang-observables",
        action="store_true",
        default=Config.defang_observables,
        help="Defang 'fanged' observables in input file.",
    )

    arg_parser.add_argument(
        "--backend",
        action="store",
        help="Cache folder path where MITRE ATT&K and CAPEC warning list will be stored (default: %(default)s)",
    )

    arg_parser.add_argument(
        "--extraction-mode",
        action="store",
        choices=["analysis", "sighting", "observed"],
        default=Config.extraction_mode,
        help="Choose extraction mode of report (default: %(default)s)",
    )

    arg_parser.add_argument(
        "--no-branding",
        action="store_true",
        default=False,
        help="Remove file2stix branding in external_reference property for each extracted object (default: %(default)s)",
    )

    arg_parser.add_argument(
        "--confidence",
        action="store",
        type=int,
        help="Set confidence to be assigned to Indicator SDOs. Must be >= 0 <= 100",
    )

    arg_parser.add_argument(
        "--ignore-warninglist-observables",
        action="store_true",
        default=Config.ignore_warninglist_observables,
        help="Do not extract observables in a report the match to a warning list",
    )

    args = arg_parser.parse_args()

    input_file_path = (
        os.path.abspath(args.input_file) if args.input_file != None else None
    )

    output_json_file_path = (
        os.path.abspath(args.output_json_file)
        if args.output_json_file != None
        else None
    )

    ignore_observables_list = None
    if args.ignore_observable_prefix != None:
        ignore_observables_list = get_observable_class_from_name(
            args.ignore_observable_prefix.split(",")
        )

    tlp_level_map = {
        "WHITE": TLP_WHITE,
        "GREEN": TLP_GREEN,
        "AMBER": TLP_AMBER,
        "RED": TLP_RED,
    }
    tlp_level = tlp_level_map[args.tlp_level]

    identity = STIX2_OBJECTS_STORE.get_object("file2stix")
    if args.user_identity_file != None:
        # Set user identity
        try:
            with open(args.user_identity_file) as f:
                identity_config = yaml.safe_load(f)
            identity = Identity(**identity_config)
        except Exception as error:
            raise IdentityError(
                "Identity config file is not present or is in incorrect format."
            ) from error

    if args.backend:
        if not os.path.exists(args.backend):
            raise FileExistsError("Backend file not found")
        with open(args.backend, "r") as stream:
            try:
                data = yaml.safe_load(stream)
            except yaml.YAMLError:
                raise ValueError("Incorrect YML file")
            if data.get("backend") not in [e.value for e in Backends]:
                raise ValueError("Backend in YML doesn't match any available backends")
        arangodb.check_arango_connection(args.backend)

    branding_external_ref = Config.branding_external_ref
    if args.no_branding == True:
        branding_external_ref = None

    confidence = args.confidence
    if confidence != None and not(0 <= confidence <= 100):
        logger.error("--confidence option should be between 0 and 100")
        sys.exit(1)
    if tlp_level == TLP_WHITE and confidence != None:
        logger.warning("Confidence property ignored, since TLP level is WHITE.")
        confidence = None

    if tlp_level == TLP_WHITE and args.misp_custom_warning_list_file != None:
        logger.error("MISP custom warning list file cannot be specified in TLP LEVEL WHITE reports.")
        sys.exit(1)

    # Build config object
    config = Config(
        input_file_path=input_file_path,
        output_json_file_path=output_json_file_path,
        output_preprocessed_file=args.output_processed_input_file,
        cache_folder=os.path.abspath(args.cache_folder),
        update_mitre_cti_database=args.update_mitre_cti_database,
        custom_extraction_file=args.custom_extraction_file,
        tlp_level=tlp_level,
        identity=identity,
        ignore_observables_list=ignore_observables_list,
        misp_custom_warning_list_file=args.misp_custom_warning_list_file,
        defang_observables=args.defang_observables,
        extraction_mode=args.extraction_mode,
        backend=args.backend,
        confidence=confidence,
        ignore_warninglist_observables=args.ignore_warninglist_observables,
        # branding_external_ref=branding_external_ref,
    )

    config.branding_external_ref = branding_external_ref

    # Call main
    main(config)


if __name__ == "__main__":
    cli()
