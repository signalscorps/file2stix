"""
Contains logic for extracting observables.
"""

import logging

from file2stix.cache import Cache
from file2stix.config import Config
from file2stix.error_handling import error_logger
from file2stix.observables import (
    CustomObservable,
    MITREEnterpriseAttackObservable,
    MITREMobileAttackObservable,
    MITREICSAttackObservable,
    MITRECapecObservable,
)
import pattern2sco

logger = logging.getLogger(__name__)
# error_logger = logging.getLogger("ERROR_LOGGER")


class ExtractStixObservables:
    """
    Iterable that extracts all the observables matching a given format.
    In each iteration, it returns the next extracted observable as a STIX object..
    """

    def __init__(self, observable_cls, text, cache: Cache, config: Config):
        self.index = 0
        self.extracted_observables = []
        self.config = config

        # Handling special observables like MITRE ATT&CK and CAPEC
        if (
            observable_cls == MITREEnterpriseAttackObservable
            or observable_cls == MITREMobileAttackObservable
            or observable_cls == MITREICSAttackObservable
            or observable_cls == MITRECapecObservable
        ):
            if cache.is_mitre_cti_database_in_cache():
                observable_cls.build_extraction_regex(cache.cti_folder_path)
            else:
                logger.warning(
                    "Not extracting MITRE Observable since MITRE CTI database is not present in cache. "
                    "Use --update-mitre-cti-database option to update MITRE CTI database."
                )
                return
        if observable_cls == CustomObservable:
            if config.custom_extraction_file != None:
                observable_cls.build_extraction_pattern_list(
                    config.custom_extraction_file, cache.cti_folder_path
                )
            else:
                logger.info(
                    "Custom extraction file not given, hence not extracting any custom observables."
                )
                return

        self.extracted_observables = observable_cls.extract_observables_from_text(
            text, config
        )

        logger.debug("Extraction of observable text complete.")

    def __iter__(self):
        return self

    def __next__(self):
        if self.index < len(self.extracted_observables):
            extracted_observable = self.extracted_observables[self.index]
            self.index += 1

            try:
                sdo_object = extracted_observable.get_sdo_object()
            except Exception as error:
                if self.config.fail_on_errors == False:
                    error_logger.error(
                        "Creation of stix2 observable object failed for %s",
                        extracted_observable.__class__.__name__,
                    )
                    error_logger.error(
                        "Extracted observable text: %s",
                        extracted_observable.extracted_observable_text,
                    )
                    error_logger.exception(error)
                else:
                    logger.error(
                        "Creation of stix2 observable object failed for %s",
                        extracted_observable.__class__.__name__,
                    )
                    logger.error(
                        "Extracted observable text: %s",
                        extracted_observable.extracted_observable_text,
                    )
                    raise error
            else:
                sco_objects = pattern2sco.get_sco_objects(
                    sdo_object, extracted_observable.defanged
                )
                return {"stix_observable": sdo_object, "sco_objects": sco_objects}
        raise StopIteration
