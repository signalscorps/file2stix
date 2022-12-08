"""
Contains logic for extracting observables.
"""

import logging

from file2stix.cache import Cache
from file2stix.config import Config, FILE2STIX_FOLDER
from file2stix.error_handling import error_logger
from file2stix.observables import (
    CustomObservable,
    MITREEnterpriseAttackObservable,
    MITREMobileAttackObservable,
    MITREICSAttackObservable,
    MITRECapecObservable,
    LookupObservable,
)
import pattern2sco

logger = logging.getLogger(__name__)
# error_logger = logging.getLogger("ERROR_LOGGER")


class ExtractStixObservables:
    """
    Iterable that extracts all the observables matching a given format.
    In each iteration, it returns the next extracted observable as a STIX object.

    BEWARE, this class is stateful, and caches the modified input text in every iteration.
    The use case is to use this iterator once in the entire lifetime of the program.
    """

    # Caches modified text (some observables like User Agent modify the input text)
    modified_text = None

    def __init__(self, observable_cls, text, cache: Cache, config: Config):
        self.index = 0
        self.extracted_observables = []
        self.config = config
        self.final_result_list = []
        if ExtractStixObservables.modified_text == None:
            ExtractStixObservables.modified_text = text

        # Handling special observables like MITRE ATT&CK and CAPEC
        if (
            observable_cls == MITREEnterpriseAttackObservable
            or observable_cls == MITREMobileAttackObservable
            or observable_cls == MITREICSAttackObservable
        ):
            if cache.is_mitre_cti_database_in_cache():
                observable_cls.build_extraction_regex(cache.cti_folder_path)
            else:
                logger.warning(
                    "Not extracting MITRE Observable since MITRE CTI database is not present in cache. "
                    "Use --update-mitre-cti-database option to update MITRE CTI database."
                )
                return
        elif observable_cls == MITRECapecObservable:
            if cache.is_mitre_capec_cti_database_in_cache():
                observable_cls.build_extraction_regex(cache.capec_cti_folder_path)
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
        if observable_cls == LookupObservable:
            lookup_folder = FILE2STIX_FOLDER / "lookups"
            observable_cls.build_extraction_pattern_list(
                lookup_folder, cache.cti_folder_path
            )

        (
            self.extracted_observables,
            ExtractStixObservables.modified_text,
        ) = observable_cls.extract_observables_from_text(
            ExtractStixObservables.modified_text, config
        )

        # Store sdo and sco_objects
        for extracted_observable in self.extracted_observables:
            try:
                sdo_objects = extracted_observable.get_sdo_object()
                if isinstance(sdo_objects, list) == False:
                    sdo_objects = [sdo_objects]
                for sdo_object in sdo_objects:
                    self.final_result_list.append(
                        self._get_final_result(
                            sdo_object, extracted_observable.defanged
                        )
                    )
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

        logger.debug("Extraction of observable text complete.")

    def _get_final_result(self, sdo_object_item, defanged):
        sco_objects = pattern2sco.get_sco_objects(sdo_object_item, defanged)
        return {"stix_observable": sdo_object_item, "sco_objects": sco_objects}

    def __iter__(self):
        return self

    def __next__(self):
        if self.index < len(self.final_result_list):
            result = self.final_result_list[self.index]
            self.index += 1
            return result
        raise StopIteration
