"""
Contains logic for extracting observables.
"""

import logging

from obstracts_cli.cache import Cache
from obstracts_cli.config import Config
from obstracts_cli.observables import (
    CustomObervable,
    MITREEnterpriseAttackObservable,
    MITREMobileAttackObservable,
    MITRECapecObservable,
)

logger = logging.getLogger(__name__)


class ExtractStixObservables:
    """
    Iterable that extracts all the observables matching a given format.
    In each iteration, it returns the next extracted observable as a STIX object..
    """

    def __init__(self, observable_cls, text, cache: Cache, config: Config):
        self.index = 0
        self.update_stix2_extractions = True
        self.extracted_observables = []

        # Handling special observables like MITRE ATT&CK and CAPEC
        if (
            observable_cls == MITREEnterpriseAttackObservable
            or observable_cls == MITREMobileAttackObservable
            or observable_cls == MITRECapecObservable
        ):
            self.update_stix2_extractions = False
            if cache.is_mitre_cti_database_in_cache():
                observable_cls.build_extraction_regex(cache.cti_folder_path)
            else:
                logger.warning(
                    "Not extracting MITRE Observable since MITRE CTI database is not present in cache. "
                    "Use --update-mitre-cti-database option to update MITRE CTI database." 
                )
                return
        if observable_cls == CustomObervable:
            if config.custom_extraction_file != None:
                observable_cls.build_extraction_regex(config.custom_extraction_file)
            else:
                logger.info("Custom extraction file not given, hence not extracting any custom observables.")
                return

        self.extracted_observables = observable_cls.extract_observables_from_text(text)

    def __iter__(self):
        return self

    def __next__(self):
        if self.index < len(self.extracted_observables):
            extracted_observable = self.extracted_observables[self.index]
            self.index += 1
            return extracted_observable.get_sdo_object(), self.update_stix2_extractions
        raise StopIteration
