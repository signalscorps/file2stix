"""
Contains logic for storing extracted observables and
getting stored observables.
"""

import json
import os
import logging
from stix2 import FileSystemStore, Filter, Bundle
from stix2.base import STIXJSONEncoder
from stix2.datastore import DataSourceError

logger = logging.getLogger(__name__)

# Folders for STIX2 reports
STIX2_EXTRACTIONS_FOLDER = os.path.abspath("stix2_objects")
STIX2_REPORTS_FOLDER = os.path.abspath("stix2_bundles")


class ObservablesStixStore:
    """
    Interface for handling storing and getting STIX objects
    """

    def __init__(
        self, file_store_path=STIX2_EXTRACTIONS_FOLDER, bundle_path=STIX2_REPORTS_FOLDER
    ):
        if os.path.exists(file_store_path) == False:
            os.makedirs(file_store_path)
        self.stix_file_store = FileSystemStore(file_store_path, allow_custom=True)

        if os.path.exists(bundle_path) == False:
            os.makedirs(bundle_path)
        self.stix_bundle_path = bundle_path

    def get_object(
        self,
        stix_object_name,
        stix_object_identity=None,
        tlp_level=None,
        # extensions=None,
        confidence=None,        
    ):
        """
        Query STIX2 Object based on `stix_object_name`
        """
        query = [
            Filter("name", "=", stix_object_name),
        ]

        if stix_object_identity:
            query += [Filter("created_by_ref", "=", stix_object_identity)]

        if confidence:
            query += [Filter("confidence", "=", confidence)]
        
        if tlp_level:
            query += [Filter("object_marking_refs", "=", tlp_level)]

        observables_found = self.stix_file_store.source.query(query)

        if observables_found == None or len(observables_found) == 0:
            return None

        return observables_found[0]

    def store_objects_in_filestore(self, stix_objects):
        for stix_object in stix_objects:
            try:
                self.stix_file_store.add(stix_object)
            except DataSourceError as ex:
                # Ignoring error, since it occurs when file is already
                # present in the file store, which is OK
                if hasattr(stix_object, "id"):
                    logger.debug(
                        "Exception caught while storing stix object %s: %s",
                        stix_object.id,
                        ex,
                    )
                else:
                    logger.debug(
                        "Exception caught while storing stix object %s: %s",
                        stix_object,
                        ex,
                    )

    def store_objects_in_bundle(self, stix_objects, output_json_file_path=None):
        bundle_of_all_objects = Bundle(*stix_objects, allow_custom=True)

        stix_bundle_file = output_json_file_path

        if stix_bundle_file == None:
            stix_bundle_file = os.path.join(
                self.stix_bundle_path, f"{bundle_of_all_objects.id}.json"
            )
        with open(stix_bundle_file, "w") as f:
            f.write(json.dumps(bundle_of_all_objects, cls=STIXJSONEncoder, indent=4))

        return stix_bundle_file
