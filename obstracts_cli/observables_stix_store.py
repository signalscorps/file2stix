"""
Contains logic for storing extracted observables and
getting stored observables.
"""

import json
import os
from stix2 import FileSystemStore, Filter, Bundle
from stix2.base import STIXJSONEncoder

# Folders for STIX2 reports
STIX2_EXTRACTIONS_FOLDER = os.path.abspath("stix2_extractions")
STIX2_REPORTS_FOLDER = os.path.abspath("stix2_reports")


class ObservablesStixStore:
    """
    Interface for handling storing and getting STIX objects
    """

    def __init__(
        self, file_store_path=STIX2_EXTRACTIONS_FOLDER, bundle_path=STIX2_REPORTS_FOLDER
    ):
        if os.path.exists(file_store_path) == False:
            os.makedirs(file_store_path)
        self.stix_file_store = FileSystemStore(file_store_path)

        if os.path.exists(bundle_path) == False:
            os.makedirs(bundle_path)
        self.stix_bundle_path = bundle_path

    def get_object(self, stix_object_name):
        """
        Query STIX2 Object based on `stix_object_name`
        """
        self.query("name", "=", stix_object_name)

    def query(self, property, operation, value):
        """
        General query of stix objects
        """
        query = [Filter(property, operation, value)]
        observables_found = self.stix_file_store.source.query(query)

        if observables_found == None or len(observables_found) == 0:
            return None

        return observables_found[0]

    def store_objects_in_filestore(self, stix_objects):
        self.stix_file_store.add(stix_objects)

    def store_objects_in_bundle(self, stix_objects):
        bundle_of_all_objects = Bundle(*stix_objects, allow_custom=True)
        stix_bundle_file = os.path.join(
            self.stix_bundle_path, f"{bundle_of_all_objects.id}.json"
        )
        with open(stix_bundle_file, "w") as f:
            f.write(json.dumps(bundle_of_all_objects, cls=STIXJSONEncoder, indent=4))

        return stix_bundle_file
