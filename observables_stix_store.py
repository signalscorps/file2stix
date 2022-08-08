"""
Contains logic for storing extracted observables and
getting stored observables.
"""
import json
from stix2 import FileSystemStore, Bundle, STIXJSONEncoder, Filter
from os import path


class ObservablesStixStore:
    def __init__(
        self, file_store_path="stix2_extractions", bundle_path="stix2_reports"
    ):
        self.stix_fs = FileSystemStore(file_store_path)
        self.bundle_path = bundle_path

    def store_in_filestore(self, stix_object):
        self.stix_fs.add(stix_object)

    def store_objects_in_bundle(self, stix_objects):
        BundleOfAllObjects = Bundle(*list(stix_objects.values()), allow_custom=True)
        bundle_file = path.join(self.bundle_path, f"{BundleOfAllObjects.id}.json")
        with open(bundle_file, "w") as f:
            f.write(json.dumps(BundleOfAllObjects, cls=STIXJSONEncoder, indent=4))

    def get_from_filestorestore(self, stix_object_name):
        return self.stix_fs.source.query(Filter("name", "=", stix_object_name))
