import json
import logging
import os
from typing import Dict, Union, List

from pyArango.collection import Edges, Collection
from pyArango.database import DBHandle

from pyArango.connection import Connection
from dotenv import load_dotenv

import argparse

from backends.arangodb.schemas import ArangoCollections, Relationship, EmbeddedRelations, Additional

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser()
parser.add_argument("--login", help="ArangoDB login", default=os.getenv("ARANGO_USER"))
parser.add_argument("--password", help="ArangoDB password", default=os.getenv("ARANGO_PASS"))
parser.add_argument("--arangourl", help="ArangoDB URL", default=os.getenv("ARANGO_URL"))

args = parser.parse_args()


def get_files_list() -> List[str]:
    """
    Go to stix2_reports dir,
    Find last added file,
    Get list of objects from this file
    """
    PATH = "./stix2_objects" if os.path.exists("stix2_objects") else None
    if not PATH:
        raise FileExistsError()
    files_list = list()
    for root, dirs, files in os.walk(PATH):
        files = [os.path.join(root, file) for file in files]
        if files:
            files_list.append(max(files, key=os.path.getctime))
    return files_list


class ArangoConverter:

    def __init__(self,
                 user: str = args.login,
                 password: str = args.password,
                 arango_url: str = args.arangourl):
        self.files = get_files_list()
        self.arango_user = user
        self.arango_pass = password
        self.arangoURL = arango_url
        self.skip_fields = ["_id", "_key", "_rev", "created"]
        try:
            self.conn = Connection(username=self.arango_user,
                                   password=self.arango_pass,
                                   arangoURL=self.arangoURL)
        except:
            raise ValueError("Incorrect arguments")

    def get_db(self) -> DBHandle:
        """
        Check Database.
        If not exist - create new
        """
        try:
            database = self.conn[ArangoCollections.DATABASE.value]
        except KeyError:
            logger.info(f"Create Database: {ArangoCollections.DATABASE.value}")
            database = self.conn.createDatabase(name=ArangoCollections.DATABASE.value)
        return database

    @staticmethod
    def check_collections(db: DBHandle) -> None:
        """
        Check Collections. If not exist - create new
        """
        try:
            _ = db[ArangoCollections.DOCUMENT.value]
        except KeyError:
            logger.info(f"Create Document Collection: {ArangoCollections.DOCUMENT.value}")
            db.createCollection(name=ArangoCollections.DOCUMENT.value)
        try:
            _ = db[ArangoCollections.EDGE.value]
        except KeyError:
            logger.info(f"Create Edge Collection: {ArangoCollections.EDGE.value}")
            db.createCollection(className=Additional.CLASS.value, name=ArangoCollections.EDGE.value)

    def get_arango_database(self) -> DBHandle:
        db = self.get_db()
        self.check_collections(db)
        return db

    def get_arango_model(self) -> None:
        """
        Add _key to stix objects
        """
        for file in self.files:
            with open(file) as stix:
                stix_object = json.load(stix)
                stix_object.update({"_key": f"{stix_object.get('id')}"})
                self.validate_json(stix_object=stix_object)

    @staticmethod
    def create_update_key(input_dict: Dict, collection: Union[Edges, Collection]):
        """
        Try to get element from collection.
        If _key not found - create new Edge/Document"""
        try:
            doc = collection[input_dict.get("_key")]
            for k, v in input_dict.items():
                doc[k] = v
            doc.save()
        except:
            collection.createEdge(input_dict).save() if collection == ArangoCollections.EDGE \
                else collection.createDocument(input_dict).save()

    def save_to_arango(self, collection: ArangoCollections, input_dict: Dict) -> None:
        """
        Connect to collection,
        Check, do we need to add a relationship or it alreadt exist
        Save element
        """
        db = self.get_arango_database()
        collection_db = db[collection.value]
        if collection == ArangoCollections.EDGE:
            try:
                collection_db[input_dict.get("_key")]
            except:
                self.create_update_key(input_dict=input_dict, collection=collection_db)
        else:
            self.create_update_key(input_dict=input_dict, collection=collection_db)

    def create_document_relation_model(self,
                                       collection: ArangoCollections,
                                       stix_object: Dict[str, str],
                                       parameter: str,
                                       relationships: Union[str, List]) -> None:
        """
        Create Embedded relationship from _ref fields
        """
        to_collection = collection.value if Relationship.MANY.value not in relationships \
            else ArangoCollections.EDGE.value
        if not isinstance(relationships, list):
            model = (EmbeddedRelations(_key=f"{stix_object.get('id')}+{relationships}",
                                       _from=f"{collection.value}/{stix_object.get('id')}",
                                       _to=f"{to_collection}/{relationships}",
                                       relationship_description=parameter))
            self.save_to_arango(collection=ArangoCollections.EDGE,
                                input_dict=model.dict())
        else:
            [self.create_document_relation_model(collection=ArangoCollections.DOCUMENT,
                                                 stix_object=stix_object,
                                                 parameter=parameter,
                                                 relationships=relation) for relation in relationships]

    def create_relation_model(self,
                              collection: ArangoCollections,
                              stix_object: Dict[str, str]) -> None:
        """
        Create Embedded relationship from relation type
        """
        to_collection = collection.value if Relationship.MANY.value not in stix_object.get('target_ref')\
            else ArangoCollections.EDGE.value
        model = EmbeddedRelations(_key=f"{stix_object.get('id')}",
                                  _from=f"{collection.value}/{stix_object.get('source_ref')}",
                                  _to=f"{to_collection}/{stix_object.get('target_ref')}",
                                  type=Relationship.ONE.value).dict()
        model.update(stix_object)
        self.save_to_arango(collection=ArangoCollections.EDGE, input_dict=model)

    @staticmethod
    def is_ref(key: str):
        return '_ref' in key[-5::]

    def validate_json(self, stix_object: Dict) -> None:
        """
        Save full object if it's not relationship type,
        Create Edge format from relationship type,
        Validate Embedded relationships
        """
        if stix_object.get('type') != Relationship.ONE.value:
            self.save_to_arango(ArangoCollections.DOCUMENT, stix_object)
            for k, v in stix_object.items():
                if self.is_ref(key=k):
                    self.create_document_relation_model(collection=ArangoCollections.DOCUMENT,
                                                        stix_object=stix_object,
                                                        parameter=k,
                                                        relationships=v)

        else:
            self.create_relation_model(collection=ArangoCollections.DOCUMENT,
                                       stix_object=stix_object)


def main():
    converter = ArangoConverter()
    converter.get_arango_model()
    logger.info(f"Database successfully updated!")


if __name__ == '__main__':
    main()
