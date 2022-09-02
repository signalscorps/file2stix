import json
import logging
import os
from datetime import datetime
from enum import Enum
from typing import Dict, Union, List, Optional

from pyArango.collection import Edges, Collection
from pyArango.database import DBHandle
from pydantic import BaseModel, Extra

from pyArango.connection import Connection

import argparse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser()
parser.add_argument("--login", help="ArangoDB login")
parser.add_argument("--password", help="ArangoDB password")
parser.add_argument("--arangourl", help="ArangoDB URL", default="http://127.0.0.1:8529")
args = parser.parse_args()


class EmbeddedRelations(BaseModel):
    _key: str
    _from: str
    _to: str
    type: str = "embedded-relationship"
    relationship_description: Optional[str]

    class Config:
        extra = Extra.allow


class ArangoCollections(Enum):
    DOCUMENT = 'stix_objects'
    EDGE = 'stix_relationships'
    DATABASE = 'stix_database'


class Relationship(Enum):
    ONE = "relationship"
    MANY = "relationships"


class Additional(Enum):
    MOD = "modified"
    CLASS = "Edges"


def get_last_modified_file() -> Dict:
    """
    Go to stix2_reports dir,
    Find last added file,
    Get list of objects from this file
    """
    PATH = "./stix2_reports"
    files = os.listdir(PATH)
    if not files:
        raise FileExistsError
    files = [file for file in [os.path.join(PATH, file) for file in files] if os.path.isfile(file)]

    file = max(files, key=os.path.getctime)
    logger.info(f"Start to process file: {file}")
    with open(file) as file:
        return json.load(file).get('objects')


class ArangoConverter:

    def __init__(self,
                 user: str = args.login,
                 password: str = args.password,
                 arango_url: str = args.arangourl):
        self.objects = get_last_modified_file()
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

    def create_update_key(self, input_dict: Dict, collection: Union[Edges, Collection]):
        """
        Try to update element from input dict.
        If _key not found - create new Edge/Document"""
        try:
            doc = collection[input_dict.get('_key')]
            for k, v in input_dict.items():
                if k not in self.skip_fields:
                    doc[k] = v
            if Additional.MOD.value not in input_dict:
                doc[Additional.MOD.value] = datetime.now()
            doc.save()
        except:
            collection.createEdge(input_dict).save() if collection == ArangoCollections.EDGE \
                else collection.createDocument(input_dict).save()

    def save_to_arango(self, collection: ArangoCollections, input_dict: Dict) -> None:
        """
        Connect to collection,
        Adding _key field if it not exist,
        Save element
        """
        db = self.get_arango_database()
        collection = db[collection.value]
        input_dict.update({'_key': input_dict.get('id')}) if not input_dict.get('_key') else None
        self.create_update_key(input_dict=input_dict, collection=collection)

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
        if type(relationships) is not list:
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

    def validate_json(self) -> None:
        """
        Save full object if it's not relationship type,
        Create Edge format from relationship type,
        Validate Embedded relationships
        """
        for stix_object in self.objects:
            if stix_object.get('type') != Relationship.ONE.value:
                self.save_to_arango(ArangoCollections.DOCUMENT, stix_object)
                for k, v in stix_object.items():
                    if '_ref' in k[-5::]:
                        self.create_document_relation_model(collection=ArangoCollections.DOCUMENT,
                                                            stix_object=stix_object,
                                                            parameter=k,
                                                            relationships=v)

            else:
                self.create_relation_model(collection=ArangoCollections.DOCUMENT,
                                           stix_object=stix_object)


def main():
    converter = ArangoConverter()
    converter.validate_json()
    logger.info(f"Database successfully updated!")


if __name__ == '__main__':
    main()
