import json
import logging
import os
from datetime import datetime
from typing import Dict, Union, List

from pyArango.collection import Edges, Collection
from pyArango.database import DBHandle

from pyArango.connection import Connection

import yaml

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Extra

from file2stix import logger


class EmbeddedRelations(BaseModel):
    _key: str
    _from: str
    _to: str
    type: str = "embedded-relationship"
    relationship_description: Optional[str]

    class Config:
        extra = Extra.allow


class ConfigData(BaseModel):
    host: Optional[str] = 'http://127.0.0.1:8529'
    username: Optional[str] = "root"
    password: Optional[str] = ''
    database_name: Optional[str] = 'file2stix'
    document_collection_name: Optional[str] = 'stix_objects'
    edge_collection_name: Optional[str] = 'stix_relationships'


class ArangoCollections(BaseModel):
    DOCUMENT: str
    EDGE: str
    DATABASE: str


class Relationship(Enum):
    ONE = "relationship"
    MANY = "relationships"


class Additional(Enum):
    MOD = "modified"
    CLASS = "Edges"


def get_config_data(path: str):
    """
    Parse data from config
    """
    with open(path, "r") as stream:
        try:
            data = yaml.safe_load(stream)
            clear_dict = {k: v for k, v in data.items() if v is not None}
            return ConfigData(**clear_dict)
        except yaml.YAMLError:
            raise ValueError("Incorrect YML file")


def get_files_list() -> List[str]:
    """
    Go to stix2_reports dir,
    Find last added file,
    Get list of objects from this file
    """
    PATH = "./stix2_objects" if os.path.exists("stix2_objects") else None
    if not PATH:
        raise FileExistsError("stix2_objects directory not found")
    files_list = list()
    for root, dirs, files in os.walk(PATH):
        [dirs.remove(d) for d in list(dirs) if d[0] == "."]
        [files.remove(f) for f in list(files) if f[0] == "."]
        files = [os.path.join(root, file) for file in files]
        if files:
            files_list.append(max(files, key=os.path.getctime))
    return files_list


class ArangoConverter:

    def __init__(self,
                 config: ConfigData):
        self.files = []
        self.arango_user = config.username
        self.arango_pass = config.password
        self.arangoURL = config.host
        self.db_name = config.database_name
        self.document_collection = config.document_collection_name
        self.edge_collection = config.edge_collection_name
        self.skip_fields = ["_id", "_key", "_rev", "created"]
        try:
            self.conn = Connection(username=self.arango_user,
                                   password=self.arango_pass,
                                   arangoURL=self.arangoURL)
        except:
            raise ValueError("Connection to Arango is failed")

    def get_files_list(self):
        """
        Go to stix2_reports dir,
        Find last added file,
        Get list of objects from this file
        """
        PATH = "./stix2_objects" if os.path.exists("stix2_objects") else None
        if not PATH:
            raise FileExistsError("stix2_objects directory not found")
        files_list = list()
        for root, dirs, files in os.walk(PATH):
            [dirs.remove(d) for d in list(dirs) if d[0] == "."]
            [files.remove(f) for f in list(files) if f[0] == "."]
            files = [os.path.join(root, file) for file in files]
            if files:
                files_list.append(max(files, key=os.path.getctime))
        self.files = files_list

    def get_db(self) -> DBHandle:
        """
        Check Database.
        If not exist - create new
        """
        try:
            database = self.conn[self.db_name]
        except KeyError:
            logger.info(f"Create Database: {self.db_name}")
            database = self.conn.createDatabase(name=self.db_name)
        return database

    def check_collections(self, db: DBHandle) -> None:
        """
        Check Collections. If not exist - create new
        """
        try:
            _ = db[self.document_collection]
        except KeyError:
            logger.info(f"Create Document Collection: {self.document_collection}")
            db.createCollection(name=self.document_collection)
        try:
            _ = db[self.edge_collection]
        except KeyError:
            logger.info(f"Create Edge Collection: {self.edge_collection}")
            db.createCollection(className=Additional.CLASS.value, name=self.edge_collection)

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
                if stix_object.get('type') != Relationship.ONE.value:
                    if not stix_object.get(Additional.MOD.value):
                        stix_object.update({Additional.MOD.value: datetime.now().isoformat()})
                    stix_object.update({"_key": f"{stix_object.get('id')}+{stix_object.get(Additional.MOD.value)}"})
                    self.create_doc(input_dict=stix_object)
                stix_object.update({"_key": f"{stix_object.get('id')}"})
                self.validate_json(stix_object=stix_object)

    def get_arango_collection(self, collection: str):
        db = self.get_arango_database()
        return db[collection]

    def create_doc(self, input_dict: Dict):
        collection = self.get_arango_collection(collection=self.document_collection)
        try:
            collection[input_dict.get("_key")]
        except:
            collection.createDocument(input_dict).save()

    def create_update_key(self, input_dict: Dict, collection: Union[Edges, Collection]):
        """
        Try to get element from collection.
        If _key not found - create new Edge/Document"""
        try:
            doc = collection[input_dict.get("_key")]
            for k, v in input_dict.items():
                doc[k] = v
            doc.save()
        except:
            collection.createEdge(input_dict).save() if collection == self.edge_collection \
                else collection.createDocument(input_dict).save()

    def save_to_arango(self, collection: str, input_dict: Dict) -> None:
        """
        Connect to collection,
        Check, do we need to add a relationship or it alreadt exist
        Save element
        """
        collection_db = self.get_arango_collection(collection=collection)

        if collection == self.edge_collection:
            try:
                collection_db[input_dict.get("_key")]
            except:
                self.create_update_key(input_dict=input_dict, collection=collection_db)
        else:
            self.create_update_key(input_dict=input_dict, collection=collection_db)

    def create_document_relation_model(self,
                                       collection: str,
                                       stix_object: Dict[str, str],
                                       parameter: str,
                                       relationships: Union[str, List]) -> None:
        """
        Create Embedded relationship from _ref fields
        """
        to_collection = collection if Relationship.MANY.value not in relationships \
            else self.edge_collection
        if not isinstance(relationships, list):
            model = (EmbeddedRelations(_key=f"{stix_object.get('id')}+{relationships}",
                                       _from=f"{collection}/{stix_object.get('id')}",
                                       _to=f"{to_collection}/{relationships}",
                                       relationship_description=parameter))
            self.save_to_arango(collection=self.edge_collection,
                                input_dict=model.dict())
        else:
            [self.create_document_relation_model(collection=self.document_collection,
                                                 stix_object=stix_object,
                                                 parameter=parameter,
                                                 relationships=relation) for relation in relationships]

    def create_relation_model(self,
                              collection: str,
                              stix_object: Dict[str, str]) -> None:
        """
        Create Embedded relationship from relation type
        """
        to_collection = collection if Relationship.MANY.value not in stix_object.get('target_ref') \
            else self.edge_collection
        model = EmbeddedRelations(_key=f"{stix_object.get('id')}",
                                  _from=f"{collection}/{stix_object.get('source_ref')}",
                                  _to=f"{to_collection}/{stix_object.get('target_ref')}",
                                  type=Relationship.ONE.value).dict()
        model.update(stix_object)
        self.save_to_arango(collection=self.edge_collection, input_dict=model)

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
            self.save_to_arango(self.document_collection, stix_object)
            for k, v in stix_object.items():
                if self.is_ref(key=k):
                    self.create_document_relation_model(collection=self.document_collection,
                                                        stix_object=stix_object,
                                                        parameter=k,
                                                        relationships=v)

        else:
            self.create_relation_model(collection=self.document_collection,
                                       stix_object=stix_object)


def check_arango_connection(path: str):
    config = get_config_data(path)
    ArangoConverter(config=config)


def start_saving_to_arango(path: str):
    config = get_config_data(path)
    converter = ArangoConverter(config=config)
    converter.get_files_list()
    converter.get_arango_model()

