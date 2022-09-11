from enum import Enum
from typing import Optional

from pydantic import BaseModel, Extra


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


class Relationship(Enum):
    ONE = "relationship"
    MANY = "relationships"


class Additional(Enum):
    MOD = "modified"
    CLASS = "Edges"