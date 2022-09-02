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