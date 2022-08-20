"""
Stores the config of obstracts-cli tool
"""
from dataclasses import dataclass

@dataclass
class Config:
    input_file_path: str
    cache_folder: str = "obstracts-cache"
    update_mitre_cti_database: bool = False
    