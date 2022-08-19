"""
Stores the config of obstracts-cli tool
"""
from dataclasses import dataclass, field

@dataclass
class Config:
    input_file_path: str
    