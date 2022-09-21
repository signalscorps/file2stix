"""
Contains defintions of custom SCO objects.
"""

import os
from pathlib import Path
from stix2 import properties, FileSystemSource, CustomObservable, CustomExtension

PATTERN2STIX_FOLDER = Path(os.path.abspath(__file__)).parent
STIX2_OBJECTS_FOLDER = PATTERN2STIX_FOLDER / "stix2-objects"
STIX_OBJECTS_STORE = FileSystemSource(STIX2_OBJECTS_FOLDER, allow_custom=True)

CRYPTOCURRENCY_EXTENSION = STIX_OBJECTS_STORE.get(
    stix_id="extension-definition--532ae28d-137b-4b89-afb7-9cf9b504191b"
)

CREDIT_CARD_EXTENSION = STIX_OBJECTS_STORE.get(
    stix_id="extension-definition--abd6fc0e-749e-4e6c-a20c-1faa419f5ee4"
)


@CustomObservable(
    "cryptocurrency",
    [
        ("symbol", properties.StringProperty(required=True)),
        ("address", properties.StringProperty(required=True)),
    ],
    id_contrib_props=["symbol", "address"]
)
class Cryptocurrency(object):
    def __init__(self, symbol, **kwargs):
        if symbol not in ["BTC", "ETH", "XMR"]:
            raise ValueError(
                "'%s' is not a recognized symbol of cryptocurrency." % symbol
            )


# @CustomObservable(
#     "credit-card",
#     [
#         ("symbol", properties.StringProperty(required=True)),
#         ("address", properties.StringProperty(required=True)),
#     ],
#     extension_name="extension-definition--532ae28d-137b-4b89-afb7-9cf9b504191b",
# )
# class Cryptocurrency(object):
#     def __init__(self, symbol, **kwargs):
#         if symbol not in ["BTC", "ETH", "XMR"]:
#             raise ValueError(
#                 "'%s' is not a recognized symbol of cryptocurrency." % symbol
#             )
