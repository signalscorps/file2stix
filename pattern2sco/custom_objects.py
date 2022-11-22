"""
Contains defintions of custom SCO objects.
"""

from stix2 import properties, CustomObservable


@CustomObservable(
    "cryptocurrency",
    [
        ("symbol", properties.StringProperty(required=True)),
        ("address", properties.StringProperty(required=True)),
    ],
    id_contrib_props=["symbol", "address"],
    extension_name="extension-definition--532ae28d-137b-4b89-afb7-9cf9b504191b",
)
class Cryptocurrency(object):
    def __init__(self, symbol, **kwargs):
        if symbol not in ["BTC", "ETH", "XMR"]:
            raise ValueError(
                "'%s' is not a recognized symbol of cryptocurrency." % symbol
            )


@CustomObservable(
    "credit-card",
    [
        ("provider", properties.StringProperty(required=True)),
        ("number", properties.StringProperty(required=True)),
    ],
    id_contrib_props=["provider", "number"],
    extension_name="extension-definition--abd6fc0e-749e-4e6c-a20c-1faa419f5ee4",
)
class CreditCard(object):
    pass


@CustomObservable(
    "iban",
    [
        ("country_code", properties.StringProperty(required=True)),
        ("number", properties.StringProperty(required=True)),
    ],
    id_contrib_props=["country_code", "number"],
    extension_name="extension-definition--349c1029-4052-4635-a064-263cb17290ea",
)
class IBAN(object):
    pass

@CustomObservable(
    "user-agent",
    [
        ("string", properties.StringProperty(required=True)),
        ("software", properties.StringProperty(required=True)),
        ("system", properties.StringProperty(required=False)),
        ("platform", properties.StringProperty(required=False)),
        ("browser", properties.StringProperty(required=False)),
        ("browser_enhancements", properties.StringProperty(required=False)),
    ],
    id_contrib_props=["string", "software", "system", "platform", "browser", "browser_enhancements"],
    extension_name="extension-definition--6cea4dc9-9517-44b8-b021-ae82e2f1de43",
)
class UserAgent(object):
    pass
