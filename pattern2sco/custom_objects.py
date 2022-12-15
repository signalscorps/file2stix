"""
Contains defintions of custom SCO objects.
"""

from stix2 import properties, CustomObservable


@CustomObservable(
    "cryptocurrency-transaction",
    [
        ("currency_symbol", properties.StringProperty(required=True)),
        ("hash", properties.StringProperty(required=True)),
        ("input", properties.ListProperty(properties.DictionaryProperty)),
        ("output", properties.ListProperty(properties.DictionaryProperty)),
        ("block_id", properties.StringProperty()),
        ("fee", properties.StringProperty()),
    ],
    id_contrib_props=["currency_symbol", "hash"],
    extension_name="extension-definition--532ae28d-137b-4b89-afb7-9cf9b504191b",
)
class CryptocurrencyTransaction(object):
    def __init__(self, input=None, output=None, **kwargs):
        if input != None:
            for input_item in input:
                # If input_item contains dictionary keys other than
                # {"address_ref", "amount_sent"}, then raise
                if input_item.keys() > {"address_ref", "amount_sent"}:
                    raise ValueError(
                        f"Individual item in 'input' field should be a dictionary with fields 'address_ref' and 'amount_sent'"
                    )

        if output != None:
            for input_item in input:
                # If input_item contains dictionary keys other than
                # {"address_ref", "amount_received"}, then raise
                if input_item.keys() > {"address_ref", "amount_received"}:
                    raise ValueError(
                        f"Individual item in 'input' field should be a dictionary with fields 'address_ref' and 'amount_received'"
                    )


@CustomObservable(
    "credit-card",
    [
        ("number", properties.StringProperty(required=True)),
        ("issuer", properties.StringProperty(required=True)),
        ("issuing_bank_name", properties.StringProperty()),
        ("issuing_bank_country", properties.StringProperty()),
        ("cardholder_name", properties.StringProperty()),
        ("start_date", properties.StringProperty()),
        ("expiry_date", properties.StringProperty()),
        ("security_code", properties.StringProperty()),
    ],
    id_contrib_props=["issuer", "number"],
    extension_name="extension-definition--abd6fc0e-749e-4e6c-a20c-1faa419f5ee4",
)
class CreditCard(object):
    pass


@CustomObservable(
    "bank-account",
    [
        ("bank_country", properties.StringProperty(required=True)),
        ("iban_number", properties.StringProperty(required=True)),
        ("bank_name", properties.StringProperty()),
        ("currency", properties.StringProperty()),
        ("holder_name", properties.StringProperty()),
        ("swift_code", properties.StringProperty()),
    ],
    id_contrib_props=["bank_country", "iban_number"],
    extension_name="extension-definition--349c1029-4052-4635-a064-263cb17290ea",
)
class BankAccount(object):
    pass


@CustomObservable(
    "user-agent",
    [
        ("string", properties.StringProperty(required=True)),
        # ("software", properties.StringProperty(required=True)),
        # ("system", properties.StringProperty(required=False)),
        # ("platform", properties.StringProperty(required=False)),
        # ("browser", properties.StringProperty(required=False)),
        # ("browser_enhancements", properties.StringProperty(required=False)),
    ],
    # id_contrib_props=["string", "software", "system", "platform", "browser", "browser_enhancements"],
    id_contrib_props=["string"],
    extension_name="extension-definition--6cea4dc9-9517-44b8-b021-ae82e2f1de43",
)
class UserAgent(object):
    pass
