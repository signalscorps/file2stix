import re
from stix2 import (
    Indicator,
    IPv4Address,
    NetworkTraffic,
    IPv6Address,
    DomainName,
    URL,
    File,
    Directory,
    EmailAddress,
    MACAddress,
    WindowsRegistryKey,
    AutonomousSystem,
)
from pattern2sco.custom_objects import (
    Cryptocurrency,
    CreditCard,
    IBAN,
)


def extract_name_from_regex(regex, pattern):
    return re.search(regex, pattern).groups()[0]


def get_sco_objects(sdo_object, defanged=False):
    sco_objects = []
    # created_by_ref = None
    # if hasattr(sdo_object, "created_by_ref"):
    #     created_by_ref = sdo_object.created_by_ref

    if isinstance(sdo_object, Indicator):
        if sdo_object.name.startswith("ipv4"):
            ipv4_regex = r"ipv4-addr:value = '([\.0-9\/]*)'"
            ipv4_addr = re.search(ipv4_regex, sdo_object.pattern).groups()[0]
            ipv4_object = IPv4Address(
                value=ipv4_addr,
                defanged=defanged,
                object_marking_refs=sdo_object.object_marking_refs,
            )
            sco_objects += [ipv4_object]

            port_regex = r"network-traffic:dst_port = '(.*)'"
            try:
                port = re.search(port_regex, sdo_object.pattern).groups()[0]
                sco_objects += [
                    NetworkTraffic(
                        dst_ref=ipv4_object,
                        dst_port=port,
                        protocols=["ipv4"],
                        defanged=defanged,
                        object_marking_refs=sdo_object.object_marking_refs,
                    )
                ]
            except Exception as error:
                pass

        if sdo_object.name.startswith("ipv6"):
            ipv6_regex = r"ipv6-addr:value = '([0-9a-fA-F\:\/]*)'"
            ipv6_addr = re.search(ipv6_regex, sdo_object.pattern).groups()[0]
            ipv4_object = IPv6Address(
                value=ipv6_addr,
                defanged=defanged,
                object_marking_refs=sdo_object.object_marking_refs,
            )
            sco_objects += [ipv4_object]

            port_regex = r"network-traffic:dst_port = '(.*)'"
            try:
                port = re.search(port_regex, sdo_object.pattern).groups()[0]
                sco_objects += [
                    NetworkTraffic(
                        dst_ref=ipv4_object,
                        dst_port=port,
                        protocols=["ipv6"],
                        defanged=defanged,
                        object_marking_refs=sdo_object.object_marking_refs,
                    )
                ]
            except Exception as error:
                pass

        if sdo_object.name.startswith("Domain"):
            domain_regex = r"domain-name:value = '(.*)'"
            domain_name = re.search(domain_regex, sdo_object.pattern).groups()[0]
            sco_objects += [
                DomainName(
                    value=domain_name,
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("URL"):
            url_regex = r"url:value = '(.*)'"
            url_name = re.search(url_regex, sdo_object.pattern).groups()[0]
            sco_objects += [
                URL(
                    value=url_name,
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("File name"):
            regex = r"file:name = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                File(
                    name=name,
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("Directory"):
            regex = r"directory:path = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                Directory(
                    path=name,
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("md5"):
            regex = r"file:hash.md5 = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                File(
                    hashes={
                        "md5": name,
                    },
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("sha1"):
            regex = r"file:hash.sha1 = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                File(
                    hashes={
                        "sha1": name,
                    },
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("sha256"):
            regex = r"file:hash.sha256 = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                File(
                    hashes={
                        "sha256": name,
                    },
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("sha512"):
            regex = r"file:hash.sha512 = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                File(
                    hashes={
                        "sha512": name,
                    },
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("ssdeep"):
            regex = r"file:hash.ssdeep = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                File(
                    hashes={
                        "ssdeep": name,
                    },
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("ssdeep"):
            regex = r"file:hash.ssdeep = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                File(
                    hashes={
                        "ssdeep": name,
                    },
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("Email Address"):
            regex = r"email-addr:value = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                EmailAddress(
                    value=name,
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("MAC Address"):
            regex = r"mac-addr:value = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                MACAddress(
                    value=name,
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("Windows Registry Key"):
            regex = r"windows-registry-key:key = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                WindowsRegistryKey(
                    key=name,
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        # if sdo_object.name.startswith("User Agent"):
        #     regex = r"network-traffic:extensions.'http-requestext'.request_header.'User-Agent' = '(.*)'"
        #     name = extract_name_from_regex(regex, sdo_object.pattern)
        #     sco_objects += [
        #         NetworkTraffic(
        #             protocols=["http", "https", "tcp", "udp"],
        #             extensions={
        #                 "http-request-ext": {
        #                     "request_method": "",
        #                     "request_value": "",
        #                     "request_header": {"User-Agent": name},
        #                 }
        #             },
        #             defanged=defanged,
        #             object_marking_refs=sdo_object.object_marking_refs,
        #         )
        #     ]

        if sdo_object.name.startswith("AS"):
            regex = r"autonomous-system:number = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                AutonomousSystem(
                    number=name,
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("BTC"):
            regex = r"artifact:payload_bin = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                Cryptocurrency(
                    symbol="BTC",
                    address=name,
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("ETH"):
            regex = r"artifact:payload_bin = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                Cryptocurrency(
                    symbol="ETH",
                    address=name,
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("XMR"):
            regex = r"artifact:payload_bin = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                Cryptocurrency(
                    symbol="XMR",
                    address=name,
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("Mastercard Credit Card"):
            regex = r"credit-card:number = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                CreditCard(
                    provider="Mastercard",
                    number=name,
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("VISA Credit Card"):
            regex = r"credit-card:number = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                CreditCard(
                    provider="VISA",
                    number=name,
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("Amex Credit Card"):
            regex = r"credit-card:number = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                CreditCard(
                    provider="Amex",
                    number=name,
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("Union Pay Credit Card"):
            regex = r"credit-card:number = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                CreditCard(
                    provider="Union Pay",
                    number=name,
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("Diners Credit Card"):
            regex = r"credit-card:number = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                CreditCard(
                    provider="Diners",
                    number=name,
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

        if sdo_object.name.startswith("JCB Credit Card"):
            regex = r"credit-card:number = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                CreditCard(
                    provider="JCB",
                    number=name,
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]
        
        if sdo_object.name.startswith("IBAN"):
            regex = r"iban:number = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                IBAN(
                    country_code=name[:2],
                    number=name,
                    defanged=defanged,
                    object_marking_refs=sdo_object.object_marking_refs,
                )
            ]

    return sco_objects
