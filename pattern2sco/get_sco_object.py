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
    Software,
)
from pattern2sco.custom_objects import (
    Cryptocurrency,
    CreditCard,
    IBAN,
    UserAgent,
)


def extract_name_from_regex(regex, pattern):
    return re.search(regex, pattern).groups()[0]


def get_sco_objects(sdo_object, defanged=False):
    """
    Get SCO object of respective Indicator SDO objects
    """
    sco_objects = []

    if isinstance(sdo_object, Indicator):
        if sdo_object.name.startswith("ipv4"):
            ipv4_regex = r"ipv4-addr:value = '([\.0-9\/]*)'"
            ipv4_addr = re.search(ipv4_regex, sdo_object.pattern).groups()[0]
            ipv4_object = IPv4Address(
                value=ipv4_addr,
                defanged=defanged,
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
                )
            ]

        if sdo_object.name.startswith("URL"):
            url_regex = r"url:value = '(.*)'"
            url_name = re.search(url_regex, sdo_object.pattern).groups()[0]
            sco_objects += [
                URL(
                    value=url_name,
                    defanged=defanged,
                )
            ]

        if sdo_object.name.startswith("File name"):
            regex = r"file:name = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                File(
                    name=name,
                    defanged=defanged,
                )
            ]

        if sdo_object.name.startswith("Directory"):
            regex = r"directory:path = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                Directory(
                    path=name,
                    defanged=defanged,
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
                )
            ]

        if sdo_object.name.startswith("Email Address"):
            regex = r"email-addr:value = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                EmailAddress(
                    value=name,
                    defanged=defanged,
                )
            ]

        if sdo_object.name.startswith("MAC Address"):
            regex = r"mac-addr:value = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                MACAddress(
                    value=name,
                    defanged=defanged,
                )
            ]

        if sdo_object.name.startswith("Windows Registry Key"):
            regex = r"windows-registry-key:key = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                WindowsRegistryKey(
                    key=name,
                    defanged=defanged,
                )
            ]

        if sdo_object.name.startswith("User Agent"):
            regex = r"user-agent:string = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)

            # extract each component of user_agent
            # software = None
            # system = None
            # platform = None
            # browser = None
            # browser_enhancements = None

            # user_agent_search = re.search("(Mozilla/5\.0) \((.*)\)", name)
            # if user_agent_search != None:
            #     software = user_agent_search.groups()[0]
            #     system = user_agent_search.groups()[1]

            # user_agent_search = re.search("(Mozilla/5\.0) \((.*)\) (.*)", name)
            # if user_agent_search != None:
            #     software = user_agent_search.groups()[0]
            #     system = user_agent_search.groups()[1]
            #     platform = user_agent_search.groups()[2]

            # user_agent_search = re.search("(Mozilla/5\.0) \((.*)\) (.*) \((.*)\)", name)
            # if user_agent_search != None:
            #     software = user_agent_search.groups()[0]
            #     system = user_agent_search.groups()[1]
            #     platform = user_agent_search.groups()[2]
            #     browser = user_agent_search.groups()[3]

            # user_agent_search = re.search(
            #     "(Mozilla/5\.0) \((.*)\) (.*) \((.*)\) (.*)", name
            # )
            # if user_agent_search != None:
            #     software = user_agent_search.groups()[0]
            #     system = user_agent_search.groups()[1]
            #     platform = user_agent_search.groups()[2]
            #     browser = user_agent_search.groups()[3]
            #     browser_enhancements = user_agent_search.groups()[4]

            sco_objects += [
                UserAgent(
                    string=name,
                    defanged=defanged,
                )
            ]

        if sdo_object.name.startswith("AS"):
            regex = r"autonomous-system:number = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                AutonomousSystem(
                    number=name,
                    defanged=defanged,
                )
            ]

        if sdo_object.name.startswith("BTC"):
            regex = r"cryptocurrency:address = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                Cryptocurrency(
                    # symbol="BTC",
                    address=name,
                    defanged=defanged,
                )
            ]

        if sdo_object.name.startswith("ETH"):
            regex = r"cryptocurrency:address = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                Cryptocurrency(
                    # symbol="ETH",
                    address=name,
                    defanged=defanged,
                )
            ]

        if sdo_object.name.startswith("XMR"):
            regex = r"cryptocurrency:address = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                Cryptocurrency(
                    # symbol="XMR",
                    address=name,
                    defanged=defanged,
                )
            ]

        if sdo_object.name.startswith("Mastercard Credit Card"):
            regex = r"credit-card:number = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                CreditCard(
                    issuer="Mastercard",
                    number=name,
                    defanged=defanged,
                )
            ]

        if sdo_object.name.startswith("VISA Credit Card"):
            regex = r"credit-card:number = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                CreditCard(
                    issuer="VISA",
                    number=name,
                    defanged=defanged,
                )
            ]

        if sdo_object.name.startswith("Amex Credit Card"):
            regex = r"credit-card:number = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                CreditCard(
                    issuer="Amex",
                    number=name,
                    defanged=defanged,
                )
            ]

        if sdo_object.name.startswith("Union Pay Credit Card"):
            regex = r"credit-card:number = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                CreditCard(
                    issuer="Union Pay",
                    number=name,
                    defanged=defanged,
                )
            ]

        if sdo_object.name.startswith("Diners Credit Card"):
            regex = r"credit-card:number = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                CreditCard(
                    issuer="Diners",
                    number=name,
                    defanged=defanged,
                )
            ]

        if sdo_object.name.startswith("JCB Credit Card"):
            regex = r"credit-card:number = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                CreditCard(
                    issuer="JCB",
                    number=name,
                    defanged=defanged,
                )
            ]

        if sdo_object.name.startswith("IBAN"):
            regex = r"iban:number = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)
            sco_objects += [
                IBAN(
                    bank_country=name[:2],
                    iban_number=name,
                    defanged=defanged,
                )
            ]

        if sdo_object.name.startswith("CPE"):
            regex = r"software:cpe = '(.*)'"
            name = extract_name_from_regex(regex, sdo_object.pattern)

            cpe_list = name.split(":")
            cpe_part = cpe_list[2]
            cpe_vendor = cpe_list[3]
            cpe_product = cpe_list[4]
            cpe_version = cpe_list[5]
            cpe_update = cpe_list[6]
            cpe_edition = cpe_list[7]
            cpe_language = cpe_list[8]
            cpe_sw_edition = cpe_list[9]
            cpe_target_sw = cpe_list[10]
            cpe_target_hw = cpe_list[11]
            cpe_other = cpe_list[12]

            software = Software(
                name=f"CPE: {cpe_vendor} {cpe_product} {cpe_version}",
                cpe=name,
                version=cpe_version,
                vendor=cpe_vendor,
                extensions={
                    "extension-definition--6c453e0f-9895-498f-a273-2e2dda473377": {
                        "extension_type": "property-extension",
                        "cpe23Uri": name,
                        "part": cpe_part,
                        "vendor": cpe_vendor,
                        "product": cpe_product,
                        "version": cpe_version,
                        "update": cpe_update,
                        "edition": cpe_edition,
                        "language": cpe_language,
                        "sw_edition": cpe_sw_edition,
                        "target_sw": cpe_target_sw,
                        "target_hw": cpe_target_hw,
                        "other": cpe_other,
                    }
                },
            )

            sco_objects += [software]

    return sco_objects
