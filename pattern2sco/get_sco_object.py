import re
from sys import maxsize
from stix2 import Indicator, IPv4Address, NetworkTraffic, IPv6Address


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

    return sco_objects
