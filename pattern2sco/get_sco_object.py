import re
from stix2 import Indicator, IPv4Address, NetworkTraffic


def get_sco_objects(sdo_object, defanged=False):
    sco_objects = []

    if isinstance(sdo_object, Indicator):
        # TODO: Not sure if the below logic is right in all cases
        value = sdo_object.name.split(":")[1].strip()

        if sdo_object.name.startswith("ipv4"):
            ipv4_object = IPv4Address(
                value=value,
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

    return sco_objects
