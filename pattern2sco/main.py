from stix2 import Indicator, IPv4Address

def get_sco_objects(sdo_object, defanged=False):
    sco_objects = []

    if isinstance(sdo_object, Indicator):
        # TODO: Not sure if the below logic is right in all cases
        value = sdo_object.name.split(":")[1].strip()

        if sdo_object.name.startswith("ipv4"):
            sco_objects += [IPv4Address(
                value=value,
                defanged=defanged,
                object_marking_refs=sdo_object.object_marking_refs
            )]
        
    return sco_objects
