"""
Implements a command line interface, which takes in a 
pattern string and outputs the SCO object.
"""

import logging
import re
from stix2 import Indicator

from pattern2sco.get_sco_object import get_sco_objects

logger = logging.getLogger(__name__)


def main(pattern):

    observable_regex_map = {
        "ipv4": r"\[ ipv4-addr:value = '.*' \]",
        "ipv4-with-port": r"\[ ipv4-addr:value = '.*' AND network-traffic:dst_port = '.*' \]",
        "ipv6": r"\[ ipv6-addr:value = '.*' \]",
        "ipv6-with-port": r"\[ ipv6-addr:value = '.*' AND network-traffic:dst_port = '.*' \]",
        "File name": r"\[ file:name = '.*' \]",
        "md5": r"\[ file:hash.md5 = '.*' \]",
        "sha1": r"\[ file:hash.sha1 = '.*' \]",
        "sha256": r"\[ file:hash.sha256 = '.*' \]",
        "sha512": r"\[ file:hash.sha512 = '.*' \]",
        "ssdeep": r"\[ file:hash.ssdeep = '.*' \]",
        "Directory": r"\[ directory:path = '.*' \]",
        "Domain": r"\[ domain-name:value = '.*' \]",
        "URL": r"\[ url:value = '.*' \]",
        "Email Address": r"\[ email-addr:value = '.*' \]",
        "MAC Address": r"\[ mac-addr:value = '.*' \]",
        "Windows Registry Key": r"\[ windows-registry-key:key = '.*' \]",
        "User Agent": r"\[ user-agent:string = '.*' \]",
        "AS": r"\[ autonomous-system:number = '.*' \]",
        "BTC": r"\[ cryptocurrency:symbol = 'BTC' AND cryptocurrency:address = '.*' \]",
        "ETH": r"\[ cryptocurrency:symbol = 'ETH' AND cryptocurrency:address = '.*' \]",
        "XMR": r"\[ cryptocurrency:symbol = 'XMR' AND cryptocurrency:address = '.*' \]",
        "Mastercard Credit Card": r"\[ credit-card:provider = 'Mastercard' AND credit-card:number = '.*' \]",
        "VISA Credit Card": r"\[ credit-card:provider = 'VISA' AND credit-card:number = '.*' \]",
        "Amex Credit Card": r"\[ credit-card:provider = 'Amex' AND credit-card:number = '.*' \]",
        "Union Pay Credit Card": r"\[ credit-card:provider = 'Union' AND credit-card:number = '.*' \]",
        "Diners Credit Card": r"\[ credit-card:provider = 'Diners' AND credit-card:number = '.*' \]",
        "JCB Credit Card": r"\[ credit-card:provider = 'JCB' AND credit-card:number = '.*' \]",
        "IBAN": r"\[ iban:number = '.*' \]",
        "CPE": r"\[ software:cpe = '.*' \]"
    }

    sco_objects = []

    for observable_name, observable_regex in observable_regex_map.items():
        if re.search(observable_regex, pattern):
            indicator = Indicator(name=observable_name, pattern_type="stix", pattern=pattern)
            sco_objects = get_sco_objects(indicator)

    if sco_objects == []:
        logger.error("Given pattern is invalid and does not map to any SCO object.")

    for sco_object in sco_objects:
        print(sco_object.serialize(pretty=True))
