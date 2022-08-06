import argparse
import json
import re
from ipaddress import IPv4Interface, IPv6Interface
from pathlib import Path
import validators
from stix2 import Indicator, Bundle, Vulnerability, ExternalReference
from stix2.base import STIXJSONEncoder

# Helper regexes

# Suspicious file extensions
file_extensions = "(?:(?:7(?:Z|z))|(?:AP(?:K|P))|(?:B(?:AT|IN|MP))|(?:C(?:LASS|AB|ER|GI|HM|MD|RX))|(?:D(?:OCX?|EB|LL))|EXE|FLV|(?:G(?:ADGET|IF|Z))|INF|(?:J(?:A(?:VA|R)|PG|S))|(?:L(?:NK|OG))|(?:M(?:O(?:F|V)|P(?:4|G)|S(?:G|I)|4V))|ODT|(?:P(?:LUGIN|PTX?|7S|DF|HP|NG|SD|F|Y))|(?:R(?:AR|PM))|(?:S(?:VG|WF|YS|O))|(?:T(?:IFF?|AR|GZ|MP|XT))|(?:V(?:BS|IR))|(?:W(?:MV|SF))|XLSX?|ZIPX?|(?:ap(?:k|p))|(?:b(?:at|in|mp))|(?:c(?:lass|ab|er|gi|hm|md|rx))|(?:d(?:ocx?|eb|ll))|exe|flv|(?:g(?:adget|if|z))|inf|(?:j(?:a(?:va|r)|pg|s))|(?:l(?:nk|og))|(?:m(?:o(?:f|v)|p(?:4|g)|s(?:g|i)|4v))|odt|(?:p(?:lugin|ptx?|7s|df|hp|ng|sd|f|y))|(?:r(?:ar|pm))|(?:s(?:vg|wf|ys|o))|(?:t(?:iff?|ar|gz|mp|xt))|(?:v(?:bs|ir))|(?:w(?:mv|sf))|xlsx?|zipx?)"

# Windows and Unix path
windows_path = r"[A-Z]:(\\\\[^<>:\"/\\|\?\*]+)+"
unix_path = r"(/\S+)+"

# Registry key
registry_key = r"(?:CLSID|(?:HK(?:EY\_(?:CURRENT\_(?:CONFIG|USER)|LOCAL\_MACHINE|USERS)|C(?:C|U)|LM|U))|(?:I(?:nterface|ID))|REGISTRY|TypeLib)"

# User agent
platforms = r"(Gecko)|(Firefox)|(AppleWebKit)|(Chrome)|(Safari)|(OPR)|(Edg)|(Safari)|(Mobile)|(curl)|(PostmanRuntime)"
user_agent_details = r"\([\w;\s\.:-]+\)"
user_agent = rf"(User-Agent:|user-agent:)? Mozilla/5.0(\s((\([\w;\s\.:-]+\)|(({platforms})(/\S+)+))))+"

# Cryptocurrency address
btc_address = r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}"
etc_address = r"0x[a-f0-9]{40}"
xmr_address = r"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}"

# Dictionary mapping observable to regular expression or a custom function
# Note the regexs will be matched with each word in the input
observables_map = {
    "ipv4-addr:value": lambda x: IPv4Interface(x),
    "ipv6-addr:value": lambda x: IPv6Interface(x),
    "file:name": rf"^(.*)\.({file_extensions})$",
    "file:hashes.md5": r"^[a-fA-F0-9]{32}$",
    "file:hashes.sha1": r"^[a-fA-F0-9]{40}$",
    "file:hashes.sha256": r"^[a-fA-F0-9]{64}$",
    "file:hashes.sha512": r"^[a-fA-F0-9]{128}$",
    "file:hashes.ssdeep": r"^\d{1,}:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}$",
    "directory:path": rf"^(({windows_path})|({unix_path}))$",
    "domain-name:value": lambda x: validators.domain(x),
    "url:value": lambda x: validators.url(x),
    "email-addr:value": lambda x: validators.email(x),
    "mac-addr:value": lambda x: validators.mac_address(x),
    "windows-registry-key:key": rf"^({registry_key}(\\\\[^<>:\"/\\|\?\*]+)+)$",
    "network-traffic:extensions.'http-requestext'.request_header.'User-Agent'": rf"{user_agent}",
    "autonomous-system:number": r"^((AS|ASN)\d+)$",
    "artifact:payload_bin": rf"^(({btc_address})|({etc_address})|({xmr_address}))$",
    "cve": r"^(CVE-(19|20)\d{2}-\d{4,7})$",
}


class ExtractPatterns:
    """
    Iterable that extracts all the words in `input` matching a given `pattern`.
    In each iteration, it returns the next matched word.
    """

    def __init__(self, pattern, input):
        self.pattern = pattern
        self.input = input
        self.match_index = 0
        self.matches = []

        # If pattern is a regex, then find all matches to the regular expression
        if isinstance(pattern, str):
            if pattern.startswith("^") and pattern.endswith("$"):
                # Match each word with the regex
                for word in input.split():
                    if re.match(pattern, word):
                        self.matches.append(word)
            else:
                # Find regex in the entire text (including whitespace)
                for match in re.finditer(pattern, input):
                    self.matches.append(match.group())

        # If pattern is a function, then find matches that don't throw exception when
        # `pattern` function runs
        elif callable(pattern):
            for word in input.split():
                try:
                    if pattern(word):
                        self.matches.append(word)
                except:
                    pass

    def __iter__(self):
        return self

    def __next__(self):
        if self.match_index < len(self.matches):
            match = self.matches[self.match_index]
            self.match_index += 1
            return match
        raise StopIteration


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(
        prog="extract_observables",
        usage="%(prog)s <input-text-file>",
        description="Extract observables from input file and store it in a STIX bundle",
    )
    arg_parser.add_argument(
        "Input",
        type=str,
        help="Input text file from which observables will be extracted.",
    )

    # Read input from file
    args = arg_parser.parse_args()
    input_file_path = args.Input
    input = Path(input_file_path).read_text()

    # Iterate over each observable and extract them from input file
    stix_objects = {}
    for observable, pattern in observables_map.items():
        for match in ExtractPatterns(pattern, input):
            if observable == "cve":
                vulnerability = Vulnerability(
                    name=match,
                    external_references=ExternalReference(
                        source_name="cve", external_id=match
                    ),
                )
                stix_objects[match] = vulnerability
            else:
                indicator = Indicator(
                    type="indicator",
                    name=match,
                    pattern_type="stix",
                    pattern=f"[ {observable} = '{match}' ]",
                    indicator_types=["malicious-activity"],
                )
                # Storing in a dictionary to avoid duplicate indicators
                # for the same matching string
                stix_objects[match] = indicator

    # Create a STIX bundle of all the indicators
    BundleOfAllObjects = Bundle(*list(stix_objects.values()), allow_custom=True)
    with open(BundleOfAllObjects.id + ".json", "w") as f:
        f.write(json.dumps(BundleOfAllObjects, cls=STIXJSONEncoder, indent=4))
