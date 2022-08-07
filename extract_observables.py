"""
Contains logic for extracting observables.
"""

import re
from ipaddress import IPv4Interface, IPv6Interface
import validators

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
