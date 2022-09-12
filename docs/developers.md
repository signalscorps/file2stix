# Developers

file2stix was built to be extended. This section of the documentation covers information that will be useful to developers.

## Running tests

Ensure that `pytest` is installed:

```shell
pip install pytest
```

Then run `pytest` command in the command line to run all tests:

```shell
pytest
```




file2stix --input-file tests/observable_tests/credit_card.txt
file2stix --input-file tests/observable_tests/directory.txt
file2stix --input-file tests/observable_tests/domain.txt
file2stix --input-file tests/observable_tests/email.txt
file2stix --input-file tests/observable_tests/file.txt
file2stix --input-file tests/observable_tests/file_hash.txt
file2stix --input-file tests/observable_tests/iban.txt
file2stix --input-file tests/observable_tests/ipv4.txt
file2stix --input-file tests/observable_tests/ipv6.txt
file2stix --input-file tests/observable_tests/mitre_capec.txt
file2stix --input-file tests/observable_tests/registry_key.txt
file2stix --input-file tests/observable_tests/sigma_rule.txt
file2stix --input-file tests/observable_tests/url.txt
file2stix --input-file tests/observable_tests/user_agent.txt
file2stix --input-file tests/observable_tests/yara_rule.txt


## Testing obeservable types

### Supported observables

#### ASN

```
file2stix --input-file tests/observable_tests/asn.txt
```

#### Country

```
file2stix --input-file tests/observable_tests/country_adjective.txt
```

```
file2stix --input-file tests/observable_tests/country_code.txt
```

#### CPE

```
file2stix --input-file tests/observable_tests/cpe.txt
```





#### MITRE ATT&CK

##### Shared Matrices

```
file2stix --input-file tests/observable_tests/mitre_attck_all.txt
```

##### Enterprise Matrix

```
file2stix --input-file tests/observable_tests/mitre_attck_enterprise.txt
```

##### ICS Matrix

```
file2stix --input-file tests/observable_tests/mitre_attck_ics.txt
```

##### Mobile Matrix

```
file2stix --input-file tests/observable_tests/mitre_attck_mobile.txt
```


## Testing filetypes

### Supported filetypes

#### .csv

```
file2stix --input-file tests/file_inputs/csv/input.csv
```

#### .doc

```
file2stix --input-file tests/file_inputs/doc/input.doc
```

```
file2stix --input-file tests/file_inputs/doc/input.docxs
```

#### .html

```
file2stix --input-file tests/file_inputs/html/input.html
```

##### Large complex HTML

```
file2stix --input-file tests/file_inputs/html/catapult-spider-adversary-quest-walkthrough-2022.html
```

#### .json

```
file2stix --input-file tests/file_inputs/json/input.json
```

#### .md

```
file2stix --input-file tests/file_inputs/md/input.md
```

#### .pdf

```
file2stix --input-file tests/file_inputs/pdf/input.pdf
```

#### .txt

```
file2stix --input-file tests/file_inputs/txt/input.txt
```

#### .xls

```
file2stix --input-file tests/file_inputs/xls/input.xls
```

```
file2stix --input-file tests/file_inputs/xls/input.xlsx
```

#### .xml

```
file2stix --input-file tests/file_inputs/xml/input.xml
```

#### .yaml

```
file2stix --input-file tests/file_inputs/yara/input.yaml
```

```
file2stix --input-file tests/file_inputs/yara/input.yml
```

#### .yara

```
file2stix --input-file tests/file_inputs/yara/input.yar
```

```
file2stix --input-file tests/file_inputs/yara/input.yara
```

### Unsupported filetypes

#### .py

```
file2stix --input-file setup.py
```

## Testing custom extractions

```
file2stix --input-file tests/custom_extractions/test_extractions.txt --custom-extraction-file tests/custom_extractions/test_extractions.txt
```

## Testing Warning Lists

```
file2stix --input-file tests/file_inputs/txt/input.txt --misp-custom-warning-list-file tests/custom_warning_lists/list.json
```

## Testing TLPs

### TLP:WHITE

```
file2stix --input-file tests/observable_tests/ipv4.txt --tlp-level WHITE
```

**Expected output:**

All report and relationship objects have property:

```
"object_marking_refs": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
```

On every new run of same report input, the `modified` property of previously extracted objects is updated and the bundle includes the newly modified object.

### TLP:GREEN

```
file2stix --input-file tests/observable_tests/ipv4.txt --tlp-level GREEN
```

**Expected output:**

All objects have property:

```
"object_marking_refs": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
```

On every new run of same report input, new objects are always created.

### TLP:AMBER

```
file2stix --input-file tests/observable_tests/ipv4.txt --tlp-level AMBER
```

**Expected output:**

All objects have property:

```
"object_marking_refs": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
```

On every new run of same report input, new objects are always created.

### TLP:RED

```
file2stix --input-file tests/observable_tests/ipv4.txt --tlp-level RED
```

**Expected output:**

All objects have property:

```
"object_marking_refs": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
```

On every new run of same report input, new objects are always created.

### TLP:BAD

```
file2stix --input-file tests/observable_tests/ipv4.txt --tlp-level BAD
```

**Expected output:**

Error message: Invalid choice

## Testing ignore observable

### Ignore IPv4

```
file2stix --input-file tests/observable_tests/ipv4.txt --ignore-observable-prefix ipv4
```

**Expected output:**

Warning message: no observables extracted

### Ignore IPv4 and Url

```
file2stix --input-file tests/file_inputs/txt/input.txt --ignore-observable-prefix \
IPv4Observable,IPv4WithPortObservable,\
IPv6Observable,IPv6WithPortObservable,\
FileNameObservable,FileHashMD5Observable,\
FileHashSHA1Observable,\
FileHashSHA256Observable,\
FileHashSHA512Observable,\
FileHashSsDeepObservable,\
DirectoryPathObservable,\
DomainNameObservable,\
UrlObservable,\
EmailAddressObservable,\
MacAddressObservable,\
WindowsRegistryKeyObservable,\
UserAgentObservable,\
AutonomousSystemNumberObservable,\
CryptocurrencyBTCObservable,\
CryptocurrencyETHObservable,\
CryptocurrencyXMRObservable,\
CountryNameObservable,\
CountryCodeAlpha2Observable,\
CountryCodeAlpha3Observable,\
MastercardCreditCardObservable,\
VisaCreditCardObservable,\
AmexCreditCardObservable,\
UnionPayCreditCardObservable,\
DinersCreditCardObservable,\
JCBCreditCardObservable,\
IBANCodeObservable,\
YaraRuleObservable,\
CPEObservable,\
CVEObservable,\
MITREEnterpriseAttackObservable,\
MITREMobileAttackObservable,\
MITREICSAttackObservable,\
MITRECapecObservable,\
CustomObservable
```




* ipv4 (inc. CIDR, port) (`IPv4`, `IPv4WithPort`)
* ipv6 (inc. CIDR, port) (`IPv6`, `IPv6WithPort`)
* File name (`FileName`)
* md5 hash (`FileHashMD5`)
* sha1 hash (`FileHashSHA1`)
* sha256 hash (`FileHashSHA256`)
* sha512 hash (`FileHashSHA512`)
* ssdeep hash (`FileHashSsDeep`)
* Directory (Window and UNIX) (`DirectoryPath`)
* Domain (`DomainName`)
* URL (`Url`)
* Email Address (`EmailAddress`)
* MAC Address (`MacAddress`)
* Windows Registry Key (`WindowsRegistryKey`)
* User Agent (`UserAgent`)
* Autonomous System Number (ASN) (`AutonomousSystemNumber`)
* Bitcoin address (BTC) (`CryptocurrencyBTC`)
* Ethereum address (ETH) (`CryptocurrencyETH`)
* Monero address (XMR) (`CryptocurrencyXMR`)
* International Bank Account Number (IBAN) (`IBAN`)
* CVE (`CVE`)
* CPE (`CPE`)
* Credit Card (Mastercard, Visa, Amex, Union Pay, Diners, JCB) (`MastercardCreditCard`,`VisaCreditCard`,`AmexCreditCard`, `UnionPayCreditCard`, `DinersCreditCard`, `JCBCreditCard`)
* YARA Rule (`YaraRule`)
* SIGMA Rule (`SigmaRule`)
* Countries (`CountryName`, `CountryCode`)
* MITRE ATT&CK (Enterprise ATT&CK, Mobile ATT&CK, ICS ATT&CK) (`MITREEnterpriseAttack`, `MITREMobileAttack`, `MITREICSAttack`)
* MITRE CAPEC (`MITRECapec`)
* Custom extractions (`Custom`)


## Testing adding custom identity

### Valid identity

`file2stix --input-file tests/observable_tests/ipv4.txt --user-identity-file tests/stix_templates/custom_identity_good.yml`

### Invalid identity

```
file2stix --input-file tests/observable_tests/ipv4.txt --user-identity-file tests/stix_templates/custom_identity_bad.yml`
```

## Testing backends




