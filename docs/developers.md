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

---

## Testing obeservable types

### Supported observables

#### ASN

```shell
file2stix --input-file tests/observable_tests/asn.txt
```

```shell
file2stix --input-file tests/observable_tests/asn.txt
```

#### Country

```shell
file2stix --input-file tests/observable_tests/country_adjective.txt
```

```shell
file2stix --input-file tests/observable_tests/country_code.txt
```

#### CPE

```shell
file2stix --input-file tests/observable_tests/cpe.txt
```

#### Cyptocurrency

##### BTC

```shell
file2stix --input-file tests/observable_tests/crypto_btc.txt
```

##### ETH

```shell
file2stix --input-file tests/observable_tests/crypto_eth.txt
```

##### XMR

```shell
file2stix --input-file tests/observable_tests/crypto_xmr.txt
```

##### IPv6

```shell
file2stix --input-file tests/observable_tests/ipv6.txt
```

#### Credit Card

##### Amex

```shell
file2stix --input-file tests/observable_tests/credit_card_amex.txt
```

##### Mastercard

```shell
file2stix --input-file tests/observable_tests/credit_card_mastercard.txt
```

##### Visa

```shell
file2stix --input-file tests/observable_tests/credit_card_visa.txt
```

##### Discover

```shell
file2stix --input-file tests/observable_tests/credit_card_discover.txt
```

##### Diners

```shell
file2stix --input-file tests/observable_tests/diners.txt
```

##### Union Pay

```shell
file2stix --input-file tests/observable_tests/credit_card_union_pay.txt
```

##### JCB

```shell
file2stix --input-file tests/observable_tests/credit_card_jcb.txt
```

#### Directory

```shell
file2stix --input-file tests/observable_tests/directory.txt
```

#### Domain / sub-domain

##### Domain

```shell
file2stix --input-file tests/observable_tests/domain.txt
```

##### Subdomain

```shell
file2stix --input-file tests/observable_tests/domain_sub.txt
```

#### Email

```shell
file2stix --input-file tests/observable_tests/email.txt
```

#### Filehash

##### md5

```shell
file2stix --input-file tests/observable_tests/file_hash_md5.txt
```

##### sha1

```shell
file2stix --input-file tests/observable_tests/file_hash_sha1.txt
```

##### sha256

```shell
file2stix --input-file tests/observable_tests/file_hash_sha256.txt
```

##### sha512

```shell
file2stix --input-file tests/observable_tests/file_hash_sha512.txt
```

##### ssdeep

```shell
file2stix --input-file tests/observable_tests/file_hash_ssdeep.txt
```

#### File 

```shell
file2stix --input-file tests/observable_tests/file.txt
```

#### IBAN

```shell
file2stix --input-file tests/observable_tests/iban.txt
```

#### IPv4

##### IPv4

```shell
file2stix --input-file tests/observable_tests/ipv4.txt
```

```shell
file2stix --input-file tests/observable_tests/ipv4-multi.txt
```


##### IPv4 with port

```shell
file2stix --input-file tests/observable_tests/ipv4_port.txt
```

##### IPv4 with CIDR

```shell
file2stix --input-file tests/observable_tests/ipv4_cidr.txt
```

#### IPv6

##### IPv6

```shell
file2stix --input-file tests/observable_tests/ipv6.txt
```

##### IPv6 with port

```shell
file2stix --input-file tests/observable_tests/ipv6_port.txt
```

##### IPv6 with CIDR

```shell
file2stix --input-file tests/observable_tests/ipv6_cidr.txt
```

#### MITRE ATT&CK

##### Shared Matrices

```shell
file2stix --input-file tests/observable_tests/mitre_attck_all.txt --update-mitre-cti-database
```

##### Enterprise Matrix

```shell
file2stix --input-file tests/observable_tests/mitre_attck_enterprise.txt --update-mitre-cti-database
```

##### ICS Matrix

```shell
file2stix --input-file tests/observable_tests/mitre_attck_ics.txt --update-mitre-cti-database
```

##### Mobile Matrix

```shell
file2stix --input-file tests/observable_tests/mitre_attck_mobile.txt --update-mitre-cti-database
```

#### MITRE CAPEC

```shell
file2stix --input-file tests/observable_tests/mitre_capec.txt --update-mitre-cti-database
```

#### Windows Registry Key

```shell
file2stix --input-file tests/observable_tests/registry_key.txt
```

#### Sigma Rule

```shell
file2stix --input-file tests/observable_tests/sigma_rule.txt
```

#### URL

```shell
file2stix --input-file tests/observable_tests/url.txt
```

#### User Agent

```shell
file2stix --input-file tests/observable_tests/user_agent.txt
```

#### YARA Rule

```shell
file2stix --input-file tests/observable_tests/yara_rule.txt
```

---

## Testing custom extractions

```shell
file2stix --input-file tests/custom_extractions/test_extractions.txt --custom-extraction-file tests/custom_extractions/test_extractions.txt
```


### Extracting explicit ATT&CK Objects

```shell
file2stix --input-file tests/custom_extractions/extract_as_attack_capec_objects.txt --custom-extraction-file tests/custom_extractions/extract_as_attack_capec_objects.txt
```
---

## Testing branding

```shell
file2stix --input-file tests/observable_tests/ipv4.txt
```

---

## Test import of custom extension-definition objects

### Crypto SCO

### Crypto SDO


---

## Testing filetypes

### Supported filetypes

#### .csv

```shell
file2stix --input-file tests/file_inputs/csv/input.csv
```

#### .doc

```shell
file2stix --input-file tests/file_inputs/doc/input.doc
```

```shell
file2stix --input-file tests/file_inputs/doc/input.docxs
```

#### .html

```shell
file2stix --input-file tests/file_inputs/html/input.html
```

##### Large complex HTML

```shell
file2stix --input-file tests/file_inputs/html/catapult-spider-adversary-quest-walkthrough-2022.html
```

#### .json

```shell
file2stix --input-file tests/file_inputs/json/input.json
```

#### .md

```shell
file2stix --input-file tests/file_inputs/md/input.md
```

#### .pdf

```shell
file2stix --input-file tests/file_inputs/pdf/input.pdf
```

#### .txt

```shell
file2stix --input-file tests/file_inputs/txt/input.txt
```

#### .xls

```shell
file2stix --input-file tests/file_inputs/xls/input.xls
```

```shell
file2stix --input-file tests/file_inputs/xls/input.xlsx
```

#### .xml

```shell
file2stix --input-file tests/file_inputs/xml/input.xml
```

#### .yaml

```shell
file2stix --input-file tests/file_inputs/yaml/input.yaml
```

```shell
file2stix --input-file tests/file_inputs/yaml/input.yml
```

#### .yara

```shell
file2stix --input-file tests/file_inputs/yara/input.yar
```

```shell
file2stix --input-file tests/file_inputs/yara/input.yara
```

### Unsupported filetypes

#### .py

```shell
file2stix --input-file setup.py
```

---

## Testing defanging of data

```shell
file2stix --input-file tests/file_inputs/fanged_data/fanged_data.txt --defang-observables
```

---

## Testing Warning Lists

### Default Warning List

```shell
file2stix --input-file tests/warning_lists/known_matches.txt
```

### Custom Warning List

```shell
file2stix --input-file tests/warning_lists/custom_list.json --misp-custom-warning-list-file tests/warning_lists/custom_list.json --tlp-level GREEN
```

```shell
file2stix --input-file tests/warning_lists/custom_list_matches.txt --misp-custom-warning-list-file tests/warning_lists/custom_list.json --tlp-level GREEN
```

### Ignore warning list match extractions

```shell
file2stix --input-file tests/warning_lists/known_matches.txt --ignore-warninglist-observables
```



---

## Testing script modes

### Sighting Mode

Single extraction (sighting)

```shell
file2stix --input-file tests/observable_tests/crypto_btc.txt --extraction-mode sighting
```

Multiple extractions (sightings)

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --extraction-mode sighting
```

### Analysis Mode

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --extraction-mode analysis
```

_Should be the same output as `file2stix --input-file tests/observable_tests/ipv4.txt`_


---

## Testing processed file

```shell
file2stix --input-file tests/file_inputs/html/catapult-spider-adversary-quest-walkthrough-2022.html --output-processed-input-file
```


---

## Testing TLPs

### TLP:WHITE

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --tlp-level WHITE
```

**Expected output:**

All report and relationship objects have property:

```
"object_marking_refs": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
```

On every new run of same report input, the `modified` property of previously extracted objects is updated and the bundle includes the newly modified object.

### TLP:GREEN

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --tlp-level GREEN
```

**Expected output:**

All objects have property:

```
"object_marking_refs": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
```

On every new run of same report input, new objects are always created.

### TLP:AMBER

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --tlp-level AMBER
```

**Expected output:**

All objects have property:

```
"object_marking_refs": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
```

On every new run of same report input, new objects are always created.

### TLP:RED

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --tlp-level RED
```

**Expected output:**

All objects have property:

```
"object_marking_refs": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
```

On every new run of same report input, new objects are always created.

### TLP:BAD

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --tlp-level BAD
```

**Expected output:**

Error message: Invalid choice

## Testing ignore observable

### Ignore IPv4

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --ignore-observable-prefix ipv4
```

**Expected output:**

Warning message: no observables extracted

### Ignore IPv4 and Url

```shell
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

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --user-identity-file tests/stix_templates/custom_identity_good.yml --tlp-level GREEN
```

## Testing backends

### Valid arangodb backend

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --backend tests/backends/arangodb.yml
```

---

## Testing alternative bundle directory

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --output-json-file stix2_bundles_alt
```

---

## Testing confidence

### TLP Green

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --tlp-level GREEN --confidence 100
```

### TLP Amber

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --tlp-level AMBER --confidence 100
```

### TLP Red

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --tlp-level RED --confidence 100
```

### TLP White Warning

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --confidence 100
```

_Should process the file, but throw a warning that it won't include confidence scores in CLI_

---

## Testing custom defintions for SCOs

### Cryptocurrency SCO

```shell
file2stix --input-file tests/observable_tests/crypto_btc.txt
```

### Credit Card SCO

```shell
file2stix --input-file tests/observable_tests/credit_card_mastercard.txt
```

### ASN SCO

```shell
file2stix --input-file tests/observable_tests/asn.txt
```

### IBAN SCO

```shell
file2stix --input-file tests/observable_tests/iban.txt
```

### User Agent SCO

```shell
file2stix --input-file tests/observable_tests/user_agent.txt
```

---

## Testing custom defintions for SDOs

MISP Warning Lists Properties


Sigma Rule Properties


MISP Warning Lists Properties


