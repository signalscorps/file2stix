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

Expected:

* Indicator SDO
* ASN SCO
* R

#### Country

```shell
file2stix --input-file tests/observable_tests/country_adjective.txt
```

```shell
file2stix --input-file tests/observable_tests/country_code.txt
```

#### CVE

```shell
file2stix --input-file tests/observable_tests/cve.txt
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

#### MAC Address

```shell
file2stix --input-file tests/observable_tests/mac_address.txt
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
file2stix --input-file tests/file_inputs/doc/input.docx
```

```shell
file2stix --input-file tests/file_inputs/doc/ipv4.docx
```

#### .html

```shell
file2stix --input-file tests/file_inputs/html/input.html
```

##### Large complex HTML

```shell
file2stix --input-file tests/file_inputs/html/catapult-spider-adversary-quest-walkthrough-2022.html
```

```shell
file2stix --input-file tests/file_inputs/html/OriginLogger-A-Look-at-Agent-Teslas-Successor.html
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

Large complex PDFs

```shell
file2stix --input-file tests/file_inputs/pdf/rpt_APT37.pdf
```

```shell
file2stix --input-file tests/file_inputs/pdf/FireEye-APT39.pdf
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

```shell
file2stix --input-file tests/file_inputs/fanged_data/fanged_data.txt
```

---

## Testing Warning Lists

#### Default Warning List - String

```shell
file2stix --input-file tests/warning_lists/default_list_matches-string.txt
```

#### Default Warning List - Sub-string

```shell
file2stix --input-file tests/warning_lists/default_list_matches-substring.txt
```

#### Default Warning List - Hostname

```shell
file2stix --input-file tests/warning_lists/default_list_matches-hostname.txt
```

#### Default Warning List - CIDR

```shell
file2stix --input-file tests/warning_lists/default_list_matches-cidr.txt
```

### Custom Warning List

```shell
file2stix --input-file tests/warning_lists/custom_list_matches.txt --misp-custom-warning-list-file tests/warning_lists/custom_list.json --tlp-level GREEN
```




### Ignore default warning list match extractions

```shell
file2stix --input-file tests/warning_lists/default_list_matches-substring.txt --ignore-warninglist-observables
```

### Ignore custom warning list match extractions

```shell
file2stix --input-file tests/warning_lists/custom_list_matches.txt --misp-custom-warning-list-file tests/warning_lists/custom_list.json --tlp-level GREEN --ignore-warninglist-observables
```

---

## Testing script modes

### Analysis Mode

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --extraction-mode analysis
```

_Should be the same output as `file2stix --input-file tests/observable_tests/ipv4.txt`_

### Observed Mode

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --extraction-mode observed
```

### Sighting Mode

Single extraction (sighting)

```shell
file2stix --input-file tests/observable_tests/crypto_btc.txt --extraction-mode sighting
```

Multiple extractions (sightings)

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --extraction-mode sighting
```






---

## Testing processed file

```shell
file2stix --input-file tests/file_inputs/html/catapult-spider-adversary-quest-walkthrough-2022.html --output-processed-input-file output.txt
```

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --output-processed-input-file ipv4-output.txt
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

## Testing reuse of STIX Object

The following test use the same single observble in `test_a.txt` (`198.51.100.3`)

The following commands should all create a different `id` property for the Indicator Observable `198.51.100.3`

#### 1.0

```shell
file2stix --input-file tests/extraction_tests/test_a.txt --tlp-level GREEN
````

#### 1.1

```shell
file2stix --input-file tests/extraction_tests/test_a.txt --confidence 100 --user-identity-file tests/stix_templates/custom_identity_good.yml --tlp-level GREEN --no-branding --defang-observables --misp-custom-warning-list-file tests/warning_lists/custom_list.json
```

* New indicator SDO
* New ipv4 SCO

#### 1.2

Change confidence

```shell
file2stix --input-file tests/extraction_tests/test_a.txt --confidence 90 --user-identity-file tests/stix_templates/custom_identity_good.yml --tlp-level GREEN --no-branding --defang-observables --misp-custom-warning-list-file tests/warning_lists/custom_list.json
```

* New indicator SDO
* Same ipv4 SCO as 1.1

#### 1.3

Change user identity

```shell
file2stix --input-file tests/extraction_tests/test_a.txt --confidence 100 --user-identity-file tests/stix_templates/custom_identity_good2.yml --tlp-level GREEN --no-branding --defang-observables --misp-custom-warning-list-file tests/warning_lists/custom_list.json
```

* New indicator SDO
* Same ipv4 SCO as 1.1

#### 1.4

Change TLP

```shell
file2stix --input-file tests/extraction_tests/test_a.txt --confidence 100 --user-identity-file tests/stix_templates/custom_identity_good.yml --tlp-level AMBER --no-branding --defang-observables --misp-custom-warning-list-file tests/warning_lists/custom_list.json
```

* New indicator SDO
* New ipv4 SCO

#### 1.5

Change branding

```shell
file2stix --input-file tests/extraction_tests/test_a.txt --confidence 90 --user-identity-file tests/stix_templates/custom_identity_good.yml --tlp-level GREEN --defang-observables --misp-custom-warning-list-file tests/warning_lists/custom_list.json
```

* New indicator SDO
* Same ipv4 SCO as 1.1

#### 1.6

Change defang

```shell
file2stix --input-file tests/extraction_tests/test_a.txt --confidence 100 --user-identity-file tests/stix_templates/custom_identity_good.yml --tlp-level GREEN --no-branding --misp-custom-warning-list-file tests/warning_lists/custom_list.json
```

* New indicator SDO
* New ipv4 SCO

```shell
file2stix --input-file tests/extraction_tests/test_b.txt --confidence 100 --user-identity-file tests/stix_templates/custom_identity_good.yml --tlp-level GREEN --no-branding --defang-observables --misp-custom-warning-list-file tests/warning_lists/custom_list.json
```

* Same indicator SDO (1.6)
* Same ipv4 SCO (1.6)

#### 1.7

Change MISP Warning List

```shell
file2stix --input-file tests/extraction_tests/test_a.txt --confidence 100 --user-identity-file tests/stix_templates/custom_identity_good.yml --tlp-level GREEN --no-branding
```

* New indicator SDO
* Same ipv4 SCO as 1.1

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

### CPE Properties (Software SCO)

```shell
file2stix --input-file tests/observable_tests/cpe.txt
```

---

## Testing custom defintions for SDOs

### MISP Warning Lists Properties (Indicator SDO)

```shell
file2stix --input-file tests/warning_lists/default_list_matches-string.txt
```

```shell
file2stix --input-file tests/warning_lists/custom_list_matches.txt --misp-custom-warning-list-file tests/warning_lists/custom_list.json --tlp-level GREEN
```

### Sigma Rule Properties (Indicator SDO)

```shell
file2stix --input-file tests/observable_tests/sigma_rule.txt
```

### CVE Properties (Vulnerability SCO)

```shell
file2stix --input-file tests/observable_tests/cve.txt
```






