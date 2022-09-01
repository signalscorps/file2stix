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

file2stix --input-file tests/observable_tests/asn.txt
file2stix --input-file tests/observable_tests/country_adjective.txt
file2stix --input-file tests/observable_tests/country_code.txt
file2stix --input-file tests/observable_tests/cpe.txt
file2stix --input-file tests/observable_tests/credit_card.txt
file2stix --input-file tests/observable_tests/directory.txt
file2stix --input-file tests/observable_tests/domain.txt
file2stix --input-file tests/observable_tests/email.txt
file2stix --input-file tests/observable_tests/file.txt
file2stix --input-file tests/observable_tests/file_hash.txt
file2stix --input-file tests/observable_tests/iban.txt
file2stix --input-file tests/observable_tests/ipv4.txt
file2stix --input-file tests/observable_tests/ipv6.txt
file2stix --input-file tests/observable_tests/mitre_attck.txt
file2stix --input-file tests/observable_tests/mitre_capec.txt
file2stix --input-file tests/observable_tests/registry_key.txt
file2stix --input-file tests/observable_tests/sigma_rule.txt
file2stix --input-file tests/observable_tests/url.txt
file2stix --input-file tests/observable_tests/user_agent.txt
file2stix --input-file tests/observable_tests/yara_rule.txt

file2stix --input-file tests/custom_extractions/test_extractions.txt --custom-extraction-file tests/custom_extractions/test_extractions.txt


file2stix --input-file tests/observable_tests/ipv4.txt --user-identity-file stix_templates/identity.yml


file2stix --input-file tests/observable_tests/ipv4.txt --tlp-level AMBER --user-identity-file stix_templates/identity.yml


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

## Testing adding custom identity

### Valid identity

`file2stix --input-file tests/observable_tests/ipv4.txt --user-identity-file tests/stix_templates/custom_identity_good.yml`

### Invalid identity

```
file2stix --input-file tests/observable_tests/ipv4.txt --user-identity-file tests/stix_templates/custom_identity_bad.yml`
```

