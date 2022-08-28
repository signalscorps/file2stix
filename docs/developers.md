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