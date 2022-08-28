# file2stix

![](/docs/assets/img/extraction-screenshot.png)

file2stix is your automated threat intelligence analyst.

Use file2stix to extract machine readable intelligence in STIX 2.1 format from unstructured reports.

Some example use-cases file2stix solves for include:

* Automatically converting IoC feeds to STIX format
* Identifying observables in webpages to ingest into downstream tools
* Quickly identify MITRE ATT&CK and MITRE CAPEC context from reports
* Extracting detection rules from text (YARA and SIGMA)

Why use file2stix;

* is much faster than human analysis
* can operate at volume
* saves costs through faster threat analysis and remediation
* is extendable

file2stix currently supports the following extraction types:

* ipv4 (inc. CIDR, port)
* ipv6 (inc. CIDR, port)
* File name
* md5 hash
* sha1 hash
* sha256 hash
* sha512 hash
* ssdeep hash
* Directory (Window and UNIX)
* Domain
* URL
* Email Address
* MAC Address
* Windows Registry Key
* User Agent
* Autonomous System Number (ASN)
* Bitcoin address (BTC)
* Ethereum address (ETH)
* Monero address (XMR)
* International Bank Account Number (IBAN)
* CVE
* CPE
* Credit Card (Mastercard, Visa, Amex, Union Pay, Diners, JCB)
* YARA Rule
* SIGMA Rule
* Countries
* MITRE ATT&CK (Enterprise ATT&CK, Mobile ATT&CK, ICS ATT&CK)
* MITRE CAPEC
* Custom extractions

file2stix is not a Threat Intelligence Platform. It is designed to feed Threat Intelligence Platforms. Intelligence Analysts still need to review the output from file2stix because it will often contain false positives. However, file2stix removes the tedious part of data entry from an Intelligence Analysts workload freeing them up to put their skills to work.

file2stix project from the [Signals Corps](https://www.signalscorps.com/). We hope you find it useful.

## Download and Install

Download

```shell
git clone https://github.com/signalscorps/file2stix
cd file2stix
```

Setup virtual environment

```shell
python3 -m venv file2stix_venv
source file2stix_venv/bin/activate
```

Install `file2stix` tool

```shell
pip3 install .
```

**NOTE**: If you are a developer, install `file2stix` in editable mode.

```shell
pip3 install -e .
```

## Run

To run file2stix;

```shell
file2stix --input-file PATH/TO/FILE --custom-extraction-file PATH/TO/FILE --update-mitre-cti-database
```

* `--input-file` (required): provides the path to the input file
* `--custom-extraction-file` (optional): provides the path to the file with custom extraction logic
* `--update-mitre-cti-database` (optional) updates the local cache with latest MITRE CTI dataset. To make use of MITRE ATT&CK and MITRE CAPEC extractions you should run this on the first install, and run it again when any updates when ATT&CK or CAPEC versions are updated.
* `--cache-folder` (optional) cache folder path where MITRE ATT&K, CAPEC and MISP warning list will be stored. By default MITRE dataset is stored in "file2stix-cache" folder. You can specify a different folder for this using the `--cache-folder` option

You can also run `file2stix --help` to know more about these options.

For example;

```shell
file2stix --input-file tests/file_inputs/txt/input.txt
```

Or with a custom extraction file specified;

```shell
file2stix --input-file tests/file_inputs/txt/input.txt --custom-extraction-file tests/file_inputs/custom_extractions/extractions.txt
````

## Documentation

Please take a moment to review the comprehensive documentation included in this repository -- it covers almost all common questions people have about file2stix.

[Read the documentation here](/docs/index.md).

## Support

[Signals Corps are committed to providing best effort support via Slack](https://join.slack.com/t/signalscorps-public/shared_invite/zt-1exnc12ww-9RKR6aMgO57GmHcl156DAA).

If you notice a bug or have a feature request, [please submit them as issues on Github](https://github.com/signalscorps/file2stix/issues).

## License

[MIT LICENSE](/LICENSE).

## Useful supporting tools

* [STIX Viewer](https://github.com/traut/stixview): Quickly load bundles produced from your report : 
* [file2stix](https://www.file2stix.com): Our web implementation of file2stix with lots of additional features.