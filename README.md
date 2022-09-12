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

* ipv4 (inc. CIDR, port) (`IPv4`, `IPv4WithPort`)
* ipv6 (inc. CIDR, port) (`IPv6`, `IPv6WithPort`)
* File name (`FileName`)
* File hase
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
* Cyptocurrency
	* Bitcoin address (BTC) (`CryptocurrencyBTC`)
	* Ethereum address (ETH) (`CryptocurrencyETH`)
	* Monero address (XMR) (`CryptocurrencyXMR`)
* International Bank Account Number (IBAN) (`IBAN`)
* CVE (`CVE`)
* CPE (`CPE`)
* Credit Card
	* Mastercard (`MastercardCreditCard`)
	* Visa (`VisaCreditCard`)
	* Amex (`AmexCreditCard`)
	* Union Pay (`UnionPayCreditCard`)
	* Diners (`DinersCreditCard`)
	* JCB (`JCBCreditCard`)
* YARA Rule (`YaraRule`)
* SIGMA Rule (`SigmaRule`)
* Countries (`CountryName`, `CountryCode`)
* MITRE ATT&CK
	* Enterprise ATT&CK (`MITREEnterpriseAttack`)
	* Mobile ATT&CK (`MITREMobileAttack`)
	* ICS ATT&CK (`MITREICSAttack`)
* MITRE CAPEC (`MITRECapec`)
* Custom extractions (`Custom`)

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
file2stix --input-file PATH/TO/FILE --custom-extraction-file PATH/TO/FILE --update-mitre-cti-database --cache-folder PATH/TO/DIRECTORY --tlp-level TLP --user-identity-file PATH/TO/FILE --ignore-observable-prefix observable1,observable2 --backend PATH/TO/CONFIG.yml
```

* `--input-file` (required): provides the path to the input file
* `--custom-extraction-file` (optional, no default): provides the path to the file with custom extraction logic
* `--update-mitre-cti-database` (optional, no default): updates the local cache with latest MITRE CTI dataset. To make use of MITRE ATT&CK and MITRE CAPEC extractions you should run this on the first install, and run it again when any updates when ATT&CK or CAPEC versions are updated.
* `--cache-folder` (optional, default `file2stix-cache`): cache folder path where MITRE ATT&K, CAPEC and MISP warning list will be stored. By default MITRE dataset is stored in "file2stix-cache" folder. You can specify a different folder for this using the `--cache-folder` option
* `--tlp-level` (optional, default `WHITE`): the TLP level of report and extracted object. Either `WHITE` or `AMBER`. IMPORTANT, the TLP level defined has an impact on how the objects are stored. Read `docs/conversions.md` for more info.
* `--user-identity-file` (optional, default `stix_templates/identity.yml`): path to user identity config file (in yml format) to assign to objects extracted. Note, the TLP level also has an impact on how identity is assigned.
* `--ignore-observable-prefix` (optional, default none): you pass a list of obeservable types to ignore (e.g. `ipv4,ipv6`). The field matches on value passed against class names in `file2stix/observables.py`, so you can pass many options to this parameter. e.g. you can pass a  "i", " ip", "ipv", "ipv4", "ipv4o", ..., "ipv4observable" (note that these are case insensitive) as parameter. By passing a very short prefix like "ip", this could ignore several observables (in this case, both ipv4 and ipv6 observables). You should check `file2stix/observables.py` for a full list of class names (e.g `class IPv4Observable`).
* `--misp-custom-warning-list-file` (optional, default none): a custom Warning List used to whitelist indicators. Must be in the same format as MISP Warning Lists. An example can be seen here `tests/custom_warning_lists/list.json`
* --backend (optional, default none): Defines wether output should be stored to a supported backend (in addition to file store). Should be path to backend config file, e.g. `tests/backends/arangodb.yml`

You can also run `file2stix --help` to print more about these options in the command line.

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

* [STIX Viewer](https://github.com/traut/stixview): Quickly load bundles produced from your report.