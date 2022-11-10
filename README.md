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
git clone --recurse-submodules https://github.com/signalscorps/file2stix
cd file2stix
```

Setup virtual environment

```shell
python3 -m venv file2stix_venv
source file2stix_venv/bin/activate
```

Install `file2stix` tool;

```shell
pip3 install .
```

**NOTE**: If you are a developer, install `file2stix` in editable mode.

```shell
pip3 install -e .
```

And finally, install the required git sub-modules ([stix2-objects](https://github.com/signalscorps/stix2-objects) and [pattern2sco](https://github.com/signalscorps/pattern2sco));

```shell
git submodule init
git submodule update
```

Mac users;

On Mac you will need to install `antiword` to use `.doc` files. Install using

```shell
brew install antiword
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
* `--user-identity-file` (optional, default Signals Corps): path to user identity config file (in yml format) to assign to objects extracted. Note, the TLP level also has an impact on how identity is assigned.
* `--ignore-observable-prefix` (optional, default none): you pass a list of obeservable types to ignore (e.g. `ipv4,ipv6`). The field matches on value passed against class names in `file2stix/observables.py`, so you can pass many options to this parameter. e.g. you can pass a  "i", " ip", "ipv", "ipv4", "ipv4o", ..., "ipv4observable" (note that these are case insensitive) as parameter. By passing a very short prefix like "ip", this could ignore several observables (in this case, both ipv4 and ipv6 observables). You should check `file2stix/observables.py` for a full list of class names (e.g `class IPv4Observable`).
* `--misp-custom-warning-list-file` (optional, default none): a custom Warning List used to whitelist indicators. Must be in the same format as MISP Warning Lists. An example can be seen here `tests/custom_warning_lists/list.json`. Only available for Reports marked `TLP GREEN`, `TLP AMBER`, or `TLP RED`
* `--defang-observables` (optional, default not used): If any 'fanged' Observables are detected, these will be defanged before extraction to ensure they are detected correctly as Observables (e.g. `1[.]1[.]1[.]1` defanged becomes `1.1.1.1`) when this flag is used
* `--backend` (optional, default none): Defines whether output should be stored to a supported backend (in addition to file store). Should be path to backend config file, e.g. `tests/backends/arangodb.yml`
* `--no-branding` (optional, default not used): file2stix prints an `external_references` in each object it creates. By passing this flag, this reference will be removed.
* `--confidence` (optional, default none): you can assign a static confidence score to all Indicator SDOs extracted from a report. This value must be within the range >= 0 <= 100.
* `--ignore-warninglist-observables` (optional, default false): file2stix will keep any extracted objects that match to default and custom warning lists (and marks them as matching and benign). If you would like to ignore any extractions that match to warning lists (and not create STIX Objects from them) then set this to true.
* `--extraction-mode` (optional, default analysis): please read the docs for more information about modes. You can set either `analysis` (the default), `observed` or `sighting`
* `--output-processed-input-file` (optional, default false): this is useful for debugging extractions. It will show you the actual text considered for text extraction (because file2stix performs some preprocessing on files, see docs)
* `--output-json-file` (optional, default stix2bundles): this is where the bundles for each report will be stored. By default is `$FILE2STIX/stix2bundles` but can be changed by specifying a directory path for this flag.
* `--fail-on-errors` (optional, default false): By default file2stix will continue when non-critical errors (e.g. failed extraction) occurs and log errors runtime errors in the `logs/` directory. If set to `true`, the script will completely fail if any errors observed.
* `--help` (optional, default false) to print more about these options in the command line.

For example;

```shell
file2stix --input-file tests/file_inputs/txt/input.txt
```

Or with a custom extraction file specified;

```shell
file2stix --input-file tests/file_inputs/txt/input.txt --custom-extraction-file tests/file_inputs/custom_extractions/extractions.txt
````

To run script for convert data from reports to ArangoDB, you should add in `arangodb.yml` file your config values and run the script:

```shell
file2stix --input-file tests/observable_tests/asn.txt --update-mitre-cti-database --backend backends/arangodb/arangodb.yml
```

## Documentation

Please take a moment to review the comprehensive documentation included in this repository -- it covers almost all common questions people have about file2stix.

[Read the documentation here](https://signalscorps.github.io/file2stix/).

## Support

[Signals Corps are committed to providing best effort support via Slack](https://join.slack.com/t/signalscorps-public/shared_invite/zt-1exnc12ww-9RKR6aMgO57GmHcl156DAA).

If you notice a bug or have a feature request, [please submit them as issues on Github](https://github.com/signalscorps/file2stix/issues).

## License

[MIT LICENSE](/LICENSE).

## A special thanks to...

I would like to thank the authors of the following tools used to build file2stix (making it a hundred times easier);

* [STIX 2](https://pypi.org/project/stix2/): APIs for serializing and de-serializing STIX2 JSON content
* [STIX 2 Pattern Validator](https://pypi.org/project/stix2-patterns/): a tool for checking the syntax of the Cyber Threat Intelligence (CTI) STIX Pattern expressions
* [MISP Warning Lists](https://github.com/MISP/misp-warninglists): Warning lists to inform users of MISP about potential false-positives or other information in indicators
* [STIX Viewer](https://github.com/traut/stixview): Quickly load bundles produced from your report.