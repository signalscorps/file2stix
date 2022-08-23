# Stixify

Stixify is your automated threat intelligence analyst.

Use Stixify to extract machine readable intelligence from unstructured data.

A project from the Signals Corps: https://www.signalscorps.com/ 

## Download and Install

Download

```shell
git clone https://github.com/signalscorps/stixify
cd stixify
```

Setup virtual environment

```shell
python -m venv stixify
source stixify/bin/activate
```

Install `obstracts-cli` tool

```shell
pip install .
```

**NOTE**: If you are a developer, install `obstracts-cli` in editable mode.

```shell
pip install -e .
```

To make use of MITRE ATT&CK and MITRE CAPEC extractions you also need to import the latest version of the databases

```shell
obstracts-cli --update-mitre-cti-database
```

You can run this command at any time to update these records (e.g. in the case of a new version of ATT&CK being published)

Run program

```shell
obstracts-cli --input-file tests/file_inputs/txt/input.txt
```

Creates two directories;

* `stix2_extractions/`
	* STIX Objects for observables detected. These are used for future runs of the script. In the sub-directories you will find STIX 2.1 Bundles containing individual STIX 2.1 Objects extracted.
* `stix2_reports/`
	* Final STIX bundles containing collections of Objects from observables extracted from reports. In the sub-directories you will find STIX 2.1 Bundles containing all STIX 2.1 Objects extracted from a report. Some examples can be seen in the `/tests/expected_reports` directory.

## Inputs

Stixify supports the following filetype inputs:

* Markdown (`.md`, `.markdown`)
* Plain text (`.txt`)
* CSV (`.csv`)
* XML (`.xml`)
* JSON (`.json`)
* PDF (`.pdf`)
* Microsoft Word (`.doc`, `.docx`)
* Microsoft Excel (`.xls`, `.xlsx`)


## Extractions

### Default Extractions

Stixify ships with the following automatic Observable extraction types:

#### STIX 2.1 Indicator SDOs

* ipv4 (inc. with CIDR and port)
* ipv6 (inc. with CIDR and port)
* File name
* md5
* sha1
* sha256
* sha512
* ssdeep
* Directory (Window and UNI)
* Domain
* URL
* Email Address
* MAC Address
* Windows Registry Key
* User Agent
* ASN
* BTC (Crypto)
* ETH (Crypto)
* XMR (Crypto)
* CVE
* IBAN
* YARA Rule

#### STIX 2.1 Location SDOs

* Country (Name, Country Code)
* Credit Card (Mastercard, Visa, Amex, Union Pay, Diners, JCB)

#### External STIX 2.1 Objects (various types)

* MITRE ATT&CK (Enterprise ATT&CK, Mobile ATT&CK)
* MITRE CAPEC

### Custom Extractions

You can also write your own custom extractions. To create these you must specify an extraction string (case insensitive) and a STIX 2.1 Object to use when the match is detected in the format;

```csv
"EXTRACTION STRING",STIX-OBJECT-TYPE
```

For example, to extract the 

```csv
"RYUK",malware
```

Would search document inputs for the strong "RYUK". If a match is identified, a STIX 2.1 Malware Object would be created.

### Updating STIX Objects

If the script detects an already extracted observable value present in `stix2_extractions/` then the `modified` time of this object is updated to the new extraction time and the updated object used in the final bundle for the report.

For example, if 1.1.1.1 detected in report 1 it would create a new object (object 1) where `created` and `modified` times were equal. Subsequently if 1.1.1.1 detected in report 2 it would use object 1 in the final bundle, but object 1 would also be updated with new `modifed` time to represent second sighting. The old bundle would remain unchanged. So bundle for report 1 would still have created and modified times equal, but report 2 would have the updated object, and so on.

## Whitelisting

Stixify used MISP Warning Lists to identify potential extractions that should be whitelisted.

More info here

### Running tests

Ensure that `pytest` is installed:

```shell
pip install pytest
```

Then run `pytest` command in the command line to run all tests:

```shell
pytest
```

## Viewer

Need a graphical STIX Bundle Viewer? Load bundles produced for your report using STIX View: https://github.com/traut/stixview

## Obstracts Web

Need more? Check out: https://www.obstracts.com/

## License

[LICENSE](/LICENSE)

## Support

Ask a question on Slack: https://join.slack.com/t/signalscorps-public/shared_invite/zt-1exnc12ww-9RKR6aMgO57GmHcl156DAA