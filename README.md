# Stixify

![](/docs/assets/img/extraction-screenshot.png)

Stixify is your automated threat intelligence analyst.

Use Stixify to extract machine readable intelligence from unstructured reports.

Stixify;

* is much faster than human analysis
* can operate at volume
* saves costs through faster threat analysis and remediation
* is extendable

Analysts still need to review the output from Stixify (probably in a threat intelligence platform), however Stixify removes the tedious part of converting it to STIX 2.1.

A project from the Signals Corps: https://www.signalscorps.com/

## Why use Stixify?

Some example implemenations include:

* Automatically converting IoC feeds to STIX 2.1 Objects
* Extracting MITRE ATT&CK and MITRE CAPEC contect from reports
* Creating STIX 2.1 Bundles from Reports to speed up analysis

## STIX Support

Stixify only supports STIX version 2.1 [as defined by this specification](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html).

## Support

[Ask a question on Slack](https://join.slack.com/t/signalscorps-public/shared_invite/zt-1exnc12ww-9RKR6aMgO57GmHcl156DAA).

## License

[MIT LICENSE](/LICENSE).

## Download and Install

Download

```shell
git clone https://github.com/signalscorps/stixify
cd stixify
```

Setup virtual environment

```shell
python3 -m venv stixify
source stixify/bin/activate
```

Install `stixify` tool

```shell
pip3 install .
```

**NOTE**: If you are a developer, install `stixify` in editable mode.

```shell
pip3 install -e .
```

## Run

To run Stixify;

```shell
stixify --input-file PATH/TO/FILE --custom-extraction-file PATH/TO/FILE --update-mitre-cti-database
```

* `--input-file` (required): provides the path to the input file
* `--custom-extraction-file` (optional): provides the path to the file with custom extraction logic
* `--update-mitre-cti-database` (optional) updates the local cache with latest MITRE CTI dataset. To make use of MITRE ATT&CK and MITRE CAPEC extractions you should run this on the first install, and run it again when any updates when ATT&CK or CAPEC versions are updated.
* `--cache-folder` (optional) cache folder path where MITRE ATT&K, CAPEC and MISP warning list will be stored. By default MITRE dataset is stored in "stixify-cache" folder. You can specify a different folder for this using the `--cache-folder` option

You can also run `stixify --help` to know more about these options.

For example;

```shell
stixify --input-file tests/file_inputs/txt/input.txt
```

Or with a custom extraction file specified;

```shell
stixify --input-file tests/file_inputs/txt/input.txt --custom-extraction-file tests/file_inputs/custom_extractions/extractions.txt
````

When the command executes successfully and matches are detected two directories will be created;

* `stix2_extractions/`
	* STIX Objects for observables detected. These are used for future runs of the script. In the sub-directories you will find STIX 2.1 Bundles containing individual STIX 2.1 Objects extracted.
* `stix2_reports/`
	* Final STIX bundles containing collections of Objects from observables extracted from reports. In the sub-directories you will find STIX 2.1 Bundles containing all STIX 2.1 Objects extracted from a report. Some examples can be seen in the `/tests/expected_reports` directory.

## Inputs

Stixify supports the following filetype inputs:

* Markdown (`.md`, `.markdown`)
	* e.g. `stixify --input-file tests/file_inputs/md/input.md`
	* e.g. `stixify --input-file tests/file_inputs/md/input.markdown`
	* note, markdown can contain HTML. If HTML elements are detected, these are stripped. Only content outside of HTML tags is considered. e.g. `<a href="URL_INSIDE_HTML_TAG">PRINTED_URL</a>`, only `PRINTED_URL` would remain for extraction pattern matching
* Plain text (`.txt`)
	* e.g. `stixify --input-file tests/file_inputs/txt/input.txt`
* CSV (`.csv`)
	* e.g. `stixify --input-file tests/file_inputs/csv/input.csv`
* XML (`.xml`)
	* e.g. `stixify --input-file tests/file_inputs/xml/input.xml`
	* note, all XML tags are stripped. e.g. `<url = "URL_INSIDE_XML_TAG">PRINTED_URL</url>`, only `PRINTED_URL` would remain for extraction pattern matching
* JSON (`.json`)
	* e.g. `stixify --input-file tests/file_inputs/json/input.json`
	* note, only key values are considered. e.g. `{"1.1.1.1": "SOME_IP"}`, only `SOME_IP` would remain.
* PDF (`.pdf`)
	* e.g. `stixify --input-file tests/file_inputs/pdf/input.pdf`
* Microsoft Word (`.doc`, `.docx`)
	* e.g. `stixify --input-file tests/file_inputs/doc/input.docx`
	* e.g. `stixify --input-file tests/file_inputs/doc/input.doc`
		* note, on Mac you will need to install `antiword` to use `.doc` files. Install using `brew install antiword`
* Microsoft Excel (`.xls`, `.xlsx`)
	* e.g. `stixify --input-file tests/file_inputs/xls/input.xlsx`
	* e.g. `stixify --input-file tests/file_inputs/xls/input.xls`

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
* Credit Card (Mastercard, Visa, Amex, Union Pay, Diners, JCB)

#### STIX 2.1 Location SDOs

* Country (Name, Country Code)

#### External STIX 2.1 Objects (various types)

* MITRE ATT&CK (Enterprise ATT&CK, Mobile ATT&CK)
* MITRE CAPEC

### Custom Extractions

You can also write your own custom extractions.

Custom extractions can be written and stored in a plain text file.

Inside this file you must specify an extraction string (case insensitive) and a STIX 2.1 Object to use when the match is detected in the format;

```csv
"EXTRACTION STRING",STIX-OBJECT-TYPE
```

The following STIX 2.1 Objects are supported by custom extractions:

* [Attack Pattern](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070618) (`attack-pattern`)
* [Campaign](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070621) (`campaign`)
* [Course of Action](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070624) (`course-of-action`)
* [Infrastructure](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070636) (`infrastructure`)
* [Intrusion Set](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070639) (`intrustion-set`)
* [Malware](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070645) (`malware`)
* [Threat Actor](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070663) (`threat-actor`)
* [Tool](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070666) (`tool`)

e.g. to search a document for the string "RYUK" and create a Malware STIX 2.1 SDO if a match is identified;

```csv
"ryuk",malware
```

You can also create multiple custom extractions in the same file by adding multiple lines, e.g.

```csv
"ryuk",malware
"darkhotel",malware
"patch",course-of-action
```

You can see an example custom extraction file in `tests/file_inputs/custom_extractions/test_extractions.txt`

### Updating STIX Objects

If the script detects an already extracted observable value present in `stix2_extractions/` then the `modified` time of this object is updated to the new extraction time and the updated object used in the final bundle for the report.

For example, if 1.1.1.1 detected in report 1 it would create a new object (object 1) where `created` and `modified` times were equal. Subsequently if 1.1.1.1 detected in report 2 it would use object 1 in the final bundle, but object 1 would also be updated with new `modifed` time to represent second sighting. The old bundle would remain unchanged. So bundle for report 1 would still have created and modified times equal, but report 2 would have the updated object, and so on.

You will see both copies of the Object still in the `stix2_extractions/` directory.

## Running tests

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