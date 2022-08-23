# Stixify

Stixify is your automated threat intelligence analyst.

Use Stixify to extract machine readable intelligence from unstructured data.

![](/docs/extraction-screenshot.png)

A project from the Signals Corps: https://www.signalscorps.com/

## Support

Ask a question on Slack: https://join.slack.com/t/signalscorps-public/shared_invite/zt-1exnc12ww-9RKR6aMgO57GmHcl156DAA

## License

[LICENSE](/LICENSE)

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

To make use of MITRE ATT&CK and MITRE CAPEC extractions you also need to import the latest version of the databases on install;

```shell
obstracts-cli --update-mitre-cti-database
```

## Run

To run Stixify;

```shell
obstracts-cli --input-file PATH/TO/FILE --custom-extraction-file PATH/TO/FILE --update-mitre-cti-database
```

* `--input-file` (required): provides the path to the input file
* `--custom-extraction-file` (optional): provides the path to the file with custom extraction logic
* `--update-mitre-cti-database` (optional) updates the local cache with latest MITRE CTI dataset

You can also run `obstracts-cli --help` to know more about these options.

For example;

```shell
obstracts-cli --input-file tests/file_inputs/txt/input.txt
```

Or with a custom extraction file specified;

```shell
obstracts-cli --input-file tests/file_inputs/txt/input.txt --custom-extraction-file tests/file_inputs/custom_extractions/extractions.txt
````

When the command executes successfully and matches are detected two directories will be created;

* `stix2_extractions/`
	* STIX Objects for observables detected. These are used for future runs of the script. In the sub-directories you will find STIX 2.1 Bundles containing individual STIX 2.1 Objects extracted.
* `stix2_reports/`
	* Final STIX bundles containing collections of Objects from observables extracted from reports. In the sub-directories you will find STIX 2.1 Bundles containing all STIX 2.1 Objects extracted from a report. Some examples can be seen in the `/tests/expected_reports` directory.

## Inputs

Stixify supports the following filetype inputs:

* Markdown (`.md`, `.markdown`)
	* e.g. `obstracts-cli --input-file tests/file_inputs/md/input.md`
	* e.g. `obstracts-cli --input-file tests/file_inputs/md/input.markdown`
* Plain text (`.txt`)
	* e.g. `obstracts-cli --input-file tests/file_inputs/txt/input.txt`
* CSV (`.csv`)
	* e.g. `obstracts-cli --input-file tests/file_inputs/csv/input.csv`
* XML (`.xml`)
	* e.g. `obstracts-cli --input-file tests/file_inputs/xml/input.xml`
* JSON (`.json`)
	* e.g. `obstracts-cli --input-file tests/file_inputs/json/input.json`
* PDF (`.pdf`)
	* e.g. `obstracts-cli --input-file tests/file_inputs/pdf/input.pdf`
* Microsoft Word (`.doc`, `.docx`)
	* e.g. `obstracts-cli --input-file tests/file_inputs/doc/input.docx`
	* e.g. `obstracts-cli --input-file tests/file_inputs/doc/input.doc`
* Microsoft Excel (`.xls`, `.xlsx`)
	* e.g. `obstracts-cli --input-file tests/file_inputs/xls/input.xlsx`
	* e.g. `obstracts-cli --input-file tests/file_inputs/xls/input.xls`

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

You can see an example custom extraction file in `tests/file_inputs/custom_extractions/extractions.txt`

### Updating STIX Objects

If the script detects an already extracted observable value present in `stix2_extractions/` then the `modified` time of this object is updated to the new extraction time and the updated object used in the final bundle for the report.

For example, if 1.1.1.1 detected in report 1 it would create a new object (object 1) where `created` and `modified` times were equal. Subsequently if 1.1.1.1 detected in report 2 it would use object 1 in the final bundle, but object 1 would also be updated with new `modifed` time to represent second sighting. The old bundle would remain unchanged. So bundle for report 1 would still have created and modified times equal, but report 2 would have the updated object, and so on.

You will see both copies of the Object still in the `stix2_extractions/` directory.

## Whitelisting

Stixify used MISP Warning Lists (using [PyMISPWarningLists](https://github.com/MISP/PyMISPWarningLists)) to identify potential extractions that should be whitelisted.

```json
	"x_warning_list_match": [
		"Top 20 000 websites from Cisco Umbrella",
		"Top 1000 website from Alexa",
		"List of known google domains",
		"Top 10 000 websites from Cisco Umbrella",
		"Top 1000 websites from Cisco Umbrella",
		"Top 10K most-used sites from Tranco",
		"Top 5000 websites from Cisco Umbrella",
		"Top 1,000,000 most-used sites from Tranco",
		"Top 10K websites from Majestic Million"
    ]
```

Whitelisted values still appear in results, however, you will see a custom STIX 2.1 Property `x_warning_list_match` in the Object when the extraction matches to a warning list.

For example;

```json
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--163a35c3-7d71-4c53-9a3d-5e6c660c9cb1",
            "created": "2022-08-23T10:59:13.009489Z",
            "modified": "2022-08-23T10:59:13.009489Z",
            "name": "Domain: google.com",
            "indicator_types": [
                "malicious-activity"
            ],
            "pattern": "[ domain-name:value = 'google.com' ]",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": "2022-08-23T10:59:13.009489Z",
            "x_warning_list_match": [
                "Top 20 000 websites from Cisco Umbrella",
                "Top 1000 website from Alexa",
                "List of known google domains",
                "Top 10 000 websites from Cisco Umbrella",
                "Top 1000 websites from Cisco Umbrella",
                "Top 10K most-used sites from Tranco",
                "Top 5000 websites from Cisco Umbrella",
                "Top 1,000,000 most-used sites from Tranco",
                "Top 10K websites from Majestic Million"
            ]
        }
```

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

