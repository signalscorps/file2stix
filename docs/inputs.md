# Inputs

You can upload a range of filetypes to file2stix. This section of the documentation explains the types of files you can upload and how they are processed before extraction happens.

## Supported filetypes

file2stix supports the following filetype inputs:

* Markdown (`.md`, `.markdown`)
	* e.g. `file2stix --input-file tests/file_inputs/md/input.md`
	* e.g. `file2stix --input-file tests/file_inputs/md/input.markdown`
	* note, markdown can contain HTML. If HTML elements are detected, these are stripped. Only content outside of HTML tags is considered. e.g. `<a href="URL_INSIDE_HTML_TAG">PRINTED_URL</a>`, only `PRINTED_URL` would remain for extraction pattern matching
* Plain text (`.txt`)
	* e.g. `file2stix --input-file tests/file_inputs/txt/input.txt`
* CSV (`.csv`)
	* e.g. `file2stix --input-file tests/file_inputs/csv/input.csv`
* XML (`.xml`)
	* e.g. `file2stix --input-file tests/file_inputs/xml/input.xml`
	* note, all XML tags are stripped. e.g. `<url = "URL_INSIDE_XML_TAG">PRINTED_URL</url>`, only `PRINTED_URL` would remain for extraction pattern matching
* JSON (`.json`)
	* e.g. `file2stix --input-file tests/file_inputs/json/input.json`
	* note, only key values are considered. e.g. `{"1.1.1.1": "SOME_IP"}`, only `SOME_IP` would remain.
* PDF (`.pdf`)
	* e.g. `file2stix --input-file tests/file_inputs/pdf/input.pdf`
* Microsoft Word (`.doc`, `.docx`)
	* e.g. `file2stix --input-file tests/file_inputs/doc/input.docx`
	* e.g. `file2stix --input-file tests/file_inputs/doc/input.doc`
		* note, on Mac you will need to install `antiword` to use `.doc` files. Install using `brew install antiword`
* Microsoft Excel (`.xls`, `.xlsx`)
	* e.g. `file2stix --input-file tests/file_inputs/xls/input.xlsx`
	* e.g. `file2stix --input-file tests/file_inputs/xls/input.xls`
* YAML (`.yml`, `.yaml`)
	* e.g. `file2stix --input-file tests/file_inputs/yaml/input.yml`
	* e.g. `file2stix --input-file tests/file_inputs/yaml/input.yaml`
	* note, only key values are considered. e.g. `KEY: VALUE`, only `VALUE` would remain.
* YARA (`.yar`, `.yara`)
	* e.g. `file2stix --input-file tests/file_inputs/yara/input.yar`
	* e.g. `file2stix --input-file tests/file_inputs/yara/input.yara`