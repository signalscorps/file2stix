# Inputs

You can upload a range of filetypes to file2stix. This section of the documentation explains the types of files you can upload and how they are processed before extraction happens.

## Supported filetypes

file2stix uses Python library called textract to extract text from files.

Once text has been extracted, the actual filetype determines what part of that text is considered for matching to extraction regular expressions.

### Plain text (`.txt`)

Plain text files are not processed. All content in a `.txt` file is considered.

e.g. `file2stix --input-file tests/file_inputs/txt/input.txt`

### CSV (`.csv`)

CSV files are not processed. All content in a `.csv` file is considered.

e.g. `file2stix --input-file tests/file_inputs/csv/input.csv`

### HTML (`.html`)

All HTML tags are stripped from the parsed text before extractions are run.

For example, `<a href="URL_INSIDE_HTML_TAG">PRINTED_URL</a>`, only `PRINTED_URL` would remain for extraction pattern matching.

e.g. `file2stix --input-file tests/file_inputs/html/input.html`

Note, html can get very messy. We generally recommend using a html to pdf tool (e.g. [printfriendly](https://www.printfriendly.com/) or similar) and uploading the page as a pdf (or whatever less messy file structure you covert to) for best results.

### Markdown (`.md`, `.markdown`)

Markdown can contain HTML. If HTML elements are detected, these are stripped (in the same way as done for HTML inputs). Only content between HTML tags is considered.

For example, `<a href="URL_INSIDE_HTML_TAG">PRINTED_URL</a>`, only `PRINTED_URL` would remain for extraction pattern matching.

e.g. `file2stix --input-file tests/file_inputs/md/input.md`

### PDF (`.pdf`)

Only printed text in a pdf is considered for matching.

e.g. `file2stix --input-file tests/file_inputs/pdf/input.pdf`

### XML (`.xml`)

All XML tags are stripped from the parsed text before extractions are run.

For example, `<url = "URL_INSIDE_XML_TAG">PRINTED_URL</url>`, only `PRINTED_URL` would remain for extraction pattern matching

e.g. `file2stix --input-file tests/file_inputs/xml/input.xml`

### JSON (`.json`)

Only values are considered for json inputs.

For example; `{"1.1.1.1": "SOME_IP"}`, only `SOME_IP` would remain for matching.

e.g. `file2stix --input-file tests/file_inputs/json/input.json`

### Microsoft Word (`.doc`, `.docx`)

Only printed text in a Word doc is considered for matching.

e.g. `file2stix --input-file tests/file_inputs/doc/input.docx`

### Microsoft Excel (`.xls`, `.xlsx`)

Only printed text in a Excel doc is considered for matching (formulas and scripts are ignored).

e.g. `file2stix --input-file tests/file_inputs/xls/input.xlsx`

### YAML (`.yml`, `.yaml`)

YAML files are not processed. All content in a YAML file is considered.

e.g. `file2stix --input-file tests/file_inputs/yaml/input.yml`

### YARA (`.yar`, `.yara`)

All content in yara filetypes is considered. Howevere, this input is designed for importing single yara rules only. Generally a single yara rule.

e.g. `file2stix --input-file tests/file_inputs/yara/input.yar`