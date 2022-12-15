# Demo Script

file2stix is designed to take unstructured intel documents -- text, emails, pdfs, word docs -- and turn them into structured STIX 2.1 intel.

Let's ease into it gently.

## Extractions 101

A simple extraction of an IP. Here's the file I will input to file2stix, and now I will run the script;

```shell
file2stix --input-file tests/observable_tests/ipv4.txt
```

As you can see a Report SDO, Indicator SDO, and IPv4 SCO have been created. file2stix support most STIX 2.1 SDO, SRO, and SCO objects, and also introduces some custom objects (using extensions definitions).

## Defang extractions

In many cases reports contain fanged data. file2stix won't automatically extract these, but can be instructed to try and defang them before extractions.

```shell
file2stix --input-file tests/observable_tests/ipv4-fanged.txt --defang-observables
```

Note, file2stix attempts to extract many types of fangs, but not all due to the variety used.

Note, if I pass the same file without defang, no data will be extracted;

```shell
file2stix --input-file tests/observable_tests/ipv4-fanged.txt
```

## Extraction modes

One thing I observed was people using browser extensions to extract data from logs in SIEMs -- not naming any names but there have been many similar scenarios.

To satisfy various uses like this; file2stix offers 3 extraction modes; `analysis` (shown), `observed` which in addition to analysis mode will use the observed data object to also count the times an observable has been seen in a report, and `sighting` which in addition to observed mode will report a Sighting SRO against the Observed data object, e.g.

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --extraction-mode sighting
```

## Supported filetypes

file2stix supports multi-filetypes for extraction (doc, pdf, csv, )

```shell
file2stix --input-file tests/demos/ipv4.docx
```

Depending on the filetype file2stix will treat it differently. In the case of doc files they are firstly translated to txt. file2stix also supports html, in this case, file2stix strips the html tags.

In both of these previous examples, you will see the same object extracted.

## Custom extractions

All these objects are created from extractions defined using regular expressions (essentially pattern matching). 

Over 20 default extractions are supported by file2stix from AS numbers, cryptocurrency wallets, credit-cards, to detection rules like Sigma etc.

The nice thing about using regex is that it makes the tool expandable to tweak existing and add new extractions.

If you don't want to get into the codebase file2stix also allows for custom extractions. You can enter your own string of text and map it to a STIX object and file2stix will use it as part of the extraction logic.

```shell
file2stix --input-file tests/custom_extractions/malware_input_file.txt --custom-extraction-file tests/custom_extractions/malware_custom_extraction.txt

```

## Warning list / ignoring extractions

If you're working with large files you can choose to ignore certain types observables from extraction entirely;

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --ignore-observable-prefix IPv4

```

file2stix also supports MISP Warning Lists. For those unfamiliar MISP Warning List identify false positives, e.g. google.com extracted from a report.

By default MISP Warning Lists will be considered against all extractions;

```shell
file2stix --input-file tests/warning_lists/default_list_matches-string.txt
```

You can see in the output how the Indicator SDO contains an extension linking the MISP Warning List Match.

It's also possible to create your own Warning Lists (in MISP Warning List format) to identify benign extractions;

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --misp-custom-warning-list-file tests/warning_lists/ipv4.json
```

## MITRE Knowledge-bases

file2stix also takes in external MITRE knowledge-bases -- ATT&CK and CAPEC -- for extraction.

```shell
file2stix --input-file tests/observable_tests/mitre_attck_enterprise.txt --update-mitre-cti-database
```

You'll see I am passing `--update-mitre-cti-database`, this just makes file2stix is using the most up-to-date version of ATT&CK and CAPEC.

In this example, file2stix has detected references two ATT&CK techniques. All ATT&CK and CAPEC STIX objects are supported. This makes it really useful when adding the contextual information to reports -- I know a lot of analysts doing this manually right now.

## TLP Levels

By default, file2stix assigns TLP White to objects extracted, but you can modify this by specifying TLP levels:

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --tlp-level RED
```

Here all extracted SDOs and SROs are tagged as TLP RED.

## Confidence

If you trust the author of the report (or are unsure), it's possible to assign a confidence score to extracted SDOs (including the Report SDO). Currently this is quite simplistic and will apply the same confidence score to all SDOs, for example;

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --confidence 80
```

## Identities

By default, file2stix will use the default file2stix identity and assign that to the `created_by_ref` of SDOs and SROs. 

Many of you will want to change this to an existing STIX Identity (or new one) for your organisation. This can be done by passing your own `identity.yml` file as documented. This will create a new STIX identity object using the defined settings that will be used instead;

```shell
file2stix --input-file tests/observable_tests/ipv4.txt --user-identity-file tests/stix_templates/custom_identity_good.yml
```` 

## End

That was very quick demo of file2stix. You can use a combination of these options to get the desired output. There's a lot more to file2stix I haven't covered. Be sure to check out the full documentation.