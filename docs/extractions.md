# Extractions

file2stix extracts observables from text and translates them into STIX 2.1 Objects. This section of the documentation describes the templates of the STIX Objects created.

## Defanging

Defanging obfuscates indicators into a safer representations so that a user reading a report does not accidentally click on a malicious URL or inadvertently run malicious code. Many cyber threat intelligence reports shared electronically employ defanging.

Typical types of fanged Observables include IPv4 addresses (e.g. `1.1.1.1`), IPv6 addresses (e.g. `2001:0db8:85a3:0000:0000:8a2e:0370:7334`), domain names (e.g. `example.com`), URLs (e.g. `https://example.com/research/index.html`), email addresses (e.g. `example@example.com`), file extensions (e.g. `malicious.exe`), and directory paths (e.g. `C:\\Windows\\System32`).

Unfortunately, there is no universal standard for defanging, although there are some common methods. Some samples of defanging I have observed include the following:

* Wrapping one or more special characters in `[` `]`
  * e.g. `www[.]example[.]com`
  * e.g. `http[:]//example.com`
  * e.g. `http[://]example.com`
  * e.g. `1.1.1.1[/]24`
* Wrapping one or more special characters in `{` `}`
* Wrapping one or more special characters in `(` `)`
* Prefixing one or more special characters with `[`
  * e.g. `www[.example[.com`
  * e.g. `http[://example.com`
  * e.g. `http[://example.com`
* Prefixing one or more special characters with `\`
* Replacing `http` and `hxxp`
  * e.g. `hxxps://google.com`
* Replacing `.` with ` dot `
  * e.g. `example@example dot com`
  * e.g. `http://example dot com`
* Replacing `.` with `[dot]` (or  `(dot)`, or `{dot}`)
  * e.g. `example@example[dot]com`
* Replacing `@` with ` at `
  * e.g. `example at example.com`
* Replacing `@` with `[at]` (or  `(at)`, or `{at}`)
  * e.g. `example[at]example.com` 

Note, a combination of the above techniques are also commonly implemented used. For example replacing `.` with ` dot ` and replacing `@` with ` at ` for an email like so; fanged = `example at example dot com`, defanged = `example@example.com`

Another example using even more fanging technique combinations for a URL; fanged = `hxxps[:]//test\.example[.)com[/]path`, defanged = `https://test.example.com/path`

file2stix can be used to defang the following observable types

* ipv4
* ipv6
* domain
* url
* email-address

## STIX Support

file2stix only supports STIX version 2.1 [as defined by this specification](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html).

## Identities (`identity`)

file2stix assigns a `created_by_ref` property to many Objects. This value is obtained from an Identity Object generated from the template `/stix_templates/identity.yml`.

By defaults the generic file2stix identity will be used. 

You can also change the Identity by modifying the values in the template file.

If you do modify the file make sure to;

1. Only modified the fields described in the following bullet points
2. Keep the quotes (`""`) around values
3. Replace the UUID in the `id` property with a randomly generated UUID v4. [Here is a generator you can use to do this](https://www.uuidgenerator.net/version4)
  * e.g. `identity--acf55024-6bbe-486f-a27a-7967559324f4` -> `identity--bf65f135-7876-4b4f-a48b-4cbd85e77e87`
4. Modify the `created` and `modified` dates, if needed. Be sure to keep the same date/time format `YYYY-DD-MMTHH:MM:SS.sssZ`
5. Update the `name` and `description` fields. If using special json characters be sure to escape them
6. The `identity_class` property [must match one shown here](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_be1dktvcmyu)
7. The `sectors` property [must match one shown here](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_oogrswk3onck)

## Confidence scoring

file2stix also optionally allows you to add the `confidence` property to all extracted Indicator SDOs. You can set confidence between 0 - 100. [Consult the STIX 2.1 Specification for more information](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_1v6elyto0uqg).

## TLP (`marking-definition`)

The TLP defined plays two important roles in file2stix.

1. It adds a `marking-definition--` to all Objects
2. Determines how creation of Object should work

file2stix allows for `TLP:GREEN`, `TLP:AMBER`, `TLP:RED` and `TLP:WHITE` definitions to be used when adding Reports. 

This determines the [STIX marking-definition](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_yd3ar14ekwrs), either;

* `TLP:WHITE` (`marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9`)
* `TLP:GREEN` (`marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da`)
* `TLP:AMBER` (`marking-definition--f88d31f6-486f-44da-b317-01333bde0b82`)
* `TLP:RED` (`marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed`)

The TLP value is reported in the `object_marking_refs` property for the STIX Report Object and all extracted Objects representing extracted Observables (except for ATT&CK or CAPEC, where generic MITRE Objects are used).

The selection of TLP for the Report alongside the `identity`, confidence, and custom warning lists also has an impact on how the extracted observable STIX Objects are stored and represented. This is to ensure proper sharing protocols are Observed.

### `TLP:WHITE`

Every time a new observable is detected, a new SDO Object is created with the `object_marking_refs` = `marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da` (except for ATT&CK and CAPEC STIX Objects).

Now consider the future. It is very likely the same observable (in this case IPv4 address) will also extracted from other uploads. When the same observable is detected in future report marked TLP White, the previously created STIX Object is updated.

To update the existing Object, the `created` property of the STIX Object would remain unchanged. However, the `modified` property would be updated to the timestamp of when the observable was last extracted from a report.

This happens in custom extractions too, where a user has set the same extraction string and Object type.

This does not include SCOs (e.g. Software Objects). Here the existing Object would be used, but not updated (because they do not contain `created` or `modified` properties).
 
To demonstrate how this works in practice, lets assume in report 1 an IPv4 address observable (`198.51.100.3`) is detected.

Assuming the IPv4 address (`198.51.100.3`) has not been saved as an IPv4 address SDO previously from a report marked `TLP:WHITE`, a new SDO would be created for it (in this case, lets give it `id` = `ff26c055-6336-5bc5-b98d-13d6226742dd`). The `created` and `modified` properties for this STIX Object would both have the same timestamp (the time of extraction). The object also inherits the TLP level set against the report (in this case, `TLP:WHITE`).

If this IPv4 address (`198.51.100.3`) was later detected in another data source imported to file2stix and that report was marked `TLP:WHITE`, the existing SDO would be used (and updated) to represent the extraction (in this case the SDO with `id` = `ff26c055-6336-5bc5-b98d-13d6226742dd` would be updated).

For Reports marked TLP White, STIX 2.1 Objects representing extracted values (not the Report Object itself) do not contain a `created_by_ref` property. Extractions can be attributed to an identity using the SRO linking it to the Report SDO (see: Relationships).

As a result, confidence and custom whitelists cannot be applied to Reports marked TLP:WHITE.

### `TLP:GREEN`, `TLP:AMBER` or `TLP:RED`

In many cases, a person uploading a report will not want the report and the observables extracted to be shared with anyone else beyond their organisation. In file2stix we treat an Organisation as a single `identity` Object. In such instances they would assign the report a `TLP:GREEN`, `TLP:AMBER` or `TLP:RED` designation.

For Reports marked TLP Green, Amber or Red STIX 2.1 Objects representing extracted values always contain `created_by_ref` property to ensure proper attribution when sharing. This only applies to STIX Domain an STIX Relationship Objects (SCOs never contain a `created_by_ref` property).

Like before, every time a new observable is detected, a new STIX Object is created but this time with a `TLP:GREEN`, `TLP:AMBER` or `TLP:RED` marking (except for ATT&CK and CAPEC STIX Objects). 

However, in the case of an observable being detected for the second time, unlike `TLP:WHITE` reports where a single object would be updated, it is possible new observable objects are created.

If the previously created extracted object matches a previous extracted value AND has the same `identity` AND TLP level as previously extracted AND has the same warning list matches AND has the same `confidence` score, the previously created Object will be used and updated to reflect the new extraction time (in the same way as TLP White is handled).

If the previously created extracted object matches a previous extracted value AND has the same TLP level BUT a different `identity` (or `confidence` score, or whitelist match) to one that matches then a new Object is created.

If the previously created extracted object matches a previous extracted value AND has the same `identity` BUT a different TLP level (or `confidence` score, or whitelist match) to one that matches  then a new Object is created.

Put another way, if the same combination of TLP, identity confidence and warning list exists, a previously created object is updated, else a new one is created for reports marked `TLP:GREEN`, `TLP:AMBER` or `TLP:RED`. In the case of SCOs only the TLP level is considered (because no `created_by_ref` field exists).

To give an example, assume report 4 is marked as `TLP:AMBER` is created by `identity-1234` and contains an IPv4 address observable (`198.51.100.3`). A new Indicator SDO Object is created for it (id = `01559644-3b76-4e2a-9cdd-4b7417e95640`) with marking definition `TLP:AMBER` and the `created_by_ref` for that `identity`.

Later, report 5 is uploaded by the same user, marked as `TLP:AMBER`, and contains an IPv4 address observable (`198.51.100.3`). As the TLP and `identity` match, the old object would be updated.

Later, report 6 is uploaded by a new user `identity-9999`, marked as `TLP:AMBER`, and contains an IPv4 address observable (`198.51.100.3`). In this example, a new Object for the extracted Observable would be made because the `identity` does not match a previously created object for that extraction.

## Report SDOs (`report`)

All individual data sources ingested or uploaded are represented as a unique [STIX Report SDO](https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_n8bjzg1ysgdq) that take the following structure;

```json
    {
      "type": "report",
      "spec_version": "2.1",
      "id": "report--<GENERATED BY STIX2 LIBRARY>",
      "created_by_ref": "identity--<IDENTITY ID>",
      "created": "<ITEM INGEST DATE>",
      "modified": "<ITEM INGEST DATE>",
      "name": "File converted: <FILENAME>",
      "published": "<ITEM INGEST DATE>",
      "report_types": ["threat-report"],
      "object_marking_refs": [
        "marking-definition--<TLP LEVEL SET>"
      ],
      "object_refs": ["<LIST OF ALL EXTRACTED OBJECTS>"],
      "external_references": [
        {
          "source_name": "file2stix",
          "description": "This object was created using file2stix from the Signals Corps.",
          "url": "https://github.com/signalscorps/file2stix"
        }
      ]
    }
```

Note, the `object_refs` contains all references that are referenced by objects in the report (SDOs, SROs, SCOs). This includes extracted objects (i.e. Indicator SDOs, Vulnerability SDOs, Software SCOs, Relationship SROs etc.).

## Observed Data SDOs (`observed-data`)

For every extraction type where an SCO is created (ipv4, ipv6, File name, File hash, Directory, Domain, URL, Email Address, MAC Address, Windows Registry Key, User Agent, Autonomous System Number, Cryptocurrency, IBAN, CPE, Credit Card) an Observed Data Object is also created for each unique SCO (note, if reusing old SCO a new Observed Data Object is not created, see following section).

```json
{
    "type": "observed-data",
    "spec_version": "2.1",
    "id": "observed-data--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER/GREEN USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "first_observed": "<FIRST REPORT CREATED PROPERTY VALUE>",
    "last_observed": "<LAST REPORT CREATED PROPERTY VALUE>",
    "number_observed": "<COUNT OF TIMES SCO WITH SAME TLPHAS BEEN SEEN PREVIOUSLY BY FILE2STIX>",
    "object_refs": [
      "<ID OF SCO SEEN>"
    ],
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "external_references": [
      {
        "source_name": "file2stix",
        "description": "This object was created using file2stix from the Signals Corps.",
        "url": "https://github.com/signalscorps/file2stix"
      }
    ]
}
```

The `number_observed` property is set to 1 on creation.

Everytime file2stix reuses an SCO in a bundle, the related Observed data objects `number_observed` property is increased by one.

For example, if the same SCO is seen in 5 reports all marked TLP White (and all all properties are identical), then this will represent 1 SCO, thus one Observed Data SCO, and therefore `number_observed` will be 5 for the 5 reports. If it is seen again in a report marked TLP white, then the count will increase to 6.

Using another example to illustrate the influence of TLP level; If 1 of these 5 reports in TLP Green and the rest are TLP White (with all other properties at upload the same), 2 SCOs and 2 Observed Data Objects will exist. The `number_observed` in the TLP White Observed data Object will be 4, and in the TLP Green Object the `number_observed` will be one (assuming these are the only 5 reports with this observable detected).

One final example; If 2 reports are uploaded as TLP Red and attributed to two different identities both containing the same Observable (with all other properties at upload the same) then 2 SCOs will be created, 2 Observed Data Objects will be created. Assuming these are the only 2 reports that contain this observable, then the `number_observed` will be 1 in each Observed Data Object.

## Relationship SROS (`relationship`)

There are two types of extractions in file2stix; default and custom.

### Relationships for default extractions between Report and SDO

In the case of default extractions, a Relationship between the extracted Object and Report SDO is created with the `relationship_type` equal to default-extract.

The `created_by_ref` is the Identity ID.

The `created` and `modified` dates match those in the linked Report Object.

Here is the structure of the SRO for default extractions;

```json
  {
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<USER IDENTITY ID>",
    "created": "<REPORT CREATED DATE>",
    "modified": "<REPORT CREATED DATE>",
    "relationship_type": "default-extract-from",
    "source_ref": "<EXTRACTED STIX OBSERVABLE ID>",
    "target_ref": "report--<REPORT OBJECT>",
    "external_references": [
      {
        "source_name": "file2stix",
        "description": "This object was created using file2stix from the Signals Corps.",
        "url": "https://github.com/signalscorps/file2stix"
      }
    ]
  }
```

### Relationships for custom extractions between Report and SDO

Custom extractions have slightly different Relationship Objects created where the `relationship_type` equal to custom-extract, as follows;

```json
  {
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<USER IDENTITY ID>",
    "created": "<REPORT CREATED DATE>",
    "modified": "<REPORT CREATED DATE>",
    "relationship_type": "custom-extract-from",
    "source_ref": "<EXTRACTED STIX OBSERVABLE ID>",
    "target_ref": "report--<REPORT OBJECT>",
    "external_references": [
      {
        "source_name": "file2stix",
        "description": "This object was created using file2stix from the Signals Corps.",
        "url": "https://github.com/signalscorps/file2stix"
      }
    ]
  }
```

### Relationships between SCO and SDO

Many extractions that create Indicator Objects also create one or more SCOs. These are joined like so

```json
  {
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<USER IDENTITY ID>",
    "created": "<REPORT CREATED DATE>",
    "modified": "<REPORT CREATED DATE>",
    "relationship_type": "pattern-contains",
    "source_ref": "indicator--<EXTRACTED STIX INDICATOR ID>",
    "target_ref": "<EXTRACTED STIX SCO ID>",
    "external_references": [
      {
        "source_name": "file2stix",
        "description": "This object was created using file2stix from the Signals Corps.",
        "url": "https://github.com/signalscorps/file2stix"
      }
    ]
  }
```

## Warning Lists

Warning Lists identify potentially benign file2stix extractions.

file2stix used MISP Warning Lists (using [PyMISPWarningLists](https://github.com/MISP/PyMISPWarningLists)) to identify potential extractions that should be whitelisted using a custom Extension definition.

https://raw.githubusercontent.com/signalscorps/stix2-objects/main/extension-definition/extension-definition--c8ea5ecb-f4a3-45e7-94de-9b9ba05161af/20220101000000000.json

Extracted values that match a Warning List are still converted to STIX 2.1 Objects, however, will contain the custom property listing the Warning Lists the extracted value matches with and will also contain `indicator_types` = `benign`.

For example;

```json
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--fb715301-acf3-4add-a70a-2b96f5ac15f5",
            "created": "2022-09-07T06:18:21.997149Z",
            "modified": "2022-09-08T06:13:24.191194Z",
            "name": "Domain: google.com",
            "indicator_types": [
                "unknown", "benign"
            ],
            "pattern": "[ domain-name:value = 'google.com' ]",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": "2022-09-07T06:18:21.997149Z",
            "object_marking_refs": [
                "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
            ],
            "extensions": {
                "extension-definition--c8ea5ecb-f4a3-45e7-94de-9b9ba05161af": {
                    "extension_type": "property-extension",
                    "warning_list_match": [
                        "Top 20 000 websites from Cisco Umbrella",
                        "Top 1000 website from Alexa",
                        "List of known google domains",
                        "Top 10 000 websites from Cisco Umbrella",
                        "Top 1000 websites from Cisco Umbrella",
                        "Top 10K most-used sites from Tranco",
                        "Top 5000 websites from Cisco Umbrella",
                        "Top 1,000,000 most-used sites from Tranco",
                        "Top 10K websites from Majestic Million"
                    ],
                    "custom_warning_list_match": [
                        "My custom list"
                    ]
                }
            },
            "external_references": [
              {
                "source_name": "file2stix",
                "description": "This object was created using file2stix from the Signals Corps.",
                "url": "https://github.com/signalscorps/file2stix"
              }
            ]
        },
```

Note, MISP Warning Lists contain a `type` value (defined in the Warning List JSON). file2stix treats each Warning List differently, depending on its type as follows;

* `string`: extracted observable must be exact match to Warning List value (e.g. warning list: google.com -> observable: google.com = match)
* `substring`: extracted observable must contain Warning List value (e.g. warning list: google -> observable: google.com = match)
* `hostname`: extracted observable must contain Warning List value
* `cidr`: extracted observable must be exact match to Warning List value
* `regex`: file2stix does not consider warning lists of type `regex`

It is possible to completely ignore extractions that match to warning lists (and not create a STIX Object from them) using the flag `--ignore-warninglist-observables`.

### Custom Warning Lists

You can also create your own Warning Lists. Custom Warning Lists must follow the [MISP Warning List schema](https://github.com/MISP/misp-warninglists/blob/main/schema.json).

An example of a custom warning list can be seen in `tests/file_inputs/custom_warning_lists/list.json`

Due to the way data is shared, only Reports marked TLP GREEN, TLP AMBER, or TLP RED can be used with custom warning lists. As TLP WHITE reports are shared without attribution, printing a Warning List name will not be enough for a downstream user to determine what/who/and where the Warning List came from.

## Extracted Object logic

If the same Observable is identified more than once in the same report, only one extraction is made. For example, if 1.1.1.1 is seen 3 times in a report, only one Indicator SDO is created for it. Similarly, for Observed Data counts, despite being mentioned 3 times in the same report, it will only add 1 to the `number_observed` field.

## Mode specific extractions

The type of Objects created during extraction depends on the mode used. file2stix offers two modes;

1. `analysis` (default): used during research to create STIX 2.1 Objects from general threat research
  * [View Analysis Mode documentation here](./extractions-analysis-mode.md)
2. `sighting`: used to denote that extractions from a report represent real instances of an observable being seen in your environment (generally used for log inputs)
  * [View Sighting Mode documentation here](./extractions-sightings-mode.md)
