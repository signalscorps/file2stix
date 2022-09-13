# Extractions: Sightings Mode

Sightings mode assumes the reports being ingested contain observables seen in your organisation. Generally speaking, this mode should only be used if uploading a log line or similar that you want to convert to a STIX 2.1 Sighting Object.

This mode will extract the same things as when Analysis mode is used ([see Analysis Mode](/extractions-analysis-mode.md)), however, will include the addition of STIX 2.1 Sighting SRO.

#### STIX 2.1 Sighting SRO

Note, Sightings do not work with the following extractions:

* Sigma Rules
* YARA Rules

This is because these Objects do not directly refer to an atomic observables.

```json
{
	"type": "sighting",
    "spec_version": "2.1",
    "id": "sighting--<GENERATED BY STIX2 LIBRARY>",
    "created_by_ref": "identity--<IF TLP RED/AMBER/GREEN USER IDENTITY ID>",
    "created": "<REPORT CREATED PROPERTY VALUE>",
    "modified": "<REPORT MODIFIED PROPERTY VALUE>",
    "last_seen": "<REPORT CREATED PROPERTY VALUE>",
    "sighting_of_ref": "<EXTRACTED OBJECT ID>",
    "observed_data_refs": [
    	"observed-data--<OBSERVED DATA OBJECT ID>"
    ],
    "object_marking_refs": [
    	"marking-definition--<TLP LEVEL SET>"
    ],
}
```

The `sighting_of_ref` points to the SDO extracted.

The `object_marking_refs` points to the related to SROs.

To make this more clear, I will demonstrate with an example.

Let's assume an ipv4 with port observable is extracted. This will extraction create an Indicator SDO (referenced in the `sighting_of_ref` property of the Sighting SRO), a ipv4-addr SCO, and network-traffic SCO. It is these two SCOs that are listed under the `observed_data_refs` property.