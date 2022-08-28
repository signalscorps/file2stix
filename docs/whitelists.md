# Whitelists

Default whitelists identify potentially benign file2stix extractions. This section of the documentation explains how default whitelists work and how write your own custom whitelists.

## MISP Warning Lists

file2stix used MISP Warning Lists (using [PyMISPWarningLists](https://github.com/MISP/PyMISPWarningLists)) to identify potential extractions that should be whitelisted.

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

## Custom whitelists

You can also create your own whitelist. This should follow the [MISP Warning List schema](https://github.com/MISP/misp-warninglists/blob/main/schema.json).

An example of a custom warning list can be seen in `tests/file_inputs/custom_warning_lists/list.json`