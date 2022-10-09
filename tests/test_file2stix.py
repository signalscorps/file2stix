"""
Run below command to run all tests (in repo root)
```
pytest -rP -vv
```

Run below command to update test reports
```
pytest -rP -vv --update-expected-reports
```
"""

import json
import pytest
import os
import file2stix.main
from file2stix.config import Config
from file2stix.observables import (
    MITREEnterpriseAttackObservable,
    MITRECapecObservable,
    MITREICSAttackObservable,
    MITREMobileAttackObservable,
)

# exclude_tests = ["credit_card_discover.txt"]

# It's a tuple containing test program path and the corresponding expected reports
testdata = [
    "tests/observable_tests/asn.txt"
]

# OBSERVABLE_TEST_FOLDER = "tests/observable_tests/"
# for (_, _, filenames) in os.walk(OBSERVABLE_TEST_FOLDER):
#     for filename in filenames:
#         testdata.append(OBSERVABLE_TEST_FOLDER + filename)


# for test in testdata[:]:
#     for slow_test in exclude_tests:
#         if slow_test in test:
#             testdata.remove(test)


@pytest.mark.parametrize("test_file_path", testdata, ids=testdata)
def test_file2stix_cli(test_file_path, update_expected_reports):
    """
    Run file2stix-cli tool for observable unit tests.
    """

    test_file_name = os.path.basename(test_file_path)
    expected_report_path = "tests/expected_reports/" + test_file_name + ".json"
    output_json_file_path = None
    update_mitre_cti_database = False
    defang_observables = False
    ignore_observables_list = [
        MITREEnterpriseAttackObservable,
        MITRECapecObservable,
        MITREICSAttackObservable,
        MITREMobileAttackObservable,
    ]

    config = None
    if update_expected_reports:
        output_json_file_path = expected_report_path

    if "mitre" in test_file_path:
        update_mitre_cti_database = True
        ignore_observables_list = None

    if "fanged" in test_file_path:
        defang_observables = True

    config = Config(
        test_file_path,
        update_mitre_cti_database=update_mitre_cti_database,
        output_json_file_path=output_json_file_path,
        ignore_observables_list=ignore_observables_list,
        defang_observables=defang_observables,
    )

    report_path = file2stix.main.main(config)

    if not update_expected_reports:
        with open(report_path) as f:
            report = json.load(f)

        with open(expected_report_path) as f:
            expected_report = json.load(f)

        for sdo_object, expected_sdo_object in zip(
            report["objects"], expected_report["objects"]
        ):
            ignore_fields_list = [
                "id",
                "created",
                "modified",
                "object_refs",
                "source_ref",
                "target_ref",
                "published",
                "valid_from",
            ]

            for field in expected_sdo_object:
                if field not in ignore_fields_list:
                    assert (
                        sdo_object[field] == expected_sdo_object[field]
                    ), f"Field {field} is differening"
