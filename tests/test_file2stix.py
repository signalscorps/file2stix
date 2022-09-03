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
    MITREMobileAttackObservable
)

slow_tests = [
    "country_adjective.txt", "country_code.txt", "domain.txt"
]

# It's a tuple containing test program path and the corresponding expected reports
testdata = []

OBSERVABLE_TEST_FOLDER = "tests/observable_tests/"
for (_, _, filenames) in os.walk(OBSERVABLE_TEST_FOLDER):
    for filename in filenames:
        testdata.append(OBSERVABLE_TEST_FOLDER + filename)


for test in testdata[:]:
    for slow_test in slow_tests:
        if slow_test in test:
            testdata.remove(test)

@pytest.mark.parametrize("test_file_path", testdata, ids=testdata)
def test_file2stix_cli(test_file_path, update_expected_reports):
    """
    Run file2stix-cli tool for example program and compare the
    generated report with the expected report.
    """
    print(update_expected_reports)

    test_file_name = os.path.basename(test_file_path)
    expected_report_path = "tests/expected_reports/" + test_file_name + ".json"
    output_json_file_path = None
    update_mitre_cti_database = False
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


    config = Config(
        test_file_path,
        update_mitre_cti_database=update_mitre_cti_database,
        output_json_file_path=output_json_file_path,
        ignore_observables_list=ignore_observables_list
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
            assert sdo_object["type"] == expected_sdo_object["type"]
            assert sdo_object["spec_version"] == expected_sdo_object["spec_version"]

            if "name" in expected_sdo_object:
                assert sdo_object["name"] == expected_sdo_object["name"]

            if "indicator_types" in expected_sdo_object:
                assert (
                    len(sdo_object["indicator_types"])
                    == len(expected_sdo_object["indicator_types"])
                    == 1
                )
                assert (
                    sdo_object["indicator_types"][0]
                    == expected_sdo_object["indicator_types"][0]
                )

            if "pattern" in expected_sdo_object:
                assert sdo_object["pattern"] == expected_sdo_object["pattern"]

            if "pattern_type" in expected_sdo_object:
                assert sdo_object["pattern_type"] == expected_sdo_object["pattern_type"]

            if "pattern_version" in expected_sdo_object:
                assert (
                    sdo_object["pattern_version"]
                    == expected_sdo_object["pattern_version"]
                )
