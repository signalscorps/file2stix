import json
import pytest
import obstracts_cli.main
from obstracts_cli.config import Config

# It's a tuple containing example program path and the corresponding expected reports
testdata = [
    (
        "examples/FireEyeAPT39.txt",
        "tests/expected_reports/bundle--8648ec6a-a38e-49cc-ad7e-b4978d591bdb.json",
    ),
    (
        "examples/input2.txt",
        "tests/expected_reports/bundle--10e65017-d8f1-44b5-873e-d07f5c7ab8d5.json",
    ),
    (
        "examples/input.txt",
        "tests/expected_reports/bundle--920996cf-3f15-4150-87d8-fca8ed1e01b5.json",
    ),
    # Ignoring madiant-api.txt for now since it takes a lot of time
    # (
    #     "examples/mandiant-apt1.txt",
    #     "tests/expected_reports/bundle--8a6989a9-d1a1-474b-b792-1c82f4cdb931.json",
    # ),
]


@pytest.mark.parametrize(
    "example_path,expected_report_path", testdata, ids=[t[0] for t in testdata]
)
def test_obstracts_cli(example_path, expected_report_path):
    """
    Run obstract-cli tool for example program and compare the 
    generated report with the expected report.
    """
    config = Config(example_path)
    report_path = obstracts_cli.main.main(config)
    
    with open(report_path) as f:
        report = json.load(f)

    with open(expected_report_path) as f:
        expected_report = json.load(f)

    for sdo_object, expected_sdo_object in zip(
        report["objects"], expected_report["objects"]
    ):
        assert sdo_object["type"] == expected_sdo_object["type"]
        assert sdo_object["spec_version"] == expected_sdo_object["spec_version"]
        assert sdo_object["name"] == expected_sdo_object["name"]

        if "indicator_types" in expected_sdo_object:
            assert (
                len(sdo_object["indicator_types"])
                == len(expected_sdo_object["indicator_types"])
                == 1
            )
            assert sdo_object["indicator_types"][0] == expected_sdo_object["indicator_types"][0]
        
        if "pattern" in expected_sdo_object:
            assert sdo_object["pattern"] == expected_sdo_object["pattern"]

        if "pattern_type" in expected_sdo_object:
            assert sdo_object["pattern_type"] == expected_sdo_object["pattern_type"]

        if "pattern_version" in expected_sdo_object:
            assert sdo_object["pattern_version"] == expected_sdo_object["pattern_version"]