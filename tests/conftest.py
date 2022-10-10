def pytest_addoption(parser):
    parser.addoption(
        "--update-expected-reports",
        action="store_true",
        help="update expected stix reports",
    )


def pytest_generate_tests(metafunc):
    update_expected_reports = False
    if "update_expected_reports" in metafunc.fixturenames:
        if metafunc.config.getoption("update_expected_reports"):
            update_expected_reports = True
        metafunc.parametrize("update_expected_reports", [update_expected_reports])
