import pytest

from constants import ROOT_DIR
from bo_analyser import main as analyzer
from modules.functions import read_from_json


def test_slice5():
    program_slice = "{}/data/slice5.json".format(ROOT_DIR)
    pattern = "{}/tests/test_slice5/slice5_vuln_pattern.json".format(ROOT_DIR)

    analyzer(program_slice, pattern, debug=False)
    output = read_from_json("{}/data/slice5.output.json".format(ROOT_DIR))

    assert output == [{
        "vulnerability": "SQL injection",
        "source": "query1",
        "sink": "z",
        "sanitizer": "",
    }]


@pytest.mark.skip(reason="no way of currently testing this")
def test_slice5_several_sources_per_sink():
    program_slice = "{}/data/slice5.json".format(ROOT_DIR)
    pattern = "{}/tests/test_slice5/slice5_vuln_pattern.json".format(ROOT_DIR)

    analyzer(program_slice, pattern, debug=False)
    output = read_from_json("{}/data/slice5.output.json".format(ROOT_DIR))

    assert output == [{
        "vulnerability": "SQL injection",
        "source": "query1",
        "sink": "z",
        "sanitizer": "",
    }
    # , {
    #     "vulnerability": "SQL injection",
    #     "source": "b",
    #     "sink": "y",
    #     "sanitizer": "",
    # }, {
    #     "vulnerability": "SQL injection",
    #     "source": "koneksi",
    #     "sink": "s",
    #     "sanitizer": "",
    # }
    ]