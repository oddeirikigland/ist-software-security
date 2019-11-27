from constants import ROOT_DIR
from bo_analyser import main as analyzer
from modules.functions import read_from_json


def test_slice4():
    program_slice = "{}/data/slice4.json".format(ROOT_DIR)
    pattern = "{}/tests/test_slice4/slice4_vuln_pattern.json".format(ROOT_DIR)

    analyzer(program_slice, pattern, debug=False)
    output = read_from_json("{}/data/slice4.output.json".format(ROOT_DIR))

    assert output == [{
        "vulnerability": "SQL injection",
        "source": "koneksi",
        "sink": "y",
        "sanitizer": "",
    }, {
        "vulnerability": "SQL injection",
        "source": "b",
        "sink": "y",
        "sanitizer": "",
    }, {
        "vulnerability": "SQL injection",
        "source": "koneksi",
        "sink": "s",
        "sanitizer": "",
    }]

