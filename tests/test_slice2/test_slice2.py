from constants import ROOT_DIR
from bo_analyser import main as analyzer
from modules.functions import read_from_json


def test_slice2():
    program_slice = "{}/data/slice2.json".format(ROOT_DIR)
    pattern = "{}/tests/test_slice2/slice2_vuln_pattern.json".format(ROOT_DIR)

    analyzer(program_slice, pattern, debug=True)
    output = read_from_json("{}/data/slice2.output.json".format(ROOT_DIR))

    assert output == [{
        "vulnerability": "SQL injection",
        "source": "koneksi",
        "sink": "y",
        "sanitizer": "",
    }]

