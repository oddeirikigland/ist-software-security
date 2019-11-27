from constants import ROOT_DIR
from modules.functions import read_from_json
from bo_analyser import main as analyzer


def test_slice12():
    program_slice = "{}/data/slice12.json".format(ROOT_DIR)
    pattern = "{}/tests/test_slice12/slice12_vuln_pattern.json".format(ROOT_DIR)

    analyzer(program_slice, pattern, debug=True)
    output = read_from_json("{}/data/slice12.output.json".format(ROOT_DIR))

    assert output == [{
            "vulnerability": "SQL injection",
            "source": "get",
            "sink": "execute",
            "sanitizer": "",
        }]

