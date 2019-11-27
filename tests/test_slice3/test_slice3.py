import pytest

from constants import ROOT_DIR
from bo_analyser import main as analyzer
from modules.functions import read_from_json


def test_slice3():
    program_slice = "{}/data/slice3.json".format(ROOT_DIR)
    pattern = "{}/tests/test_slice3/slice3_vuln_pattern.json".format(ROOT_DIR)

    analyzer(program_slice, pattern, debug=False)
    output = read_from_json("{}/data/slice3.output.json".format(ROOT_DIR))

    assert output == [{
        "vulnerability": "SQL injection",
        "source": "d",
        "sink": "z",
        "sanitizer": "t",
    }]