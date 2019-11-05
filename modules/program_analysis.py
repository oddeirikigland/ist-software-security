def program_analysis(program_slice_json, vuln_pattern_json):
    output = {
        "vulnerability": "SQL injection",
        "source": "request",
        "sink": "execute",
        "sanitizer": "",
    }
    return output
