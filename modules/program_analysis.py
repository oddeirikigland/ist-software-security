tainted_dict = {}
parent_dict = {}
output = []
template = {"vulnerability": "", "source": "", "sink": "", "sanitizer": ""}

TAINTED = "Tainted"
NOT_TAINTED = "Not Tainted"
SANITIZED = "Sanitized"

STATUS = "status"
UNIQUE_KEY = "123321"


def determine_level(d, sources):
    variable_to_be_assign = d["targets"][0]["id"]
    tainted_dict[variable_to_be_assign] = {STATUS: check_if_tainted(d["value"], sources, variable_to_be_assign)}


def check_if_tainted(d, sources, variable_to_be_assign):
    if d["ast_type"] == "Num" or d["ast_type"] == "Str":
        return NOT_TAINTED

    if d["ast_type"] == "Name":
        var_name = d["id"]
        if variable_to_be_assign is not None:
            if var_name in parent_dict:
                parent_dict[variable_to_be_assign] = parent_dict[var_name]
            else:
                parent_dict[variable_to_be_assign] = var_name

        if var_name in tainted_dict:
            return tainted_dict[var_name][STATUS]
        else:
            return TAINTED

    if d["ast_type"] == "Call":
        if d["func"]["ast_type"] == "Attribute":
            source = d["func"]["attr"]
        else:
            source = d["func"]["id"]

        if source in sources:
            return TAINTED
        for arg in d["args"]:
            return check_if_tainted(arg, sources, variable_to_be_assign)
        return NOT_TAINTED

    if d["ast_type"] == "BinOp":
        left = check_if_tainted(d["left"], sources, variable_to_be_assign)
        right = check_if_tainted(d["right"], sources, variable_to_be_assign)
        return TAINTED if left == TAINTED or right == TAINTED else NOT_TAINTED

    if d["ast_type"] == "Attribute":
        return check_if_tainted(d["value"], sources, variable_to_be_assign)
    raise RuntimeError("ALARM! Unconsidered type")


def walk_dict(d, sources, sinks):
    ast_type = d["ast_type"]
    if ast_type == "Assign":
        determine_level(d, sources)

    if ast_type == "Call":
        if d["func"]["ast_type"] == "Attribute":
            sink = d["func"]["attr"]
        else:
            sink = d["func"]["id"]
        if sink in sinks:
            for arg in d["args"]:
                sink_key = sink + UNIQUE_KEY
                status = check_if_tainted(arg, sources, variable_to_be_assign=sink_key)
                if status == TAINTED:
                    new_template = template
                    new_template["sink"] = sink
                    new_template["source"] = parent_dict[sink_key]
                    output.append(new_template)

    for key, value in d.items():
        if isinstance(value, dict):
            walk_dict(value, sources, sinks)
        if isinstance(value, list):
            for elem in value:
                walk_dict(elem, sources, sinks)


def program_analysis(program_slice_json, vuln_pattern_json):
    global output
    global template

    for pattern in vuln_pattern_json:
        for operations in program_slice_json["body"]:
            walk_dict(operations, sources=pattern["sources"], sinks=pattern["sinks"])
        for vul in output:
            vul["vulnerability"] = pattern["vulnerability"]
        if len(output) > 0:
            return output[0]
    # If no vulnerability found
    return template
