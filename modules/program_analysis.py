import json

TAINTED = "Tainted"
NOT_TAINTED = "Not Tainted"
SANITIZED = "Sanitized"

STATUS = "status"
UNIQUE_KEY = "123321"


def pretty_json(json_dict):
    return json.dumps(json_dict, indent=4, sort_keys=True)


def determine_level(d, sources, sanitizers, variable_to_be_assign):
    tainted_dict[variable_to_be_assign] = {
        STATUS: check_if_tainted(d["value"], sources, sanitizers, variable_to_be_assign)
    }


def check_if_tainted(d, sources, sanitizers, variable_to_be_assign):
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
            function_name = d["func"]["attr"]
        else:
            function_name = d["func"]["id"]
        if function_name in sources:
            parent_dict[variable_to_be_assign] = function_name
            return TAINTED

        function_name_is_sanitizer = function_name in sanitizers
        status = NOT_TAINTED
        for arg in d["args"]:
            current_status = check_if_tainted(
                arg, sources, sanitizers, variable_to_be_assign
            )
            if function_name_is_sanitizer and current_status == TAINTED:
                try:
                    if arg["id"] in parent_dict:
                        sanitized_dict[parent_dict[arg["id"]]] = function_name
                    else:
                        sanitized_dict[arg["id"]] = function_name
                except KeyError:
                    # If it's a call inside the sanitizer
                    sanitized_dict[arg["func"]["id"]] = function_name
            if status == NOT_TAINTED:
                status = current_status
        if function_name_is_sanitizer and status == TAINTED:
            return SANITIZED
        return status

    if d["ast_type"] == "BinOp":
        left = check_if_tainted(d["left"], sources, sanitizers, variable_to_be_assign)
        right = check_if_tainted(d["right"], sources, sanitizers, variable_to_be_assign)
        return TAINTED if left == TAINTED or right == TAINTED else NOT_TAINTED

    if d["ast_type"] == "Attribute":
        return check_if_tainted(d["value"], sources, sanitizers, variable_to_be_assign)

    if d["ast_type"] == "NameConstant":
        return NOT_TAINTED
    if d["ast_type"] == "Tuple":
        status_list = [check_if_tainted(elem, sources, sanitizers, variable_to_be_assign) for elem in d["elts"]]
        return TAINTED if TAINTED in status_list else NOT_TAINTED
    if d["ast_type"] == "Compare":
        comparator = check_if_tainted(d["comparators"][0], sources, sanitizers, variable_to_be_assign)
        left = check_if_tainted(d["left"], sources, sanitizers, variable_to_be_assign)
        return TAINTED if TAINTED in comparator or TAINTED in left else NOT_TAINTED
    s = "ALARM! Unconsidered type: {}".format(d["ast_type"])
    raise RuntimeError(s)


def walk_dict(d, sources, sanitizers, sinks):
    ast_type = d["ast_type"]
    if ast_type == "Assign":
        determine_level(
            d, sources, sanitizers, variable_to_be_assign=d["targets"][0]["id"]
      )
    if ast_type == "Compare":
    # TODO to be evaluated
        implicit = check_if_tainted(d, sources, sanitizers, None)
        if implicit == TAINTED:
            print("Implicit flow detected")
    if ast_type == "BoolOp":
    # TODO determine type of BoolOp
        for i in range(len(d["values"])):
            walk_dict(d["values"][i], sources, sanitizers, sinks)
    if d["ast_type"] == "Compare":
        try:
            determine_level(d, sources, sanitizers, variable_to_be_assign=d["comparators"][0]["id"])
        except:
            print("Could not evaluate Compare statement")
    if ast_type == "If":
        walk_dict(d["test"], sources, sanitizers, sinks)
        walk_dict(d["body"][0], sources, sanitizers, sinks)
        for i in range(len(d["orelse"])):
            els = d["orelse"][i]
            walk_dict(els, sources, sanitizers, sinks)
    if ast_type == "Call":
        if d["func"]["ast_type"] == "Attribute":
            sink = d["func"]["attr"]
        else:
            sink = d["func"]["id"]
        if sink in sinks:
            for arg in d["args"]:
                sink_key = sink + UNIQUE_KEY
                status = check_if_tainted(
                    arg, sources, sanitizers, variable_to_be_assign=sink_key
                )
                if status == TAINTED or status == SANITIZED:
                    new_template = template
                    new_template["sink"] = sink
                    if sink_key in parent_dict:
                        new_template["source"] = parent_dict[sink_key]
                        if status == SANITIZED:
                            new_template["sanitizer"] = sanitized_dict[
                                parent_dict[sink_key]
                            ]
                    output.append(new_template)

    for key, value in d.items():
        if isinstance(value, dict):
            walk_dict(value, sources, sanitizers, sinks)
        if isinstance(value, list):
            for elem in value:
                walk_dict(elem, sources, sanitizers, sinks)


def program_analysis(program_slice_json, vuln_pattern_json, debug):
    global output
    global parent_dict
    global tainted_dict
    global sanitized_dict
    global template

    tainted_dict = {}
    parent_dict = {}
    sanitized_dict = {}
    output = []
    template = {"vulnerability": "", "source": "", "sink": "", "sanitizer": ""}

    result = []
    for pattern in vuln_pattern_json:
        for operations in program_slice_json["body"]:
            walk_dict(
                operations,
                sources=pattern["sources"],
                sanitizers=pattern["sanitizers"],
                sinks=pattern["sinks"],
            )
        for vul in output:
            vul["vulnerability"] = pattern["vulnerability"]
        if len(output) > 0:
            if debug:
                print("################# DEBUG START #################")
                print("output: \n")
                print("tainted_dict {} \n".format(pretty_json(tainted_dict)))
                print("parent dict {} \n".format(pretty_json(parent_dict)))
                print(pretty_json(template))
                print("################# DEBUG END   #################")
            result += output
            output = []
    if debug:
        print("################# DEBUG START #################")
        print("template: \n")
        print("tainted_dict {} \n".format(pretty_json(tainted_dict)))
        print("parent dict {} \n".format(pretty_json(parent_dict)))
        print(pretty_json(template))
        print("################# DEBUG END   #################")
    return result
