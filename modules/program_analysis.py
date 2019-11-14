variable_condition_store = {}


class Node:
    def __init__(self, value):
        self.value = value
        self.interesting_stuff = []
        self.children = []

    def add_child(self, child_node):
        self.children.append(child_node)

    def add_interest(self, interest):
        self.interesting_stuff.append(interest)

    def __str__(self, level=0):
        ret = (
            "\t" * level + repr(self.value) + ": " + repr(self.interesting_stuff) + "\n"
        )
        for child in self.children:
            ret += child.__str__(level + 1)
        return ret

    def __repr__(self):
        return "<tree node representation>"


def find_interesting_values(d, node):
    ast_type = d["ast_type"]
    if ast_type == "Attribute":
        node.add_interest(d["attr"])
    elif ast_type == "Str":
        node.add_interest(d["s"])
    elif ast_type == "Name":
        node.add_interest(d["id"])


def check_if_tainted(d, node, sources):
    for variable in d["targets"]:
        variable_condition_store[variable["id"]] = True

    if d["value"]["ast_type"] == "Call":
        try:
            if d["value"]["func"]["id"] in sources:
                print(d["value"]["func"]["id"])
                # Todo: find the id of the variable, to save it for the output
        except KeyError:
            # Todo: which functions do not have an id?
            # Todo: dont think we need to consider them
            print("something else")
    print(variable_condition_store)


def walk_dict(d, parent_node, sources):
    node = Node(d["ast_type"])
    find_interesting_values(d, node)
    if d["ast_type"] == "Assign":
        check_if_tainted(d, node, sources)
    parent_node.add_child(node)
    for key, value in d.items():
        if isinstance(value, dict):
            walk_dict(value, node, sources)
        if isinstance(value, list):
            for elem in value:
                walk_dict(elem, node, sources)


def walk_interesting_tree(node, to_find):
    for value in to_find:
        if value in node.interesting_stuff:
            return value

    if len(node.children) > 0:
        for child in node.children:
            value = walk_interesting_tree(child, to_find)
    return value


def program_analysis(program_slice_json, vuln_pattern_json):
    template = {"vulnerability": "", "source": "", "sink": "", "sanitizer": ""}
    output = []
    pattern = vuln_pattern_json[0]

    top_node = Node(program_slice_json["ast_type"])
    for operations in program_slice_json["body"]:
        walk_dict(operations, parent_node=top_node, sources=pattern["sources"])

    print(top_node)
    sink = walk_interesting_tree(top_node, to_find=pattern["sinks"])
    new_template = template
    new_template["sink"] = sink

    output.append(new_template)
    print(sink)
    return output[0]
