class Node:
    def __init__(self, value):
        self.value = value
        self.interesting_stuff =[]
        self.children = []

    def add_child(self, child_node):
        self.children.append(child_node)

    def add_interest(self, interest):
        self.interesting_stuff.append(interest)

    def __str__(self, level=0):
        ret = "\t" * level + repr(self.value) + ": " + repr(self.interesting_stuff) + "\n"
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


def walk_dict(d, parent_node):
    node = Node(d["ast_type"])
    find_interesting_values(d, node)
    parent_node.add_child(node)
    for key, value in d.items():
        if isinstance(value, dict):
            walk_dict(value, node)
        if isinstance(value, list):
            for elem in value:
                walk_dict(elem, node)


def walk_interesting_tree(node, to_find):
    for value in to_find:
        if value in node.interesting_stuff:
            return value

    if len(node.children) > 0:
        for child in node.children:
            value = walk_interesting_tree(child, to_find)
    return value


def program_analysis(program_slice_json, vuln_pattern_json):
    template = {
        "vulnerability": "",
        "source": "",
        "sink": "",
        "sanitizer": "",
    }
    output = []
    pattern = vuln_pattern_json[0]

    top_node = Node(program_slice_json["ast_type"])
    for operations in program_slice_json["body"]:
        walk_dict(operations, parent_node=top_node)

    print(top_node)
    sink = walk_interesting_tree(top_node, to_find=pattern["sinks"])
    new_template = template
    new_template["sink"] = sink

    output.append(new_template)
    print(sink)
    return output[0]
