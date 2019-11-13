class Node:
    def __init__(self, value):
        self.value = value
        self.children = []

    def add_child(self, child_node):
        self.children.append(child_node)

    def __str__(self, level=0):
        ret = "\t" * level + repr(self.value) + "\n"
        for child in self.children:
            ret += child.__str__(level + 1)
        return ret

    def __repr__(self):
        return "<tree node representation>"


def walk_dict(d, parent_node):
    node = Node(d["ast_type"])
    parent_node.add_child(node)
    for key, value in d.items():
        if isinstance(value, dict):
            walk_dict(value, node)
        if isinstance(value, list):
            for elem in value:
                walk_dict(elem, node)


def program_analysis(program_slice_json, vuln_pattern_json):
    output = {
        "vulnerability": "SQL injection",
        "source": "request",
        "sink": "execute",
        "sanitizer": "",
    }

    top_node = Node(program_slice_json["ast_type"])
    for operations in program_slice_json["body"]:
        walk_dict(operations, parent_node=top_node)

    print(top_node)
    return output
