variable_condition_store = {}
tainted_store = {}
vuln_funcs = list()
sinks = list()


class Node:
    def __init__(self, value):
        self.value = value
        # in case we have an assignment, we should check the right side (value dict) if it has uninitialised vars
        # then we save the left side ( targets)
        self.interesting_stuff = []
        self.children = []
        self.parent = []

    def add_child(self, child_node):
        self.children.append(child_node)

    # TODO: check if necessary, might be useful
    def add_parent(self, parent):
        self.parent.append(parent)

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
            # Check if function is part of the vuln sources
            if d["value"]["func"]["id"] in sources:
                # TODO: Recursively check the variables that are used in the function?
                print(d["value"]["func"]["id"])
                # TODO safe used variables for the function ?
                # if it isnt safed already
                if d["value"]["func"]["id"] not in vuln_funcs:
                    vuln_funcs.append(d["value"]["func"]["id"])
            # Todo: find the id of the variable, to save it for the output
        except KeyError:
            # Todo: which functions do not have an id?
            # Todo: dont think we need to consider them
            print("something else")
        try:
            if d["value"]["func"]["attr"] in sources:
                if d["value"]["func"]["attr"] not in vuln_funcs:
                    vuln_funcs.append(d["value"]["func"]["attr"])
        except KeyError:
            print("nofunc attr found")
        build_taint_trace(d)
        check_taint_use(d, node)
    # if d["value"]["ast_type"] == "Name":
    #    for
    # Add all variables to the tainted list that are affected by the ones that are already in the tainted_list
    # => taint all Assign -> Name which have tainted vars in Assign -> Call
    # for key, value in { key:value for key, value in variable_condition_store.items() if value == True }:
    #    for
    print(tainted_store, variable_condition_store)


# Check if assignment uses an uninitialised variable (not included in variable_condition_store)
# => check sibling nodes
def build_taint_trace(d):
    for arg in (d["value"]["args"]):
        try:
            id = ""
            if "id" in arg:
                id = "id"
            elif "s" in arg:
                id = "s"
            if not arg[id] in variable_condition_store and id != "":
                variable_condition_store[arg["id"]] = False
                # Keep track of the variable and safe the assigned variables
                for target in d["targets"]:
                    target_id = target[id]
                    # In case there has already been an assignment it will be added to the trace (list)
                    if arg["id"] not in tainted_store:
                        tainted_store[arg["id"]] = target_id
                    else:
                        tainted_store[arg["id"]].append(target_id)
        except KeyError:
            print("id of assignment not found in dict")


def check_taint_use(d, node):
    # For every tainted var
    for tainted in tainted_store:
        # Check if is used in a child node
        if walk_interesting_tree(node, tainted_store[tainted]):
            # Get the function calll that uses it
           try:
                sinks.append(d["func"]["attr"])
           except KeyError:
               print("bllaaaa")

# d: input slice as dict
# parent node: root node of ast
# sources: sources of the vuln input
def walk_dict(d, parent_node, sources):
    node = Node(d["ast_type"])
    find_interesting_values(d, node)
    # Check if an assignment has a tainted variable
    if d["ast_type"] == "Assign":
        check_if_tainted(d, node, sources)
    node.add_parent(parent_node)
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


#def match_vuln(vuln_pattern, sinks):
#    for vuln in vuln_pattern:
#        if sinks in vuln["sink"]:
#            return vuln["vulnerability"]


def program_analysis(program_slice_json, vuln_pattern_json):
    template = {"vulnerability": "", "source": "", "sink": "", "sanitizer": ""}
    output = []
    pattern = vuln_pattern_json[0]

    top_node = Node(program_slice_json["ast_type"])
    for operations in program_slice_json["body"]:
        walk_dict(operations, parent_node=top_node, sources=pattern["sources"])

    print("bla", top_node)
    sink = walk_interesting_tree(top_node, to_find=pattern["sinks"])
    new_template = template
    new_template["sink"] = sink
    tainted_trails = list(tainted_store.keys())
    if len(tainted_trails) > 0:
        new_template["source"] = tainted_trails[0]
    # vuln = match_vuln(pattern, sinks)
   # new_template["vulnerability"] = vuln
    output.append(new_template)
    print("vuln funcs {}".format(vuln_funcs))
    print(sink)
    print("sinkss {}".format(sinks))
    print("tainted store {}".format(tainted_store))
    print(output)
    return output[0]
