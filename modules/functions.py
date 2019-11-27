import sys
import json


def read_from_json(filename):
    try:
        with open(filename) as json_file:
            data = json.load(json_file)
        return data
    except FileNotFoundError:
        print("{} does not exist".format(filename))
        sys.exit(1)
    except json.decoder.JSONDecodeError:
        print("{} is not a json file".format(filename))
        sys.exit(1)


def write_to_json(data, filename):
    with open(filename, "w") as outfile:
        json.dump(data, outfile)
