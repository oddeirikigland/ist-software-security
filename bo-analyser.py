import sys
import json

from modules.program_analysis import program_analysis


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


def main(program_slice, vulnerability_pattern, debug=False):
    program_slice_json = read_from_json(program_slice)
    vuln_pattern_json = read_from_json(vulnerability_pattern)

    output_filename = program_slice[:-5] + ".output.json"
    output = program_analysis(program_slice_json, vuln_pattern_json, debug=debug)

    write_to_json(output, output_filename)


if __name__ == "__main__":
    if len(sys.argv) == 3:
        main(sys.argv[1], sys.argv[2])
    elif len(sys.argv) == 4:
        if sys.argv[3] == "1":
            debug = True
            main(sys.argv[1], sys.argv[2], debug)
        else:
            print("Wrong debug argument")
    else:
        print("Input failed, expected: filename of two json files and an optional debug flag as arguments")
    sys.exit(1)
