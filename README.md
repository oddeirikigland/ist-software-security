# IST SOFTWARE SECURITY

To run program

```bash
python ./bo-analyser.py program.json patterns.json
```

`program.json`  is the name of the JSON file containing the program slice to analyse, represented in the form of an Abstract Syntax Tree. `patterns.json` is the name of the JSON file containing the list of vulnerability patterns to consider.

Example

```bash
python ./bo-analyser.py data/cursor_slice.json data/vuln_pattern.json
```

If you want to use the debug mode just add 1

For more information about ast_types:
https://greentreesnakes.readthedocs.io/en/latest/nodes.html
