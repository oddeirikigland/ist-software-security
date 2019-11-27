#!/bin/bash
for value in {1..12}
do
    echo Starting slice $value
    python3 bo_analyser.py data/slice$value.json data/custom_vuln_pattern.json 1
done
echo Finished
