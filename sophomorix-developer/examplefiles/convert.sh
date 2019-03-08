#!/bin/bash

echo "Converting utf-8 to 8859_1"
iconv --verbose -f utf-8 -t 8859_1 students.csv.utf-8 -o students.csv.8859_1

echo "Done"
