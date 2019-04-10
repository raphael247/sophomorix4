#!/bin/sh

echo "Converting utf-8 to 8859_1"
iconv --verbose -f utf-8 -t 8859_1 students.csv-workflow-schoolisolation-1.utf8 -o students.csv-workflow-schoolisolation-1.8859_1
iconv --verbose -f utf-8 -t 8859_1 bsz.students.csv-workflow-schoolisolation-1.utf8 -o bsz.students.csv-workflow-schoolisolation-1.8859_1

echo "Done"
