#!/bin/bash
rm cover/ -rf
set -e
set -u
echo "Running coverage..."
nosetests tests/test*.py --with-coverage --cover-erase --cover-package=cork --cover-html
