rm cover/ -rf
nosetests tests/test.py tests/test_functional.py --with-coverage --cover-erase --cover-package=cork --cover-html
