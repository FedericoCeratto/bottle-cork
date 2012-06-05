rm cover/ -rf
nosetests test/test.py test/test_functional.py --with-coverage --cover-erase --cover-package=cork --cover-html
