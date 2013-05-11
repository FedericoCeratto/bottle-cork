# vim: set noexpandtab:

PROJ = cork
VERSION=$(python setup.py --version)

# Default unit testing globbing
TESTGLOB = test*.py

all: help

help:
	egrep "^# target:" [Mm]akefile | cut -c11-

# target: cleanbuild - Remove build dir
cleanbuild:
	python setup.py clean

# target: build - build Python package
build: cleanbuild
	python setup.py sdist
	python setup.py bdist

prepare-cover-dir:
	# If there isn't a cover symlink, create and link the directory
	test -s cover || (mkdir -p docs/_build/html/cover && ln -s docs/_build/html/cover)
	rm -rf cover/*

# target: coverage - Run unit testing + code coverage
coverage: prepare-cover-dir
	nosetests tests/$(TESTGLOB) --with-coverage --cover-erase --cover-package=$(PROJ) --cover-html

# target: coverage-base - Run base functional testing + code coverage
coverage-base: TESTGLOB=test.py
coverage-base: coverage

# target: coverage-mongodb - Run MongoDB functional testing + code coverage
coverage-mongodb: TESTGLOB=test_functional_mongodb_instance.py
coverage-mongodb: coverage

# target: coverage-mysql - Run MySQL functional testing + code coverage
coverage-mysql: TESTGLOB=test_functional_mysql_instance.py
coverage-mysql: coverage


# target: doc - Build sphinx docs
doc:
	cd docs && make html

# target: docwithcoverage - Build sphinx docs
docwithcoverage: coverage doc

# target: rsync - Build docs with coverage and publish them
rsync: build docwithcoverage
	echo rsync -avz _build/html/ firelet.net:~/websites/$(PROJ)

