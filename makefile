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
	find . -name '*.pyc' -delete

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
	pgrep -c mysqld || sudo /etc/init.d/mysql start
	pgrep -c mongod || sudo /etc/init.d/mongodb start
	nosetests tests/$(TESTGLOB) --with-coverage --cover-erase --cover-package=$(PROJ) --cover-html

# target: coverage-base - Run base functional testing + code coverage
coverage-base: TESTGLOB=test.py
coverage-base: coverage

# target: coverage-sqlite - Run SQLite functional testing + code coverage
coverage-sqlite: TESTGLOB=test_sqlite.py
coverage-sqlite: coverage

# target: coverage-mongodb - Run MongoDB functional testing + code coverage
coverage-mongodb: TESTGLOB=test_functional_mongodb_instance.py
coverage-mongodb: coverage

# target: coverage-mysql - Run MySQL functional testing + code coverage
coverage-mysql: TESTGLOB=test_functional_mysql_instance.py
coverage-mysql: coverage

# target: pylint - run pylint
pylint:
	pylint cork tests

# target: doc - Build sphinx docs
doc:
	#cd docs && sphinx-build -b html .  _build/html
	sphinx-build -b html docs  docs/_build/html

# target: docwithcoverage - Build sphinx docs
docwithcoverage: coverage doc

# target: rsync - Build docs with coverage and publish them
rsync: build docwithcoverage
	cd docs && rsync -avz _build/html/ firelet.net:~/websites/$(PROJ)

# target: targeted-coverage - Run per-backend coverage tests
targeted-coverage:
	nosetests tests/test_functional_mongodb_instance.py --with-coverage --cover-erase --cover-package=cork.mongodb_backend
	nosetests tests/test_functional_mysql_instance.py --with-coverage --cover-erase --cover-package=cork.sqlalchemy_backend
	nosetests tests/test_functional_sqlalchemy_sqlite_in_memory.py --with-coverage --cover-erase --cover-package=cork.sqlalchemy_backend
	nosetests tests/test_functional_json.py --with-coverage --cover-erase --cover-package=cork.json_backend
	nosetests tests/test_sqlite.py --with-coverage --cover-erase --cover-package=cork.sqlite_backend


