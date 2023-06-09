PYTHON_BINARY := python3
VIRTUAL_ENV := venv
VIRTUAL_BIN := $(VIRTUAL_ENV)/bin
PROJECT_NAME := ssh_certificate_parser
TEST_DIR := tests

## help - Display help about make targets for this Makefile
help:
	@cat Makefile | grep '^## ' --color=never | cut -c4- | sed -e "`printf 's/ - /\t- /;'`" | column -s "`printf '\t'`" -t

## build - Builds the project in preparation for release
build:
	$(VIRTUAL_BIN)/python -m build

## clean - Remove the virtual environment and clear out .pyc files
clean:
	rm -rf $(VIRTUAL_ENV) dist/ build/ *.egg-info/ .pytest_cache .mypy_cache
	find . -name '*.pyc' -delete

## coverage - Test the project and generate an HTML coverage report
coverage:
	$(VIRTUAL_BIN)/pytest --cov=$(PROJECT_NAME) --cov-branch --cov-report=html --cov-report=term-missing --cov-fail-under=80

## install - Install the project locally
install:
	$(PYTHON_BINARY) -m venv $(VIRTUAL_ENV)
	$(VIRTUAL_BIN)/pip install -e .
	$(VIRTUAL_BIN)/pip install -r test_requirements.txt

## lint - Lint the project
lint:
	$(VIRTUAL_BIN)/flake8 $(PROJECT_NAME)/ $(TEST_DIR)/

## publish - Publish the project to PyPI
publish:
	$(VIRTUAL_BIN)/twine upload dist/*

## release - Cuts a release for the project on GitHub (requires GitHub CLI)
# tag = The associated tag title of the release
release:
	gh release create ${tag} dist/*

## test - Test the project
test:
	$(VIRTUAL_BIN)/pytest

.PHONY: help build clean coverage install lint publish release test
