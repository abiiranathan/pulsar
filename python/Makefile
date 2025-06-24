# Python Packaging Makefile
PYTHON := python3
PACKAGE_DIR := python/pulsar

.PHONY: wheel develop install clean

wheel:
	python3 setup.py bdist_wheel

develop:
	pip install -e . --config-settings editable_mode=compat

upload:
	twine upload dist/*

install: wheel
	$(PYTHON) -m pip install --force-reinstall dist/*.whl

clean:
	rm -rf build dist ./**/*.egg-info
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -delete

