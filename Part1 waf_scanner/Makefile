SRC_DIR = wafw00f
DOC_DIR = docs
MAKE = make

all:
	make install
	make test
	make html
	make clean

install:
	pip install -q -e .[dev,docs]

lint:
	prospector $(SRC_DIR) --strictness veryhigh

testall:
	tox

html:
	cd $(DOC_DIR) && $(MAKE) html

clean:
	@echo Cleaning up...
	@powershell -Command "Get-ChildItem -Path . -Include *.egg-info -Directory -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force"
	@powershell -Command "if (Test-Path build) { Remove-Item build -Recurse -Force }"
	@powershell -Command "if (Test-Path dist) { Remove-Item dist -Recurse -Force }"
	@powershell -Command "if (Test-Path .coverage) { Remove-Item .coverage -Force }"
	@powershell -Command "Get-ChildItem -Path . -Include *.pyc -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force"
	@powershell -Command "Get-ChildItem -Path . -Include __pycache__ -Directory -Recurse -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force"
	@echo Clean completed.
