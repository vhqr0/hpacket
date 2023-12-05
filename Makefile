.PHONY: compile
compile:
	hy2py -o build/hy2py hpacket

.PHONY: build
build:
	poetry build

.PHONY: test
test:
	python -m unittest tests -v

.PHONY: clean
clean:
	rm -rf build dist
	hy -c "(do (import pathlib [Path] shutil [rmtree]) \
(for [p (.rglob (Path \"hpacket\") \"__pycache__\")] (rmtree p)) \
(for [p (.rglob (Path \"tests\") \"__pycache__\")] (rmtree p)))"
