.PHONY: compile
compile:
	hy2py -o hpacket hpacket

.PHONY: build
build: compile
	hy setup.hy -v bdist_wheel

.PHONY: clean
clean:
	rm -rf build dist hpacket.egg-info
	hy -c "(do (import pathlib [Path]) (for [p (.rglob (Path \"hpacket\") \"*.py\")] (.unlink p)))"
