#!/usr/bin/env make
# Convenience wrapper around the stdlib test-suite and the packager.
.PHONY: test smoke deb clean

test:
	cd tests && python3 -m unittest discover -p "test_*.py" -v

smoke:
	./packaging/smoke.sh

deb:
	./packaging/build-deb.sh

clean:
	rm -rf dist src/*/__pycache__ src/*/*/__pycache__ tests/__pycache__
