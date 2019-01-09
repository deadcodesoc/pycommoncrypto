PYTHON=/usr/bin/python
ARCHFLAGS="-arch i386 -arch x86_64"

build:
	env ARCHFLAGS=$(ARCHFLAGS) \
	$(PYTHON) setup.py build

install:
	$(PYTHON) setup.py install

clean:
	$(PYTHON) setup.py clean
	rm -rf build *~ *.pyc

test:
	$(PYTHON) test.py

.PHONY: build install clean test
