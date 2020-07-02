GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=iso-strict --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v1.0.0)

# Use '-gcflags=all="-N -l"' to build debug binaries...
tpmprovider:
	export CGO_CFLAGS_ALLOW="-f.*"; \
	go test -c -o out/tpmprovider.test -gcflags=all="-N -l" -ldflags=-compressdwarf=false

all: tpmprovider

clean:
	rm -f cover.*
	rm -rf out/
	rm -rf builds/