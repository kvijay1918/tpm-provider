GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=iso-strict --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v1.0.0)

# Used for debugging and uses '-gcflags=all="-N -l"' for debug binaries...
tpmprovider:
	mkdir -p out
	export CGO_CFLAGS_ALLOW="-f.*"; \
	go test -c -o out/tpmprovider.test -tags=unit_test -gcflags=all="-N -l"

unit_test: tpmprovider
	export CGO_CFLAGS_ALLOW="-f.*"; \
	go test ./... -coverpkg=./... -v -tags=unit_test -coverprofile out/cover.out
	go tool cover -func out/cover.out
	go tool cover -html=out/cover.out -o out/cover.html

all: tpmprovider

clean:
	rm -f cover.*
	rm -rf out/